from __future__ import annotations

from datetime import timedelta

import pytest

from cv_trust_agent.evidence_validation import compute_evidence_value_hash
from cv_trust_agent.models import (
    ClaimKind,
    EvidenceDispositionEntry,
    PlanStep,
    ReasonCode,
    RunDecision,
    SourceKind,
    StepReceipt,
    StepStatus,
    TrustDecision,
    TrustOutcome,
    TrustScope,
    TrustStage,
    TrustState,
    ValidatedBatchEvidence,
    ValidatedCandidateEvidence,
)
from cv_trust_agent.release import ReleaseAuthorizer
from tests.test_engine_unit import (
    SNAPSHOT_ID,
    _Case,
    _case,
    _json_evidence_id,
    _record,
    _replace_record,
    _request_and_output,
    _resume_hash,
    _run,
)


def _ordinary_quarantine_fixture() -> tuple[RunDecision, ValidatedBatchEvidence]:
    resume_record = _record("AP-005", qualification="ACCA")
    request, output = _request_and_output(
        resume_record,
        snapshot_id=SNAPSHOT_ID,
        document_hash=_resume_hash(resume_record.candidate_id),
    )
    detail_record = _replace_record(resume_record, qualification=None)
    indexed = _case((detail_record,))
    null_hash = compute_evidence_value_hash(None)
    catalog = tuple(
        reference.model_copy(
            update={
                "evidence_id": _json_evidence_id(
                    SNAPSHOT_ID,
                    "AP-005",
                    "qualification",
                    None,
                ),
                "semantic_hash": null_hash,
            }
        )
        if reference.source_kind is SourceKind.APPLICATION_JSON
        and reference.field_path == "records[AP-005].qualification"
        else reference
        for reference in request.evidence_catalog
    )
    request = request.model_copy(update={"record": detail_record, "evidence_catalog": catalog})
    decision = _run(
        _Case(
            index=indexed.index,
            records=(detail_record,),
            requests=(request,),
            outputs={(SNAPSHOT_ID, detail_record.candidate_id): output},
        )
    )
    terminal = _record_gate(decision.trust_ledger, TrustStage.CANDIDATE_VALIDATION)
    batch = ValidatedBatchEvidence(
        batch_id=decision.batch_id,
        snapshot_id=decision.snapshot_id,
        candidates=(
            ValidatedCandidateEvidence(
                candidate_id=detail_record.candidate_id,
                snapshot_id=decision.snapshot_id,
                trust_state=TrustState.QUARANTINED,
                reason_codes=terminal.reason_codes,
            ),
        ),
        batch_integrity_valid=True,
        mapper_disagreement=True,
    )
    return decision, batch


def _qualification_value_conflict_fixture() -> tuple[RunDecision, ValidatedBatchEvidence]:
    record = _record("AP-005", qualification="AAT Level 3")
    request, output = _request_and_output(
        record,
        snapshot_id=SNAPSHOT_ID,
        document_hash=_resume_hash(record.candidate_id),
        claim_values={ClaimKind.QUALIFICATION: "ACCA"},
    )
    indexed = _case((record,))
    decision = _run(
        _Case(
            index=indexed.index,
            records=(record,),
            requests=(request,),
            outputs={(SNAPSHOT_ID, record.candidate_id): output},
        )
    )
    terminal = _record_gate(decision.trust_ledger, TrustStage.CANDIDATE_VALIDATION)
    batch = ValidatedBatchEvidence(
        batch_id=decision.batch_id,
        snapshot_id=decision.snapshot_id,
        candidates=(
            ValidatedCandidateEvidence(
                candidate_id=record.candidate_id,
                snapshot_id=decision.snapshot_id,
                trust_state=TrustState.QUARANTINED,
                reason_codes=terminal.reason_codes,
            ),
        ),
        batch_integrity_valid=True,
        mapper_disagreement=True,
    )
    return decision, batch


def _record_gate(
    ledger: tuple[TrustDecision, ...],
    stage: TrustStage,
) -> TrustDecision:
    return next(
        item
        for item in ledger
        if item.scope is TrustScope.RECORD and item.candidate_id == "AP-005" and item.stage is stage
    )


def _authorize(
    decision: RunDecision,
    batch: ValidatedBatchEvidence,
    *,
    ledger: tuple[TrustDecision, ...] | None = None,
    receipts: tuple[StepReceipt, ...] | None = None,
) -> bool:
    return (
        ReleaseAuthorizer()
        .authorize(
            batch,
            decision.routes,
            decision.plan,
            decision.step_receipts if receipts is None else receipts,
            trust_ledger=decision.trust_ledger if ledger is None else ledger,
            plan_history=decision.plans,
        )
        .authorized
    )


def _replace_record_gates(
    ledger: tuple[TrustDecision, ...],
    replacements: dict[TrustStage, TrustDecision],
) -> tuple[TrustDecision, ...]:
    return tuple(
        replacements.get(item.stage, item)
        if item.scope is TrustScope.RECORD and item.candidate_id == "AP-005"
        else item
        for item in ledger
    )


def test_authorizer_accepts_receipt_anchored_ordinary_quarantine() -> None:
    decision, batch = _ordinary_quarantine_fixture()
    mapping = _record_gate(decision.trust_ledger, TrustStage.MAPPING)
    provenance = _record_gate(decision.trust_ledger, TrustStage.PROVENANCE)
    mapping_receipt = next(
        item
        for item in decision.step_receipts
        if item.command_kind is PlanStep.MAP_CANDIDATE_CLAIMS
        and item.status is StepStatus.COMPLETED
    )

    assert mapping.evidence_inventory is not None
    assert mapping.evidence_inventory == provenance.evidence_inventory
    assert mapping.evidence_ids == provenance.evidence_ids
    expected_receipt_ids = {
        *mapping.evidence_ids,
        *(anchor.reference.evidence_id for anchor in mapping.evidence_inventory.structured_anchors),
    }
    cross_source = _record_gate(decision.trust_ledger, TrustStage.CROSS_SOURCE)
    expected_cross_ids = {
        item.reference.evidence_id
        for item in mapping.evidence_inventory.entries
        if item.claim_kind is not ClaimKind.EMPLOYMENT_INTERVAL
    }
    mapped_kinds = {
        item.claim_kind
        for item in mapping.evidence_inventory.entries
        if item.claim_kind is not ClaimKind.EMPLOYMENT_INTERVAL
    }
    expected_cross_ids.update(
        anchor.reference.evidence_id
        for anchor in mapping.evidence_inventory.structured_anchors
        if anchor.claim_kind in mapped_kinds
    )
    assert set(mapping_receipt.evidence_ids) == expected_receipt_ids
    assert set(cross_source.evidence_ids) == expected_cross_ids
    assert _authorize(decision, batch)


def test_authorizer_rejects_coherent_mapping_and_provenance_shrink() -> None:
    decision, batch = _ordinary_quarantine_fixture()
    mapping = _record_gate(decision.trust_ledger, TrustStage.MAPPING)
    provenance = _record_gate(decision.trust_ledger, TrustStage.PROVENANCE)
    assert mapping.evidence_inventory is not None
    target = next(
        item
        for item in mapping.evidence_inventory.entries
        if item.claim_kind is ClaimKind.QUALIFICATION
    )
    retained_entries = tuple(
        item
        for item in mapping.evidence_inventory.entries
        if item.reference.evidence_id != target.reference.evidence_id
    )
    shrunk_inventory = mapping.evidence_inventory.model_copy(update={"entries": retained_entries})
    retained_ids = tuple(
        item for item in mapping.evidence_ids if item != target.reference.evidence_id
    )
    changed_mapping = mapping.model_copy(
        update={"evidence_ids": retained_ids, "evidence_inventory": shrunk_inventory}
    )
    changed_provenance = provenance.model_copy(
        update={"evidence_ids": retained_ids, "evidence_inventory": shrunk_inventory}
    )
    ledger = _replace_record_gates(
        decision.trust_ledger,
        {
            TrustStage.MAPPING: changed_mapping,
            TrustStage.PROVENANCE: changed_provenance,
        },
    )

    mapping_receipt = next(
        item
        for item in decision.step_receipts
        if item.command_kind is PlanStep.MAP_CANDIDATE_CLAIMS
        and item.status is StepStatus.COMPLETED
    )
    assert mapping_receipt.produced_gate_id is not None
    receipts = tuple(
        item.model_copy(
            update={
                "evidence_ids": tuple(
                    evidence_id
                    for evidence_id in item.evidence_ids
                    if evidence_id != target.reference.evidence_id
                )
            }
        )
        if item is mapping_receipt
        else item
        for item in decision.step_receipts
    )
    ledger = tuple(
        item.model_copy(
            update={
                "evidence_ids": tuple(
                    evidence_id
                    for evidence_id in item.evidence_ids
                    if evidence_id != target.reference.evidence_id
                )
            }
        )
        if item.decision_id == mapping_receipt.produced_gate_id
        else item
        for item in ledger
    )

    assert not _authorize(decision, batch, ledger=ledger, receipts=receipts)


def test_authorizer_rederives_false_conflict_from_typed_values() -> None:
    """A conflict marker cannot survive after both typed values are rewritten equal."""

    decision, batch = _qualification_value_conflict_fixture()
    assert _authorize(decision, batch)
    mapping = _record_gate(decision.trust_ledger, TrustStage.MAPPING)
    provenance = _record_gate(decision.trust_ledger, TrustStage.PROVENANCE)
    assert mapping.evidence_inventory is not None
    anchor = next(
        item
        for item in mapping.evidence_inventory.structured_anchors
        if item.claim_kind is ClaimKind.QUALIFICATION
    )
    entries = tuple(
        item.model_copy(
            update={
                "mapped_value": anchor.value,
                "reference": item.reference.model_copy(
                    update={"semantic_hash": anchor.reference.semantic_hash}
                ),
            }
        )
        if item.claim_kind is ClaimKind.QUALIFICATION
        else item
        for item in mapping.evidence_inventory.entries
    )
    changed_inventory = mapping.evidence_inventory.model_copy(update={"entries": entries})
    ledger = _replace_record_gates(
        decision.trust_ledger,
        {
            TrustStage.MAPPING: mapping.model_copy(
                update={"evidence_inventory": changed_inventory}
            ),
            TrustStage.PROVENANCE: provenance.model_copy(
                update={"evidence_inventory": changed_inventory}
            ),
        },
    )

    assert not _authorize(decision, batch, ledger=ledger)


@pytest.mark.parametrize(
    "mutation",
    ["missing", "extra", "reordered", "categorical_swap"],
)
def test_authorizer_rejects_coherent_structured_anchor_mutations(mutation: str) -> None:
    decision, batch = _ordinary_quarantine_fixture()
    mapping = _record_gate(decision.trust_ledger, TrustStage.MAPPING)
    provenance = _record_gate(decision.trust_ledger, TrustStage.PROVENANCE)
    assert mapping.evidence_inventory is not None
    anchors = mapping.evidence_inventory.structured_anchors
    removed_id: str | None = None
    if mutation == "missing":
        target = next(item for item in anchors if item.claim_kind is ClaimKind.RECONCILIATION)
        removed_id = target.reference.evidence_id
        changed_anchors = tuple(item for item in anchors if item is not target)
    elif mutation == "extra":
        changed_anchors = (*anchors, anchors[-1])
    elif mutation == "reordered":
        changed_anchors = tuple(reversed(anchors))
    else:
        spreadsheet = next(item for item in anchors if item.claim_kind is ClaimKind.SPREADSHEET)
        accounting = next(
            item for item in anchors if item.claim_kind is ClaimKind.ACCOUNTING_PLATFORM
        )
        changed_anchors = tuple(
            item.model_copy(
                update={
                    "value": accounting.value,
                    "reference": item.reference.model_copy(
                        update={"semantic_hash": accounting.reference.semantic_hash}
                    ),
                }
            )
            if item is spreadsheet
            else item.model_copy(
                update={
                    "value": spreadsheet.value,
                    "reference": item.reference.model_copy(
                        update={"semantic_hash": spreadsheet.reference.semantic_hash}
                    ),
                }
            )
            if item is accounting
            else item
            for item in anchors
        )
    changed_inventory = mapping.evidence_inventory.model_copy(
        update={"structured_anchors": changed_anchors}
    )
    ledger = _replace_record_gates(
        decision.trust_ledger,
        {
            TrustStage.MAPPING: mapping.model_copy(
                update={"evidence_inventory": changed_inventory}
            ),
            TrustStage.PROVENANCE: provenance.model_copy(
                update={"evidence_inventory": changed_inventory}
            ),
        },
    )
    receipts = decision.step_receipts
    if removed_id is not None:
        mapping_receipt = next(
            item
            for item in receipts
            if item.command_kind is PlanStep.MAP_CANDIDATE_CLAIMS
            and item.status is StepStatus.COMPLETED
        )
        assert mapping_receipt.produced_gate_id is not None
        receipts = tuple(
            item.model_copy(
                update={
                    "evidence_ids": tuple(
                        evidence_id
                        for evidence_id in item.evidence_ids
                        if evidence_id != removed_id
                    )
                }
            )
            if item is mapping_receipt
            else item
            for item in receipts
        )
        ledger = tuple(
            item.model_copy(
                update={
                    "evidence_ids": tuple(
                        evidence_id
                        for evidence_id in item.evidence_ids
                        if evidence_id != removed_id
                    )
                }
            )
            if item.decision_id == mapping_receipt.produced_gate_id
            else item
            for item in ledger
        )

    assert not _authorize(decision, batch, ledger=ledger, receipts=receipts)


@pytest.mark.parametrize(
    ("target_suffix", "replacement_suffix"),
    [
        (":accounting_platform", ":candidate_id"),
        (":spreadsheet", ":candidate_id"),
        (":qualification", ":candidate_id"),
    ],
)
def test_authorizer_rejects_same_count_cross_source_catalog_substitution(
    target_suffix: str,
    replacement_suffix: str,
) -> None:
    """A parsed-but-unrelated ID cannot stand in for a typed JSON citation."""

    decision, batch = _ordinary_quarantine_fixture()
    cross_source = _record_gate(decision.trust_ledger, TrustStage.CROSS_SOURCE)
    parse_receipt = next(
        item
        for item in decision.step_receipts
        if item.command_kind is PlanStep.PARSE_CANDIDATE_RESUMES
        and item.status is StepStatus.COMPLETED
    )
    target = next(
        evidence_id
        for evidence_id in cross_source.evidence_ids
        if evidence_id.startswith("json:") and evidence_id.endswith(target_suffix)
    )
    replacement = next(
        evidence_id
        for evidence_id in parse_receipt.evidence_ids
        if evidence_id.endswith(replacement_suffix) and evidence_id not in cross_source.evidence_ids
    )
    changed_cross_source = cross_source.model_copy(
        update={
            "evidence_ids": tuple(
                sorted(
                    replacement if evidence_id == target else evidence_id
                    for evidence_id in cross_source.evidence_ids
                )
            )
        }
    )
    ledger = _replace_record_gates(
        decision.trust_ledger,
        {TrustStage.CROSS_SOURCE: changed_cross_source},
    )

    assert not _authorize(decision, batch, ledger=ledger)


@pytest.mark.parametrize(
    "claim_kind",
    [
        ClaimKind.SPREADSHEET,
        ClaimKind.ACCOUNTING_PLATFORM,
        ClaimKind.QUALIFICATION,
        ClaimKind.RECONCILIATION,
    ],
)
def test_authorizer_rejects_mapped_cross_source_pair_deletion(
    claim_kind: ClaimKind,
) -> None:
    """Both sides cannot disappear while their typed mapping remains."""

    decision, batch = _ordinary_quarantine_fixture()
    cross_source = _record_gate(decision.trust_ledger, TrustStage.CROSS_SOURCE)
    pair_ids = {
        evidence_id
        for evidence_id in cross_source.evidence_ids
        if evidence_id.endswith(f":{claim_kind.value}")
    }
    assert len(pair_ids) == 2
    changed_cross_source = cross_source.model_copy(
        update={
            "evidence_ids": tuple(
                evidence_id
                for evidence_id in cross_source.evidence_ids
                if evidence_id not in pair_ids
            )
        }
    )
    ledger = _replace_record_gates(
        decision.trust_ledger,
        {TrustStage.CROSS_SOURCE: changed_cross_source},
    )

    assert not _authorize(decision, batch, ledger=ledger)


def test_authorizer_rejects_cross_source_pair_omission_swap() -> None:
    """A same-count identity pair cannot replace an omitted mapped pair."""

    decision, batch = _ordinary_quarantine_fixture()
    cross_source = _record_gate(decision.trust_ledger, TrustStage.CROSS_SOURCE)
    parse_receipt = next(
        item
        for item in decision.step_receipts
        if item.command_kind is PlanStep.PARSE_CANDIDATE_RESUMES
        and item.status is StepStatus.COMPLETED
    )
    omitted_pair = {
        evidence_id
        for evidence_id in cross_source.evidence_ids
        if evidence_id.endswith(":spreadsheet")
    }
    replacement_pair = {
        evidence_id
        for evidence_id in parse_receipt.evidence_ids
        if evidence_id.endswith(":candidate_id")
    }
    assert len(omitted_pair) == len(replacement_pair) == 2
    assert replacement_pair.isdisjoint(cross_source.evidence_ids)
    changed_cross_source = cross_source.model_copy(
        update={
            "evidence_ids": tuple(
                sorted(
                    set(cross_source.evidence_ids).difference(omitted_pair).union(replacement_pair)
                )
            )
        }
    )
    ledger = _replace_record_gates(
        decision.trust_ledger,
        {TrustStage.CROSS_SOURCE: changed_cross_source},
    )

    assert not _authorize(decision, batch, ledger=ledger)


def test_authorizer_rejects_cross_source_evidence_reordering() -> None:
    decision, batch = _ordinary_quarantine_fixture()
    cross_source = _record_gate(decision.trust_ledger, TrustStage.CROSS_SOURCE)
    changed_cross_source = cross_source.model_copy(
        update={"evidence_ids": tuple(reversed(cross_source.evidence_ids))}
    )
    ledger = _replace_record_gates(
        decision.trust_ledger,
        {TrustStage.CROSS_SOURCE: changed_cross_source},
    )

    assert not _authorize(decision, batch, ledger=ledger)


def test_authorizer_rejects_coherently_rewritten_scalar_anchor_identifier() -> None:
    """An anchor's typed fields cannot be rebound to another parsed catalog ID."""

    decision, batch = _ordinary_quarantine_fixture()
    mapping = _record_gate(decision.trust_ledger, TrustStage.MAPPING)
    provenance = _record_gate(decision.trust_ledger, TrustStage.PROVENANCE)
    cross_source = _record_gate(decision.trust_ledger, TrustStage.CROSS_SOURCE)
    assert mapping.evidence_inventory is not None
    old_anchor = mapping.evidence_inventory.record_ap_years_reference.evidence_id
    parse_receipt = next(
        item
        for item in decision.step_receipts
        if item.command_kind is PlanStep.PARSE_CANDIDATE_RESUMES
        and item.status is StepStatus.COMPLETED
    )
    replacement = next(
        evidence_id
        for evidence_id in parse_receipt.evidence_ids
        if evidence_id.startswith("json:") and evidence_id.endswith(":qualification")
    )
    changed_reference = mapping.evidence_inventory.record_ap_years_reference.model_copy(
        update={"evidence_id": replacement}
    )
    changed_inventory = mapping.evidence_inventory.model_copy(
        update={"record_ap_years_reference": changed_reference}
    )
    mapping = mapping.model_copy(update={"evidence_inventory": changed_inventory})
    provenance = provenance.model_copy(update={"evidence_inventory": changed_inventory})
    cross_source = cross_source.model_copy(
        update={
            "evidence_ids": tuple(
                sorted(
                    replacement if evidence_id == old_anchor else evidence_id
                    for evidence_id in cross_source.evidence_ids
                )
            )
        }
    )
    ledger = _replace_record_gates(
        decision.trust_ledger,
        {
            TrustStage.MAPPING: mapping,
            TrustStage.PROVENANCE: provenance,
            TrustStage.CROSS_SOURCE: cross_source,
        },
    )
    mapping_receipt = next(
        item
        for item in decision.step_receipts
        if item.command_kind is PlanStep.MAP_CANDIDATE_CLAIMS
        and item.status is StepStatus.COMPLETED
    )
    assert mapping_receipt.produced_gate_id is not None
    receipts = tuple(
        item.model_copy(
            update={
                "evidence_ids": tuple(
                    sorted(
                        replacement if evidence_id == old_anchor else evidence_id
                        for evidence_id in item.evidence_ids
                    )
                )
            }
        )
        if item is mapping_receipt
        else item
        for item in decision.step_receipts
    )
    ledger = tuple(
        item.model_copy(
            update={
                "evidence_ids": tuple(
                    sorted(
                        replacement if evidence_id == old_anchor else evidence_id
                        for evidence_id in item.evidence_ids
                    )
                )
            }
        )
        if item.decision_id == mapping_receipt.produced_gate_id
        else item
        for item in ledger
    )

    assert not _authorize(decision, batch, ledger=ledger, receipts=receipts)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_inventory",
        "scalar",
        "scalar_type",
        "anchor",
        "timeline",
        "date",
        "category",
        "candidate_payload",
        "cross_interval",
        "cross_external_count",
        "cross_anchor",
        "domain_marker",
    ],
)
def test_authorizer_rejects_unranked_inventory_semantic_mutations(mutation: str) -> None:
    decision, batch = _ordinary_quarantine_fixture()
    mapping = _record_gate(decision.trust_ledger, TrustStage.MAPPING)
    provenance = _record_gate(decision.trust_ledger, TrustStage.PROVENANCE)
    timeline = _record_gate(decision.trust_ledger, TrustStage.TIMELINE)
    cross_source = _record_gate(decision.trust_ledger, TrustStage.CROSS_SOURCE)
    terminal = _record_gate(decision.trust_ledger, TrustStage.CANDIDATE_VALIDATION)
    assert mapping.evidence_inventory is not None
    inventory = mapping.evidence_inventory

    if mutation == "missing_inventory":
        mapping = mapping.model_copy(update={"evidence_ids": (), "evidence_inventory": None})
        provenance = provenance.model_copy(update={"evidence_ids": (), "evidence_inventory": None})
    elif mutation == "scalar":
        changed_inventory = inventory.model_copy(
            update={"record_ap_years": inventory.record_ap_years + 1.0}
        )
        mapping = mapping.model_copy(update={"evidence_inventory": changed_inventory})
        provenance = provenance.model_copy(update={"evidence_inventory": changed_inventory})
    elif mutation == "scalar_type":
        changed_inventory = inventory.model_copy(update={"record_ap_years": "4.0"})
        mapping = mapping.model_copy(update={"evidence_inventory": changed_inventory})
        provenance = provenance.model_copy(update={"evidence_inventory": changed_inventory})
    elif mutation == "anchor":
        changed_reference = inventory.record_ap_years_reference.model_copy(
            update={"field_path": "records[AP-005].invoice_processing"}
        )
        changed_inventory = inventory.model_copy(
            update={"record_ap_years_reference": changed_reference}
        )
        mapping = mapping.model_copy(update={"evidence_inventory": changed_inventory})
        provenance = provenance.model_copy(update={"evidence_inventory": changed_inventory})
    elif mutation == "timeline":
        timeline = timeline.model_copy(
            update={
                "state": TrustState.DEGRADED,
                "outcome": TrustOutcome.RESTRICT,
                "reason_codes": (ReasonCode.TIMELINE_DRIFT,),
            }
        )
        terminal_reasons = tuple(
            sorted(
                {
                    *terminal.reason_codes,
                    ReasonCode.TIMELINE_DRIFT,
                }.difference({ReasonCode.TIMELINE_VALID}),
                key=str,
            )
        )
        terminal = terminal.model_copy(update={"reason_codes": terminal_reasons})
        batch = batch.model_copy(
            update={
                "candidates": (
                    batch.candidates[0].model_copy(update={"reason_codes": terminal_reasons}),
                )
            }
        )
    elif mutation == "date":

        def alter_date(item: EvidenceDispositionEntry) -> EvidenceDispositionEntry:
            if (
                item.claim_kind is not ClaimKind.EMPLOYMENT_INTERVAL
                or item.reference.field_path != "resume.employment_start"
                or item.date_value is None
            ):
                return item
            changed_date = item.date_value + timedelta(days=2_000)
            return item.model_copy(
                update={
                    "date_value": changed_date,
                    "reference": item.reference.model_copy(
                        update={
                            "semantic_hash": compute_evidence_value_hash(changed_date.isoformat())
                        }
                    ),
                }
            )

        changed_inventory = inventory.model_copy(
            update={"entries": tuple(alter_date(item) for item in inventory.entries)}
        )
        mapping = mapping.model_copy(update={"evidence_inventory": changed_inventory})
        provenance = provenance.model_copy(update={"evidence_inventory": changed_inventory})
    elif mutation == "category":
        cross_source = cross_source.model_copy(
            update={
                "reason_codes": tuple(
                    sorted(
                        {*cross_source.reason_codes, ReasonCode.CATEGORY_NOT_SUPPORTED},
                        key=str,
                    )
                )
            }
        )
    elif mutation == "candidate_payload":
        batch = batch.model_copy(
            update={"candidates": (batch.candidates[0].model_copy(update={"ap_years": 4.0}),)}
        )
    elif mutation == "cross_interval":
        cross_source = cross_source.model_copy(
            update={
                "evidence_ids": tuple(
                    sorted({*cross_source.evidence_ids, timeline.evidence_ids[0]})
                )
            }
        )
    elif mutation == "cross_external_count":
        inventory_ids = {item.reference.evidence_id for item in inventory.entries}
        protected = {
            inventory.record_ap_years_reference.evidence_id,
            inventory.record_invoice_processing_reference.evidence_id,
        }
        external_id = next(
            item
            for item in cross_source.evidence_ids
            if item not in inventory_ids and item not in protected
        )
        cross_source = cross_source.model_copy(
            update={
                "evidence_ids": tuple(
                    item for item in cross_source.evidence_ids if item != external_id
                )
            }
        )
    elif mutation == "cross_anchor":
        parse_receipt = next(
            item
            for item in decision.step_receipts
            if item.command_kind is PlanStep.PARSE_CANDIDATE_RESUMES
            and item.status is StepStatus.COMPLETED
        )
        replacement = next(
            item
            for item in parse_receipt.evidence_ids
            if item.startswith("json:")
            and item.endswith(":candidate_id")
            and item not in cross_source.evidence_ids
        )
        cross_source = cross_source.model_copy(
            update={
                "evidence_ids": tuple(
                    sorted(
                        replacement
                        if item == inventory.record_ap_years_reference.evidence_id
                        else item
                        for item in cross_source.evidence_ids
                    )
                )
            }
        )
    else:
        cross_source = cross_source.model_copy(
            update={
                "reason_codes": tuple(
                    sorted(
                        {*cross_source.reason_codes, ReasonCode.DOMAIN_INVARIANT_CONFLICT},
                        key=str,
                    )
                )
            }
        )
        terminal_reasons = tuple(
            sorted({*terminal.reason_codes, ReasonCode.DOMAIN_INVARIANT_CONFLICT}, key=str)
        )
        terminal = terminal.model_copy(update={"reason_codes": terminal_reasons})
        batch = batch.model_copy(
            update={
                "candidates": (
                    batch.candidates[0].model_copy(update={"reason_codes": terminal_reasons}),
                )
            }
        )

    ledger = _replace_record_gates(
        decision.trust_ledger,
        {
            TrustStage.MAPPING: mapping,
            TrustStage.PROVENANCE: provenance,
            TrustStage.TIMELINE: timeline,
            TrustStage.CROSS_SOURCE: cross_source,
            TrustStage.CANDIDATE_VALIDATION: terminal,
        },
    )
    receipts = decision.step_receipts
    if mutation == "missing_inventory":
        mapping_receipt = next(
            item
            for item in receipts
            if item.command_kind is PlanStep.MAP_CANDIDATE_CLAIMS
            and item.status is StepStatus.COMPLETED
        )
        assert mapping_receipt.produced_gate_id is not None
        receipts = tuple(
            item.model_copy(update={"evidence_ids": ()}) if item is mapping_receipt else item
            for item in receipts
        )
        ledger = tuple(
            item.model_copy(update={"evidence_ids": ()})
            if item.decision_id == mapping_receipt.produced_gate_id
            else item
            for item in ledger
        )
    assert not _authorize(decision, batch, ledger=ledger, receipts=receipts)
