"""V2.2 semantic closure for mapped candidates which are not ranked."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path
from typing import Any, cast

import pytest

from cv_trust_agent.evidence_validation import compute_evidence_value_hash
from cv_trust_agent.models import ClaimKind
from evaluation.release_spec_v22 import (
    DecisionProjectionV22,
    EvidenceDispositionInventoryV22,
    ReleaseSpecV22Error,
    StructuredFieldAnchorV22,
    _canonical_evidence_id_v22,
    _derive_cross_source_v22,
    _evidence_value_sha256,
    canonical_json_bytes,
)
from tests.test_engine_unit import (
    SNAPSHOT_ID,
    _Case,
    _case,
    _record,
    _replace_record,
    _request_and_output,
    _resume_hash,
    _run,
)

Json = dict[str, Any]


def _timeline_conflict_projection() -> DecisionProjectionV22:
    """Build the ordinary local quarantine used by semantic_no_directive."""

    visible_record = _record("AP-005", ap_years=1.5)
    healthy = _record("AP-001")
    structured_record = _replace_record(visible_record, ap_years=8.0)
    request, output = _request_and_output(
        structured_record,
        snapshot_id=SNAPSHOT_ID,
        document_hash=_resume_hash(structured_record.candidate_id),
        claim_values={ClaimKind.AP_YEARS: 1.5},
    )
    clean_request, clean_output = _request_and_output(
        visible_record,
        snapshot_id=SNAPSHOT_ID,
        document_hash=_resume_hash(visible_record.candidate_id),
    )
    clean_endpoints = {
        item.field_path: item
        for item in clean_request.evidence_catalog
        if item.field_path in {"resume.employment_start", "resume.employment_end"}
    }
    request = request.model_copy(
        update={
            "evidence_catalog": tuple(
                clean_endpoints.get(item.field_path or "", item)
                for item in request.evidence_catalog
            )
        }
    )
    clean_interval = next(
        claim for claim in clean_output.claims if claim.kind is ClaimKind.EMPLOYMENT_INTERVAL
    )
    output = output.model_copy(
        update={
            "claims": tuple(
                clean_interval if claim.kind is ClaimKind.EMPLOYMENT_INTERVAL else claim
                for claim in output.claims
            )
        }
    )
    base = _case((healthy, structured_record))
    case = _Case(
        index=base.index,
        records=(healthy, structured_record),
        requests=(base.requests[0], request),
        outputs={
            (SNAPSHOT_ID, healthy.candidate_id): base.outputs[(SNAPSHOT_ID, healthy.candidate_id)],
            (SNAPSHOT_ID, structured_record.candidate_id): output,
        },
    )
    observation = cast(Json, _run(case).model_dump(mode="json", exclude_none=True))
    return DecisionProjectionV22.from_observation(observation)


def _cross_source_conflict_projection() -> DecisionProjectionV22:
    """Build a graph-free quarantine after a valid timeline was consumed."""

    visible_record = _record("AP-005", reconciliation=True)
    structured_record = _replace_record(visible_record, reconciliation=False)
    healthy = _record("AP-001")
    request, output = _request_and_output(
        structured_record,
        snapshot_id=SNAPSHOT_ID,
        document_hash=_resume_hash(structured_record.candidate_id),
        claim_values={ClaimKind.RECONCILIATION: True},
    )
    base = _case((healthy, structured_record))
    case = _Case(
        index=base.index,
        records=(healthy, structured_record),
        requests=(base.requests[0], request),
        outputs={
            (SNAPSHOT_ID, healthy.candidate_id): base.outputs[(SNAPSHOT_ID, healthy.candidate_id)],
            (SNAPSHOT_ID, structured_record.candidate_id): output,
        },
    )
    observation = cast(Json, _run(case).model_dump(mode="json", exclude_none=True))
    return DecisionProjectionV22.from_observation(observation)


@pytest.fixture(scope="module")
def quarantine_projection() -> DecisionProjectionV22:
    return _timeline_conflict_projection()


@pytest.fixture(scope="module")
def cross_quarantine_projection() -> DecisionProjectionV22:
    return _cross_source_conflict_projection()


def _canonical(projection: DecisionProjectionV22) -> Json:
    return cast(Json, json.loads(canonical_json_bytes(projection.canonical_object())))


def _gate(value: Json, stage: str, candidate_id: str = "AP-005") -> Json:
    return next(
        gate
        for gate in cast(list[Json], value["trust_gates"])
        if gate["scope"] == "record"
        and gate["candidate_id"] == candidate_id
        and gate["stage"] == stage
    )


def _inventory(value: Json, stage: str, candidate_id: str = "AP-005") -> Json:
    return cast(Json, _gate(value, stage, candidate_id)["evidence_inventory"])


def _entry(inventory: Json, claim_kind: str) -> Json:
    return next(
        item for item in cast(list[Json], inventory["entries"]) if item["claim_kind"] == claim_kind
    )


def _anchor(inventory: Json, claim_kind: str) -> Json:
    return next(
        item
        for item in cast(list[Json], inventory["structured_anchors"])
        if item["claim_kind"] == claim_kind
    )


def _readdress_anchor(inventory: Json, claim_kind: str) -> None:
    anchor = _anchor(inventory, claim_kind)
    reference = cast(Json, anchor["reference"])
    reference["evidence_id"] = _canonical_evidence_id_v22(
        "json",
        cast(str, inventory["snapshot_id"]),
        cast(str, inventory["candidate_id"]),
        cast(str, reference["semantic_hash"]),
        claim_kind,
    )


def _remove_cross_source_pair(value: Json, claim_kind: str) -> None:
    """Remove both evaluated sides of one scalar without leaving an orphan."""

    inventory = _inventory(value, "mapping")
    visible_id = cast(Json, _entry(inventory, claim_kind)["reference"])["evidence_id"]
    json_id = cast(Json, _anchor(inventory, claim_kind)["reference"])["evidence_id"]
    cross_source = _gate(value, "cross_source")
    evidence_ids = cast(list[str], cross_source["evidence_ids"])
    assert visible_id in evidence_ids and json_id in evidence_ids
    cross_source["evidence_ids"] = [
        item for item in evidence_ids if item not in {visible_id, json_id}
    ]


def _rejects(projection: DecisionProjectionV22, value: Json) -> None:
    with pytest.raises(ReleaseSpecV22Error):
        DecisionProjectionV22.from_canonical(value)


def _erase_record_mapping_commitment(value: Json, candidate_id: str = "AP-005") -> None:
    """Coherently erase one record from both typed and batch MAP commitments."""

    mapping = _gate(value, "mapping", candidate_id)
    provenance = _gate(value, "provenance", candidate_id)
    inventory = cast(Json, mapping["evidence_inventory"])
    removed_ids = {
        cast(Json, item["reference"])["evidence_id"]
        for item in cast(list[Json], inventory["entries"])
    } | {
        cast(Json, item["reference"])["evidence_id"]
        for item in cast(list[Json], inventory["structured_anchors"])
    }
    mapping["evidence_ids"] = []
    mapping["evidence_inventory"] = None
    provenance["evidence_ids"] = []
    provenance["evidence_inventory"] = None

    receipt = next(
        item
        for item in cast(list[Json], value["receipts"])
        if item["command_kind"] == "map_candidate_claims" and item["status"] == "completed"
    )
    receipt["evidence_ids"] = [
        item for item in cast(list[str], receipt["evidence_ids"]) if item not in removed_ids
    ]
    produced = next(
        gate
        for gate in cast(list[Json], value["trust_gates"])
        if gate["gate_id"] == receipt["produced_gate_id"]
    )
    produced["evidence_ids"] = [
        item for item in cast(list[str], produced["evidence_ids"]) if item not in removed_ids
    ]


def test_ordinary_timeline_quarantine_retains_exact_typed_mapping_lineage(
    quarantine_projection: DecisionProjectionV22,
) -> None:
    route = next(item for item in quarantine_projection.routes if item.candidate_id == "AP-005")
    mapping = next(
        item
        for item in quarantine_projection.trust_gates
        if item.candidate_id == "AP-005" and item.stage == "mapping"
    )
    provenance = next(
        item
        for item in quarantine_projection.trust_gates
        if item.candidate_id == "AP-005" and item.stage == "provenance"
    )
    terminal = next(
        item
        for item in quarantine_projection.trust_gates
        if item.candidate_id == "AP-005" and item.stage == "candidate_validation"
    )

    assert route.rank_key is None and route.support_graph is None
    assert mapping.evidence_inventory is not None
    assert mapping.evidence_inventory == provenance.evidence_inventory
    assert mapping.evidence_inventory.record_ap_years == 8.0
    assert terminal.evidence_inventory is None
    assert (
        DecisionProjectionV22.from_canonical(
            quarantine_projection.canonical_object()
        ).audit_digest()
        == quarantine_projection.audit_digest()
    )


@pytest.mark.parametrize("empty", [False, True])
def test_synchronized_mapping_and_provenance_shrink_is_rejected(
    quarantine_projection: DecisionProjectionV22,
    empty: bool,
) -> None:
    value = _canonical(quarantine_projection)
    for stage in ("mapping", "provenance"):
        gate = _gate(value, stage)
        inventory = cast(Json, gate["evidence_inventory"])
        entries = cast(list[Json], inventory["entries"])
        removed_ids = {
            cast(Json, item["reference"])["evidence_id"]
            for item in entries
            if empty or item["claim_kind"] == "ap_years"
        }
        inventory["entries"] = [
            item
            for item in entries
            if cast(Json, item["reference"])["evidence_id"] not in removed_ids
        ]
        gate["evidence_ids"] = [
            evidence_id
            for evidence_id in cast(list[str], gate["evidence_ids"])
            if evidence_id not in removed_ids
        ]

    _rejects(quarantine_projection, value)


def test_coherent_complete_inventory_erasure_cannot_masquerade_as_an_early_stop(
    quarantine_projection: DecisionProjectionV22,
) -> None:
    """Reproduce the semantic_no_directive AP-005 audit finding exactly."""

    value = _canonical(quarantine_projection)
    _erase_record_mapping_commitment(value)

    # The forged record still claims usable provenance and a derived timeline,
    # while both record inventories and its exact MAP receipt contribution are
    # gone.  Receipt self-consistency must not make that semantic erasure valid.
    assert _gate(value, "provenance")["state"] == "USABLE"
    assert _gate(value, "timeline")["reason_codes"] == ["timeline_conflict"]
    _rejects(quarantine_projection, value)


def test_cross_source_path_cannot_survive_coherent_inventory_erasure(
    cross_quarantine_projection: DecisionProjectionV22,
) -> None:
    value = _canonical(cross_quarantine_projection)
    _erase_record_mapping_commitment(value)

    assert _gate(value, "cross_source")["state"] == "QUARANTINED"
    _rejects(cross_quarantine_projection, value)


def test_terminal_after_usable_provenance_cannot_survive_inventory_erasure(
    quarantine_projection: DecisionProjectionV22,
) -> None:
    value = _canonical(quarantine_projection)
    _erase_record_mapping_commitment(value)
    ledger = cast(list[Json], value["trust_gates"])
    timeline = _gate(value, "timeline")
    provenance = _gate(value, "provenance")
    terminal = _gate(value, "candidate_validation")
    ledger.remove(timeline)
    terminal.update(
        {
            "input_gate_ids": [provenance["gate_id"]],
            "state": "USABLE",
            "outcome": "ALLOW",
            "reason_codes": ["evidence_admissible"],
        }
    )

    _rejects(quarantine_projection, value)


def test_erasing_every_record_decision_cannot_be_relabelled_as_a_batch_early_stop(
    quarantine_projection: DecisionProjectionV22,
) -> None:
    value = _canonical(quarantine_projection)
    ledger = cast(list[Json], value["trust_gates"])
    ledger[:] = [
        gate
        for gate in ledger
        if gate["candidate_id"] != "AP-005"
        or gate["stage"]
        not in {"mapping", "provenance", "timeline", "cross_source", "candidate_validation"}
    ]

    _rejects(quarantine_projection, value)


@pytest.mark.parametrize("missing_side", ["mapping", "provenance"])
def test_one_sided_inventory_erasure_is_rejected_before_downstream_use(
    quarantine_projection: DecisionProjectionV22,
    missing_side: str,
) -> None:
    value = _canonical(quarantine_projection)
    _gate(value, missing_side)["evidence_inventory"] = None

    _rejects(quarantine_projection, value)


@pytest.mark.parametrize("case_name", ["mapper_disagreement_only", "compound"])
def test_frozen_inventory_free_early_provenance_rejections_remain_valid(
    case_name: str,
) -> None:
    artifact_path = (
        Path(__file__).parents[1]
        / "evidence"
        / "v2.2"
        / "v24-20260817-r1"
        / "deterministic-v22.json"
    )
    artifact = cast(Json, json.loads(artifact_path.read_bytes()))
    observation = next(
        item
        for item in cast(list[Json], artifact["observations"])
        if item["case_name"] == case_name
    )
    projection = cast(Json, observation["projection"])
    mapping = _gate(projection, "mapping")
    provenance = _gate(projection, "provenance")
    terminal = _gate(projection, "candidate_validation")

    assert mapping["evidence_inventory"] is None
    assert provenance["evidence_inventory"] is None
    assert provenance["reason_codes"] == ["evidence_value_conflict", "mapper_disagreement"]
    assert terminal["input_gate_ids"] == [provenance["gate_id"]]
    DecisionProjectionV22.from_canonical(projection)


def test_inventory_free_provenance_rejection_requires_its_bounded_citations() -> None:
    artifact_path = (
        Path(__file__).parents[1]
        / "evidence"
        / "v2.2"
        / "v24-20260817-r1"
        / "deterministic-v22.json"
    )
    artifact = cast(Json, json.loads(artifact_path.read_bytes()))
    observation = next(
        item
        for item in cast(list[Json], artifact["observations"])
        if item["case_name"] == "mapper_disagreement_only"
    )
    projection = deepcopy(cast(Json, observation["projection"]))
    _gate(projection, "provenance")["evidence_ids"] = []

    with pytest.raises(ReleaseSpecV22Error):
        DecisionProjectionV22.from_canonical(projection)


@pytest.mark.parametrize(
    ("case_name", "candidate_id", "failure_stage"),
    [
        ("cv_substitution", "AP-005", "identity"),
        ("detail_timeout", "AP-008", "retrieval"),
    ],
)
def test_frozen_pre_mapping_failures_remain_valid(
    case_name: str,
    candidate_id: str,
    failure_stage: str,
) -> None:
    artifact_path = (
        Path(__file__).parents[1]
        / "evidence"
        / "v2.2"
        / "v24-20260817-r1"
        / "deterministic-v22.json"
    )
    artifact = cast(Json, json.loads(artifact_path.read_bytes()))
    observation = next(
        item
        for item in cast(list[Json], artifact["observations"])
        if item["case_name"] == case_name
    )
    projection = cast(Json, observation["projection"])
    failure = _gate(projection, failure_stage, candidate_id)
    terminal = _gate(projection, "candidate_validation", candidate_id)

    assert terminal["input_gate_ids"] == [failure["gate_id"]]
    assert failure["state"] != "USABLE"
    DecisionProjectionV22.from_canonical(projection)


def test_structured_scalar_and_hash_rewrite_cannot_retain_conflict_gate(
    quarantine_projection: DecisionProjectionV22,
) -> None:
    value = _canonical(quarantine_projection)
    for stage in ("mapping", "provenance"):
        inventory = _inventory(value, stage)
        inventory["record_ap_years"] = 1.5
        reference = cast(Json, inventory["record_ap_years_reference"])
        reference["semantic_hash"] = compute_evidence_value_hash(1.5)

    _rejects(quarantine_projection, value)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("source_kind", "resume_visible"),
        ("field_path", "records[AP-005].invoice_processing"),
        ("candidate_id", "AP-999"),
        ("snapshot_id", "other-snapshot"),
    ],
)
def test_structured_anchor_source_ownership_and_field_are_closed(
    quarantine_projection: DecisionProjectionV22,
    field: str,
    replacement: str,
) -> None:
    value = _canonical(quarantine_projection)
    for stage in ("mapping", "provenance"):
        reference = cast(Json, _inventory(value, stage)["record_ap_years_reference"])
        reference[field] = replacement
        if field == "source_kind":
            reference.update(
                {
                    "page": 1,
                    "document_page_count": 1,
                    "page_width": 595.0,
                    "page_height": 842.0,
                    "bbox": [1.0, 1.0, 2.0, 2.0],
                }
            )

    _rejects(quarantine_projection, value)


def test_forged_timeline_valid_gate_is_rejected(
    quarantine_projection: DecisionProjectionV22,
) -> None:
    value = _canonical(quarantine_projection)
    _gate(value, "timeline").update(
        {
            "state": "USABLE",
            "outcome": "ALLOW",
            "reason_codes": ["timeline_valid"],
        }
    )

    _rejects(quarantine_projection, value)


def test_coherent_endpoint_date_and_hash_change_cannot_retain_old_timeline(
    quarantine_projection: DecisionProjectionV22,
) -> None:
    value = _canonical(quarantine_projection)
    for stage in ("mapping", "provenance"):
        inventory = _inventory(value, stage)
        endpoint = next(
            item
            for item in cast(list[Json], inventory["entries"])
            if cast(Json, item["reference"])["field_path"] == "resume.employment_start"
        )
        endpoint["date_value"] = "2018-01-01"
        cast(Json, endpoint["reference"])["semantic_hash"] = compute_evidence_value_hash(
            "2018-01-01"
        )

    _rejects(quarantine_projection, value)


def test_categorical_hash_from_another_bounded_field_is_rejected(
    quarantine_projection: DecisionProjectionV22,
) -> None:
    value = _canonical(quarantine_projection)
    for stage in ("mapping", "provenance"):
        spreadsheet = _entry(_inventory(value, stage), "spreadsheet")
        cast(Json, spreadsheet["reference"])["semantic_hash"] = compute_evidence_value_hash("Xero")

    _rejects(quarantine_projection, value)


def test_mapping_receipt_must_equal_typed_inventory_union(
    quarantine_projection: DecisionProjectionV22,
) -> None:
    value = _canonical(quarantine_projection)
    receipt = next(
        item
        for item in cast(list[Json], value["receipts"])
        if item["command_kind"] == "map_candidate_claims" and item["status"] == "completed"
    )
    receipt["evidence_ids"] = cast(list[str], receipt["evidence_ids"])[1:]

    _rejects(quarantine_projection, value)


def test_ordinary_cross_source_quarantine_is_independently_evaluable(
    cross_quarantine_projection: DecisionProjectionV22,
) -> None:
    route = next(
        item for item in cross_quarantine_projection.routes if item.candidate_id == "AP-005"
    )
    cross_source = next(
        item
        for item in cross_quarantine_projection.trust_gates
        if item.candidate_id == "AP-005" and item.stage == "cross_source"
    )
    terminal = next(
        item
        for item in cross_quarantine_projection.trust_gates
        if item.candidate_id == "AP-005" and item.stage == "candidate_validation"
    )

    assert route.rank_key is None and route.support_graph is None
    assert cross_source.state == "QUARANTINED"
    assert set(cross_source.reason_codes) == {"cross_source_conflict", "mapper_disagreement"}
    assert terminal.evidence_inventory is None
    inventory = next(
        item
        for item in cross_quarantine_projection.trust_gates
        if item.candidate_id == "AP-005" and item.stage == "mapping"
    ).evidence_inventory
    assert inventory is not None
    expected_cross_ids = {
        evidence_id
        for item in inventory.entries
        if item.claim_kind != "employment_interval"
        for evidence_id in (
            item.reference.evidence_id,
            next(
                anchor.reference.evidence_id
                for anchor in inventory.structured_anchors
                if anchor.claim_kind == item.claim_kind
            ),
        )
    }
    assert set(cross_source.evidence_ids) == expected_cross_ids


def test_exact_false_conflict_repro_is_rejected_after_visible_value_now_matches(
    cross_quarantine_projection: DecisionProjectionV22,
) -> None:
    """A stale producer conflict label cannot override independently matching values."""

    value = _canonical(cross_quarantine_projection)
    for stage in ("mapping", "provenance"):
        reconciliation = _entry(_inventory(value, stage), "reconciliation")
        reconciliation["mapped_value"] = False
        cast(Json, reconciliation["reference"])["semantic_hash"] = compute_evidence_value_hash(
            False
        )

    _rejects(cross_quarantine_projection, value)


def test_false_valid_ranked_gate_is_rejected_after_visible_value_conflicts(
    cross_quarantine_projection: DecisionProjectionV22,
) -> None:
    """A clean gate cannot survive a coordinated typed visible-value rewrite."""

    value = _canonical(cross_quarantine_projection)
    for stage in ("mapping", "provenance", "candidate_validation"):
        reconciliation = _entry(
            _inventory(value, stage, candidate_id="AP-001"),
            "reconciliation",
        )
        reconciliation["mapped_value"] = False
        cast(Json, reconciliation["reference"])["semantic_hash"] = compute_evidence_value_hash(
            False
        )

    _rejects(cross_quarantine_projection, value)


@pytest.mark.parametrize("mutation", ["missing", "extra", "swapped_order"])
def test_structured_anchor_set_is_exact_and_ordered(
    cross_quarantine_projection: DecisionProjectionV22,
    mutation: str,
) -> None:
    value = _canonical(cross_quarantine_projection)
    for stage in ("mapping", "provenance"):
        anchors = cast(list[Json], _inventory(value, stage)["structured_anchors"])
        if mutation == "missing":
            anchors.pop()
        elif mutation == "extra":
            anchors.append(deepcopy(anchors[-1]))
        else:
            anchors[0], anchors[1] = anchors[1], anchors[0]

    _rejects(cross_quarantine_projection, value)


@pytest.mark.parametrize(
    "mutation",
    [
        "anchor_value_without_hash",
        "anchor_value_and_hash_with_old_id",
        "anchor_hash_without_value",
        "swapped_category_values_and_hashes",
        "swapped_anchor_references",
        "noncanonical_anchor_path",
    ],
)
def test_structured_anchor_value_hash_role_and_path_are_indivisible(
    cross_quarantine_projection: DecisionProjectionV22,
    mutation: str,
) -> None:
    value = _canonical(cross_quarantine_projection)
    for stage in ("mapping", "provenance"):
        inventory = _inventory(value, stage)
        spreadsheet = _anchor(inventory, "spreadsheet")
        accounting = _anchor(inventory, "accounting_platform")
        if mutation == "anchor_value_without_hash":
            spreadsheet["value"] = "Oracle Sheets"
        elif mutation == "anchor_value_and_hash_with_old_id":
            spreadsheet["value"] = "Oracle Sheets"
            cast(Json, spreadsheet["reference"])["semantic_hash"] = compute_evidence_value_hash(
                "Oracle Sheets"
            )
        elif mutation == "anchor_hash_without_value":
            cast(Json, spreadsheet["reference"])["semantic_hash"] = "a" * 64
        elif mutation == "swapped_category_values_and_hashes":
            spreadsheet["value"], accounting["value"] = (
                accounting["value"],
                spreadsheet["value"],
            )
            spreadsheet_ref = cast(Json, spreadsheet["reference"])
            accounting_ref = cast(Json, accounting["reference"])
            spreadsheet_ref["semantic_hash"], accounting_ref["semantic_hash"] = (
                accounting_ref["semantic_hash"],
                spreadsheet_ref["semantic_hash"],
            )
        elif mutation == "swapped_anchor_references":
            spreadsheet["reference"], accounting["reference"] = (
                accounting["reference"],
                spreadsheet["reference"],
            )
        else:
            cast(Json, spreadsheet["reference"])["field_path"] = "record.spreadsheet"

    _rejects(cross_quarantine_projection, value)


def test_content_addressed_anchor_ids_bind_hash_role_and_long_safe_ids() -> None:
    semantic_hash = compute_evidence_value_hash("Excel")
    readable = _canonical_evidence_id_v22(
        "json",
        "snapshot-1",
        "AP-001",
        semantic_hash,
        "spreadsheet",
    )
    assert readable == f"json:snapshot-1:AP-001:{semantic_hash}:spreadsheet"

    long_snapshot = "s" * 128
    long_candidate = "c" * 128
    preimage = ":".join(
        (
            "json",
            long_snapshot,
            long_candidate,
            semantic_hash,
            "spreadsheet",
        )
    )
    bounded = _canonical_evidence_id_v22(
        "json",
        long_snapshot,
        long_candidate,
        semantic_hash,
        "spreadsheet",
    )
    assert bounded == f"json:{hashlib.sha256(preimage.encode('utf-8')).hexdigest()}"
    assert len(bounded) == 69


@pytest.mark.parametrize(
    ("claim_kind", "mapped_value"),
    [
        ("ap_years", 2),
        ("invoice_processing", 1),
        ("monthly_invoice_volume", 300.0),
        ("reconciliation", "true"),
    ],
)
def test_mapped_scalars_use_exact_kind_specific_json_types(
    cross_quarantine_projection: DecisionProjectionV22,
    claim_kind: str,
    mapped_value: object,
) -> None:
    value = _canonical(cross_quarantine_projection)
    for stage in ("mapping", "provenance"):
        entry = _entry(_inventory(value, stage), claim_kind)
        entry["mapped_value"] = mapped_value
        cast(Json, entry["reference"])["semantic_hash"] = compute_evidence_value_hash(
            cast(bool | int | float | str, mapped_value)
        )

    _rejects(cross_quarantine_projection, value)


def test_all_structured_anchors_are_required_in_the_map_receipt_union(
    cross_quarantine_projection: DecisionProjectionV22,
) -> None:
    value = _canonical(cross_quarantine_projection)
    anchor_id = cast(Json, _anchor(_inventory(value, "mapping"), "qualification")["reference"])[
        "evidence_id"
    ]
    receipt = next(
        item
        for item in cast(list[Json], value["receipts"])
        if item["command_kind"] == "map_candidate_claims" and item["status"] == "completed"
    )
    receipt["evidence_ids"] = [
        item for item in cast(list[str], receipt["evidence_ids"]) if item != anchor_id
    ]
    produced = next(
        gate
        for gate in cast(list[Json], value["trust_gates"])
        if gate["gate_id"] == receipt["produced_gate_id"]
    )
    produced["evidence_ids"] = list(cast(list[str], receipt["evidence_ids"]))

    _rejects(cross_quarantine_projection, value)


def test_matched_unsupported_category_requires_its_derived_gate_marker(
    cross_quarantine_projection: DecisionProjectionV22,
) -> None:
    value = _canonical(cross_quarantine_projection)
    for stage in ("mapping", "provenance"):
        inventory = _inventory(value, stage)
        anchor = _anchor(inventory, "spreadsheet")
        anchor["value"] = "Oracle Sheets"
        cast(Json, anchor["reference"])["semantic_hash"] = compute_evidence_value_hash(
            "Oracle Sheets"
        )
        entry = _entry(inventory, "spreadsheet")
        entry["mapped_value"] = "Oracle Sheets"
        cast(Json, entry["reference"])["semantic_hash"] = compute_evidence_value_hash(
            "Oracle Sheets"
        )

    _rejects(cross_quarantine_projection, value)


def test_typed_derivation_covers_optional_null_missing_domain_and_group_conflict(
    cross_quarantine_projection: DecisionProjectionV22,
) -> None:
    clean = _inventory(
        _canonical(cross_quarantine_projection),
        "mapping",
        candidate_id="AP-001",
    )

    optional_null = deepcopy(clean)
    optional_anchor = _anchor(optional_null, "spreadsheet")
    optional_anchor["value"] = None
    cast(Json, optional_anchor["reference"])["semantic_hash"] = _evidence_value_sha256(None)
    _readdress_anchor(optional_null, "spreadsheet")
    optional_inventory = EvidenceDispositionInventoryV22.model_validate_json(
        json.dumps(optional_null)
    )
    optional_result = _derive_cross_source_v22(optional_inventory)
    assert optional_result.state == "QUARANTINED"
    assert optional_result.conflicting_kinds == frozenset({"spreadsheet"})

    missing = deepcopy(clean)
    missing["entries"] = [
        item
        for item in cast(list[Json], missing["entries"])
        if item["claim_kind"] != "qualification"
    ]
    missing_result = _derive_cross_source_v22(
        EvidenceDispositionInventoryV22.model_validate_json(json.dumps(missing))
    )
    assert missing_result.state == "DEGRADED"
    assert missing_result.missing_kinds == frozenset({"qualification"})

    domain = deepcopy(clean)
    domain_anchor = _anchor(domain, "invoice_processing")
    domain_anchor["value"] = False
    cast(Json, domain_anchor["reference"])["semantic_hash"] = compute_evidence_value_hash(False)
    _readdress_anchor(domain, "invoice_processing")
    domain["record_invoice_processing"] = False
    domain["record_invoice_processing_reference"] = deepcopy(domain_anchor["reference"])
    domain_entry = _entry(domain, "invoice_processing")
    domain_entry["mapped_value"] = False
    cast(Json, domain_entry["reference"])["semantic_hash"] = compute_evidence_value_hash(False)
    domain_result = _derive_cross_source_v22(
        EvidenceDispositionInventoryV22.model_validate_json(json.dumps(domain))
    )
    assert domain_result.state == "QUARANTINED"
    assert "domain_invariant_conflict" in domain_result.terminal_reason_codes

    grouped = deepcopy(clean)
    grouped_anchor = _anchor(grouped, "ap_years")
    grouped_anchor["value"] = 4.0
    cast(Json, grouped_anchor["reference"])["semantic_hash"] = compute_evidence_value_hash(4.0)
    _readdress_anchor(grouped, "ap_years")
    grouped["record_ap_years"] = 4.0
    grouped["record_ap_years_reference"] = deepcopy(grouped_anchor["reference"])
    grouped_entry = _entry(grouped, "ap_years")
    grouped_entry["mapped_value"] = 3.991
    cast(Json, grouped_entry["reference"])["semantic_hash"] = compute_evidence_value_hash(3.991)
    second_entry = deepcopy(grouped_entry)
    second_entry["mapped_value"] = 4.009
    second_reference = cast(Json, second_entry["reference"])
    second_reference["evidence_id"] = "ev:grouped-ap-years-second"
    second_reference["semantic_hash"] = compute_evidence_value_hash(4.009)
    cast(list[Json], grouped["entries"]).append(second_entry)
    grouped_result = _derive_cross_source_v22(
        EvidenceDispositionInventoryV22.model_validate_json(json.dumps(grouped))
    )
    assert grouped_result.state == "QUARANTINED"
    assert grouped_result.conflicting_kinds == frozenset({"ap_years"})


def test_anchor_component_rejects_unknown_kind_and_inventory_id_collision(
    cross_quarantine_projection: DecisionProjectionV22,
) -> None:
    clean = _inventory(
        _canonical(cross_quarantine_projection),
        "mapping",
        candidate_id="AP-001",
    )
    unknown = deepcopy(_anchor(clean, "spreadsheet"))
    unknown["claim_kind"] = "note"
    with pytest.raises(ValueError, match="outside the comparison contract"):
        StructuredFieldAnchorV22.model_validate(unknown)

    collision = deepcopy(clean)
    anchor_id = cast(Json, _anchor(collision, "qualification")["reference"])["evidence_id"]
    cast(Json, _entry(collision, "spreadsheet")["reference"])["evidence_id"] = anchor_id
    with pytest.raises(ValueError, match="distinct from consumed evidence"):
        EvidenceDispositionInventoryV22.model_validate_json(json.dumps(collision))


def test_cross_source_quarantine_cannot_fabricate_category_marker(
    cross_quarantine_projection: DecisionProjectionV22,
) -> None:
    value = _canonical(cross_quarantine_projection)
    cross_source = _gate(value, "cross_source")
    cross_source["reason_codes"] = sorted(
        {*cast(list[str], cross_source["reason_codes"]), "category_not_supported"}
    )

    _rejects(cross_quarantine_projection, value)


def test_cross_source_quarantine_rejects_the_exact_coherent_pair_deletion_repro(
    cross_quarantine_projection: DecisionProjectionV22,
) -> None:
    value = _canonical(cross_quarantine_projection)
    _remove_cross_source_pair(value, "spreadsheet")

    _rejects(cross_quarantine_projection, value)


@pytest.mark.parametrize("claim_kind", ["accounting_platform", "qualification"])
def test_cross_source_quarantine_rejects_adjacent_optional_category_pair_deletions(
    cross_quarantine_projection: DecisionProjectionV22,
    claim_kind: str,
) -> None:
    value = _canonical(cross_quarantine_projection)
    _remove_cross_source_pair(value, claim_kind)

    _rejects(cross_quarantine_projection, value)


def test_cross_source_quarantine_rejects_an_omission_swap_to_a_matched_field(
    cross_quarantine_projection: DecisionProjectionV22,
) -> None:
    value = _canonical(cross_quarantine_projection)
    # Retain the known conflicting reconciliation pair while moving the only
    # omission to an otherwise matched bounded field.  Pairwise shape and
    # cardinality checks alone accepted this self-consistent rewrite.
    cross_source = _gate(value, "cross_source")
    assert any(item.endswith(":reconciliation") for item in cross_source["evidence_ids"])
    _remove_cross_source_pair(value, "spreadsheet")

    _rejects(cross_quarantine_projection, value)


@pytest.mark.parametrize(
    "replacement_kind",
    ["resume_identity", "adjacent_json_role"],
)
def test_cross_source_quarantine_rejects_same_count_catalog_substitution(
    cross_quarantine_projection: DecisionProjectionV22,
    replacement_kind: str,
) -> None:
    value = _canonical(cross_quarantine_projection)
    cross_source = _gate(value, "cross_source")
    evidence_ids = cast(list[str], cross_source["evidence_ids"])
    if replacement_kind == "resume_identity":
        replacement = next(
            evidence_id
            for evidence_id in cast(list[str], _gate(value, "identity")["evidence_ids"])
            if evidence_id.startswith("ev:")
        )
        replaced = next(item for item in evidence_ids if item.endswith(":spreadsheet"))
    else:
        replacement = next(
            evidence_id
            for evidence_id in cast(list[str], _gate(value, "identity")["evidence_ids"])
            if evidence_id.startswith("json:")
        )
        replaced = cast(
            Json,
            _anchor(_inventory(value, "mapping"), "spreadsheet")["reference"],
        )["evidence_id"]
    assert replacement not in evidence_ids
    cross_source["evidence_ids"] = sorted(
        replacement if item == replaced else item for item in evidence_ids
    )

    _rejects(cross_quarantine_projection, value)


def test_structured_anchor_id_must_be_the_canonical_field_id(
    cross_quarantine_projection: DecisionProjectionV22,
) -> None:
    value = _canonical(cross_quarantine_projection)
    original = cast(Json, _inventory(value, "mapping")["record_ap_years_reference"])["evidence_id"]
    replacement = cast(
        Json,
        _anchor(_inventory(value, "mapping"), "reconciliation")["reference"],
    )["evidence_id"]
    for stage in ("mapping", "provenance"):
        anchor = cast(Json, _inventory(value, stage)["record_ap_years_reference"])
        anchor["evidence_id"] = replacement
    receipt = next(
        item
        for item in cast(list[Json], value["receipts"])
        if item["command_kind"] == "map_candidate_claims" and item["status"] == "completed"
    )
    receipt["evidence_ids"] = sorted(
        replacement if item == original else item
        for item in cast(list[str], receipt["evidence_ids"])
    )
    produced = next(
        gate
        for gate in cast(list[Json], value["trust_gates"])
        if gate["gate_id"] == receipt["produced_gate_id"]
    )
    produced["evidence_ids"] = list(cast(list[str], receipt["evidence_ids"]))

    _rejects(cross_quarantine_projection, value)


def test_ranked_cross_source_gate_rejects_adjacent_json_role_substitution(
    cross_quarantine_projection: DecisionProjectionV22,
) -> None:
    value = _canonical(cross_quarantine_projection)
    cross_source = _gate(value, "cross_source", candidate_id="AP-001")
    expected = cast(
        Json,
        _anchor(
            _inventory(value, "mapping", candidate_id="AP-001"),
            "spreadsheet",
        )["reference"],
    )["evidence_id"]
    replacement = next(
        evidence_id
        for evidence_id in cast(
            list[str],
            _gate(value, "identity", candidate_id="AP-001")["evidence_ids"],
        )
        if evidence_id.startswith("json:")
    )
    evidence_ids = cast(list[str], cross_source["evidence_ids"])
    assert expected in evidence_ids and replacement not in evidence_ids
    cross_source["evidence_ids"] = sorted(
        replacement if item == expected else item for item in evidence_ids
    )

    _rejects(cross_quarantine_projection, value)


@pytest.mark.parametrize(
    "mutation",
    [
        "mapping_only_inventory",
        "provenance_only_inventory",
        "different_inventories",
        "mapping_catalog_extra",
        "batch_mapping_extra",
    ],
)
def test_mapping_commitment_boundaries_are_exact(
    quarantine_projection: DecisionProjectionV22,
    mutation: str,
) -> None:
    value = _canonical(quarantine_projection)
    mapping = _gate(value, "mapping")
    provenance = _gate(value, "provenance")
    if mutation == "mapping_only_inventory":
        provenance["evidence_inventory"] = None
    elif mutation == "provenance_only_inventory":
        mapping["evidence_inventory"] = None
    elif mutation == "different_inventories":
        inventory = cast(Json, mapping["evidence_inventory"])
        inventory["record_ap_years"] = 7.0
        cast(Json, inventory["record_ap_years_reference"])["semantic_hash"] = (
            compute_evidence_value_hash(7.0)
        )
    else:
        receipt = next(
            item
            for item in cast(list[Json], value["receipts"])
            if item["command_kind"] == "map_candidate_claims" and item["status"] == "completed"
        )
        fabricated = "ev:typed-mapping-fabricated"
        if mutation == "mapping_catalog_extra":
            receipt["evidence_ids"] = sorted(
                {*cast(list[str], receipt["evidence_ids"]), fabricated}
            )
        else:
            produced = next(
                gate
                for gate in cast(list[Json], value["trust_gates"])
                if gate["gate_id"] == receipt["produced_gate_id"]
            )
            produced["evidence_ids"] = sorted(
                {*cast(list[str], produced["evidence_ids"]), fabricated}
            )

    _rejects(quarantine_projection, value)


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_parse_catalog_id",
        "duplicate_mapping_stage",
        "mapping_gate_polarity",
        "terminal_quarantine_evidence",
        "terminal_anchor_rewrite",
        "parsed_catalog_missing_anchor",
        "untyped_invoice_hash",
    ],
)
def test_additional_mapping_lineage_mutations_fail_closed(
    quarantine_projection: DecisionProjectionV22,
    mutation: str,
) -> None:
    value = _canonical(quarantine_projection)
    if mutation == "duplicate_parse_catalog_id":
        receipt = next(
            item
            for item in cast(list[Json], value["receipts"])
            if item["command_kind"] == "parse_candidate_resumes" and item["status"] == "completed"
        )
        cast(list[str], receipt["evidence_ids"]).append(cast(list[str], receipt["evidence_ids"])[0])
    elif mutation == "duplicate_mapping_stage":
        ledger = cast(list[Json], value["trust_gates"])
        original = _gate(value, "mapping")
        duplicate = deepcopy(original)
        duplicate["gate_id"] = "g-mapping-duplicate"
        ledger.insert(ledger.index(original) + 1, duplicate)
    elif mutation == "mapping_gate_polarity":
        _gate(value, "mapping")["reason_codes"] = ["mapper_disagreement"]
    elif mutation == "terminal_quarantine_evidence":
        terminal = _gate(value, "candidate_validation")
        terminal["evidence_ids"] = [cast(list[str], _gate(value, "provenance")["evidence_ids"])[0]]
    elif mutation == "terminal_anchor_rewrite":
        terminal = _gate(value, "candidate_validation", candidate_id="AP-001")
        inventory = cast(Json, terminal["evidence_inventory"])
        cast(Json, inventory["record_ap_years_reference"])["evidence_id"] = (
            "json:forged:record-ap-years"
        )
    elif mutation == "parsed_catalog_missing_anchor":
        anchor_id = cast(Json, _inventory(value, "mapping")["record_ap_years_reference"])[
            "evidence_id"
        ]
        receipt = next(
            item
            for item in cast(list[Json], value["receipts"])
            if item["command_kind"] == "parse_candidate_resumes" and item["status"] == "completed"
        )
        receipt["evidence_ids"] = [
            item for item in cast(list[str], receipt["evidence_ids"]) if item != anchor_id
        ]
    else:
        for stage in ("mapping", "provenance"):
            invoice = _entry(_inventory(value, stage), "invoice_processing")
            cast(Json, invoice["reference"])["semantic_hash"] = "a" * 64

    _rejects(quarantine_projection, value)


def test_domain_quarantine_cannot_hide_an_unsupported_category(
    cross_quarantine_projection: DecisionProjectionV22,
) -> None:
    value = _canonical(cross_quarantine_projection)
    cross_source = _gate(value, "cross_source")
    cross_source["reason_codes"] = [
        "cross_source_match",
        "domain_invariant_conflict",
        "mapper_disagreement",
    ]
    terminal = _gate(value, "candidate_validation")
    terminal["reason_codes"] = [
        "cross_source_match",
        "domain_invariant_conflict",
        "evidence_admissible",
        "mapper_disagreement",
        "timeline_valid",
    ]
    route = next(
        item for item in cast(list[Json], value["routes"]) if item["candidate_id"] == "AP-005"
    )
    route["reason_codes"] = list(terminal["reason_codes"])
    explanation = next(
        item for item in cast(list[Json], value["explanations"]) if item["candidate_id"] == "AP-005"
    )
    explanation["reason_codes"] = list(terminal["reason_codes"])
    for stage in ("mapping", "provenance"):
        spreadsheet = _entry(_inventory(value, stage), "spreadsheet")
        cast(Json, spreadsheet["reference"])["semantic_hash"] = compute_evidence_value_hash(
            "Oracle Sheets"
        )

    _rejects(cross_quarantine_projection, value)


@pytest.mark.parametrize(
    "mutation",
    ["missing_timeline", "missing_cross_source", "inexact_cross_semantics"],
)
def test_graph_free_quarantine_requires_every_derived_terminal_stage(
    cross_quarantine_projection: DecisionProjectionV22,
    mutation: str,
) -> None:
    value = _canonical(cross_quarantine_projection)
    ledger = cast(list[Json], value["trust_gates"])
    terminal = _gate(value, "candidate_validation")
    if mutation == "missing_timeline":
        timeline = _gate(value, "timeline")
        cross_source = _gate(value, "cross_source")
        ledger.remove(timeline)
        ledger.remove(cross_source)
        terminal["input_gate_ids"] = [_gate(value, "provenance")["gate_id"]]
    elif mutation == "missing_cross_source":
        cross_source = _gate(value, "cross_source")
        ledger.remove(cross_source)
        terminal["input_gate_ids"] = [_gate(value, "timeline")["gate_id"]]
    else:
        cross_source = _gate(value, "cross_source")
        cross_source["reason_codes"] = ["mapper_disagreement"]
        terminal["reason_codes"] = [
            "evidence_admissible",
            "mapper_disagreement",
            "timeline_valid",
        ]
        route = next(
            item for item in cast(list[Json], value["routes"]) if item["candidate_id"] == "AP-005"
        )
        route["reason_codes"] = list(terminal["reason_codes"])
        explanation = next(
            item
            for item in cast(list[Json], value["explanations"])
            if item["candidate_id"] == "AP-005"
        )
        explanation["reason_codes"] = list(terminal["reason_codes"])

    _rejects(cross_quarantine_projection, value)
