"""Independent evaluator regressions for exact evidence disposition closure."""

from __future__ import annotations

import json
from collections.abc import Callable
from copy import deepcopy
from typing import Any, cast

import pytest

from cv_trust_agent.models import ClaimKind
from evaluation.release_spec_v22 import (
    DecisionProjectionV22,
    ReleaseSpecV22Error,
    canonical_json_bytes,
)
from tests.test_engine_unit import SNAPSHOT_ID, _case, _record, _run

Json = dict[str, Any]


def _projection(
    *, unsupported_category: bool = False, without_interval: bool = False
) -> DecisionProjectionV22:
    record = _record(
        "AP-001",
        spreadsheet="Oracle Sheets" if unsupported_category else "Excel",
        invoice_processing=not without_interval,
        monthly_invoice_volume=None if without_interval else 600,
    )
    case = _case((record,))
    outputs = case.outputs
    if without_interval:
        output = outputs[(SNAPSHOT_ID, "AP-001")]
        output = output.model_copy(
            update={
                "claims": tuple(
                    claim
                    for claim in output.claims
                    if claim.kind is not ClaimKind.EMPLOYMENT_INTERVAL
                )
            }
        )
        outputs = {(SNAPSHOT_ID, "AP-001"): output}
    observation = cast(Json, _run(case, outputs=outputs).model_dump(mode="json", exclude_none=True))
    return DecisionProjectionV22.from_observation(observation)


@pytest.fixture(scope="module")
def clean_projection() -> DecisionProjectionV22:
    return _projection()


@pytest.fixture(scope="module")
def unsupported_projection() -> DecisionProjectionV22:
    return _projection(unsupported_category=True)


@pytest.fixture(scope="module")
def timeline_drop_projection() -> DecisionProjectionV22:
    return _projection(without_interval=True)


def _canonical(projection: DecisionProjectionV22) -> Json:
    return cast(Json, json.loads(canonical_json_bytes(projection.canonical_object())))


def _gate(canonical: Json, stage: str) -> Json:
    return next(
        gate
        for gate in cast(list[Json], canonical["trust_gates"])
        if gate["candidate_id"] == "AP-001" and gate["stage"] == stage
    )


def _entries(gate: Json) -> list[Json]:
    inventory = cast(Json, gate["evidence_inventory"])
    return cast(list[Json], inventory["entries"])


def _mutated(
    projection: DecisionProjectionV22,
    mutate: Callable[[Json], None],
) -> Json:
    value = _canonical(projection)
    mutate(value)
    return value


def _rejects(projection: DecisionProjectionV22, mutate: Callable[[Json], None]) -> None:
    with pytest.raises(ReleaseSpecV22Error):
        DecisionProjectionV22.from_canonical(_mutated(projection, mutate))


def test_clean_projection_carries_exact_consumed_and_terminal_inventories(
    clean_projection: DecisionProjectionV22,
) -> None:
    provenance = next(
        gate
        for gate in clean_projection.trust_gates
        if gate.candidate_id == "AP-001" and gate.stage == "provenance"
    )
    terminal = next(
        gate
        for gate in clean_projection.trust_gates
        if gate.candidate_id == "AP-001" and gate.stage == "candidate_validation"
    )
    assert provenance.evidence_inventory is not None
    assert terminal.evidence_inventory is not None
    assert {item.state for item in provenance.evidence_inventory.entries} == {"consumed"}
    assert {item.state for item in terminal.evidence_inventory.entries} == {"released"}


def test_legitimate_unsupported_category_has_one_derived_drop(
    unsupported_projection: DecisionProjectionV22,
) -> None:
    terminal = next(
        gate
        for gate in unsupported_projection.trust_gates
        if gate.candidate_id == "AP-001" and gate.stage == "candidate_validation"
    )
    assert terminal.evidence_inventory is not None
    dropped = [item for item in terminal.evidence_inventory.entries if item.state != "released"]
    assert [(item.claim_kind, item.state) for item in dropped] == [
        ("spreadsheet", "dropped_unsupported_category")
    ]


def test_positive_ap_without_interval_uses_explicit_timeline_drop(
    timeline_drop_projection: DecisionProjectionV22,
) -> None:
    timeline = next(
        gate
        for gate in timeline_drop_projection.trust_gates
        if gate.candidate_id == "AP-001" and gate.stage == "timeline"
    )
    terminal = next(
        gate
        for gate in timeline_drop_projection.trust_gates
        if gate.candidate_id == "AP-001" and gate.stage == "candidate_validation"
    )
    assert timeline.reason_codes == ("timeline_valid",)
    assert terminal.evidence_inventory is not None
    assert [
        (item.claim_kind, item.state)
        for item in terminal.evidence_inventory.entries
        if item.state != "released"
    ] == [("ap_years", "dropped_timeline_policy")]


def test_fabricated_full_inventory_edge_is_not_anchored_to_mapping(
    clean_projection: DecisionProjectionV22,
) -> None:
    def mutate(value: Json) -> None:
        provenance = _gate(value, "provenance")
        terminal = _gate(value, "candidate_validation")
        cross_source = _gate(value, "cross_source")
        consumed = deepcopy(
            next(item for item in _entries(provenance) if item["claim_kind"] == "spreadsheet")
        )
        final = deepcopy(consumed)
        fabricated = "ev:index-2026-08-15:AP-001:spreadsheet_fabricated"
        cast(Json, consumed["reference"])["evidence_id"] = fabricated
        cast(Json, consumed["reference"])["semantic_hash"] = "a" * 64
        cast(Json, final["reference"])["evidence_id"] = fabricated
        cast(Json, final["reference"])["semantic_hash"] = "a" * 64
        final["state"] = "dropped_unsupported_category"
        _entries(provenance).append(consumed)
        _entries(terminal).append(final)
        _entries(provenance).sort(key=lambda item: cast(Json, item["reference"])["evidence_id"])
        _entries(terminal).sort(key=lambda item: cast(Json, item["reference"])["evidence_id"])
        provenance["evidence_ids"] = sorted([*provenance["evidence_ids"], fabricated])
        cross_source["reason_codes"] = sorted(
            {*cross_source["reason_codes"], "category_not_supported"}
        )

    _rejects(clean_projection, mutate)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_terminal",
        "duplicate_terminal",
        "cross_candidate",
        "cross_snapshot",
        "identity_role",
        "application_json",
        "cross_source_drop",
    ],
)
def test_inventory_partition_and_typed_reference_mutations_fail(
    clean_projection: DecisionProjectionV22,
    mutation: str,
) -> None:
    def mutate(value: Json) -> None:
        provenance = _gate(value, "provenance")
        terminal = _gate(value, "candidate_validation")
        terminal_entries = _entries(terminal)
        if mutation == "missing_terminal":
            terminal_entries.pop()
        elif mutation == "duplicate_terminal":
            terminal_entries.append(deepcopy(terminal_entries[0]))
        elif mutation == "cross_candidate":
            cast(Json, terminal_entries[0]["reference"])["candidate_id"] = "AP-999"
        elif mutation == "cross_snapshot":
            cast(Json, terminal_entries[0]["reference"])["snapshot_id"] = "other-snapshot"
        elif mutation == "identity_role":
            terminal_entries[0]["claim_kind"] = "candidate_id"
        elif mutation == "application_json":
            reference = cast(Json, terminal_entries[0]["reference"])
            reference.update(
                {
                    "source_kind": "application_json",
                    "page": None,
                    "document_page_count": None,
                    "page_width": None,
                    "page_height": None,
                    "bbox": None,
                }
            )
        else:
            terminal_entries[0]["state"] = "dropped_cross_source"
        # Keep both inventory copies equal for ownership mutations so the test
        # reaches the independent type/ownership checks rather than only the
        # consumed/final equality check.
        if mutation in {"cross_candidate", "cross_snapshot", "identity_role", "application_json"}:
            _entries(provenance)[0] = deepcopy(terminal_entries[0])
            _entries(provenance)[0]["state"] = "consumed"

    _rejects(clean_projection, mutate)


def test_marker_reason_swap_cannot_mint_a_drop(
    clean_projection: DecisionProjectionV22,
) -> None:
    def mutate(value: Json) -> None:
        cross_source = _gate(value, "cross_source")
        cross_source["reason_codes"] = sorted(
            {*cross_source["reason_codes"], "category_not_supported"}
        )

    _rejects(clean_projection, mutate)


@pytest.mark.parametrize(
    "mutation",
    [
        "duplicate_gate_evidence",
        "duplicate_gate_reason",
        "wrong_inventory_boundary",
        "released_at_provenance",
        "gate_inventory_mismatch",
        "consumed_at_terminal",
        "bad_employment_role",
        "bad_scalar_role",
        "integer_record_years",
        "missing_inventory",
    ],
)
def test_inventory_schema_and_gate_attachment_are_strict(
    clean_projection: DecisionProjectionV22,
    mutation: str,
) -> None:
    def mutate(value: Json) -> None:
        provenance = _gate(value, "provenance")
        terminal = _gate(value, "candidate_validation")
        if mutation == "duplicate_gate_evidence":
            provenance["evidence_ids"].append(provenance["evidence_ids"][0])
        elif mutation == "duplicate_gate_reason":
            provenance["reason_codes"].append(provenance["reason_codes"][0])
        elif mutation == "wrong_inventory_boundary":
            _gate(value, "timeline")["evidence_inventory"] = deepcopy(
                provenance["evidence_inventory"]
            )
        elif mutation == "released_at_provenance":
            _entries(provenance)[0]["state"] = "released"
        elif mutation == "gate_inventory_mismatch":
            provenance["evidence_ids"].pop()
        elif mutation == "consumed_at_terminal":
            _entries(terminal)[0]["state"] = "consumed"
        elif mutation == "bad_employment_role":
            item = next(
                entry
                for entry in _entries(provenance)
                if entry["claim_kind"] == "employment_interval"
            )
            cast(Json, item["reference"])["field_path"] = "resume.ap_years"
        elif mutation == "bad_scalar_role":
            item = next(
                entry for entry in _entries(provenance) if entry["claim_kind"] == "spreadsheet"
            )
            item["claim_kind"] = "accounting_platform"
        elif mutation == "integer_record_years":
            cast(Json, provenance["evidence_inventory"])["record_ap_years"] = 4
        else:
            provenance["evidence_inventory"] = None

    _rejects(clean_projection, mutate)


def test_dangling_marker_gate_cannot_authorize_overclosure(
    clean_projection: DecisionProjectionV22,
) -> None:
    def mutate(value: Json) -> None:
        cross_source = deepcopy(_gate(value, "cross_source"))
        cross_source["gate_id"] = "g9999"
        cross_source["reason_codes"] = sorted(
            {*cross_source["reason_codes"], "category_not_supported"}
        )
        cast(list[Json], value["trust_gates"]).append(cross_source)

    _rejects(clean_projection, mutate)


def test_supported_categorical_hash_cannot_be_called_unsupported(
    unsupported_projection: DecisionProjectionV22,
) -> None:
    def mutate(value: Json) -> None:
        for gate in (_gate(value, "provenance"), _gate(value, "candidate_validation")):
            item = next(entry for entry in _entries(gate) if entry["claim_kind"] == "spreadsheet")
            cast(Json, item["reference"])["semantic_hash"] = (
                "51836a92267ac0078db151c68f5f1b31bdf949156c7a4e690c2c2b86a5eb624b"
            )

    _rejects(unsupported_projection, mutate)


def test_ranked_candidate_cannot_relabel_category_drop_as_cross_source(
    unsupported_projection: DecisionProjectionV22,
) -> None:
    def mutate(value: Json) -> None:
        terminal = _gate(value, "candidate_validation")
        item = next(entry for entry in _entries(terminal) if entry["claim_kind"] == "spreadsheet")
        item["state"] = "dropped_cross_source"

    _rejects(unsupported_projection, mutate)


def test_timeline_drop_requires_exact_record_scalar_hash(
    timeline_drop_projection: DecisionProjectionV22,
) -> None:
    def mutate(value: Json) -> None:
        for gate in (_gate(value, "provenance"), _gate(value, "candidate_validation")):
            item = next(entry for entry in _entries(gate) if entry["claim_kind"] == "ap_years")
            cast(Json, item["reference"])["semantic_hash"] = "b" * 64

    _rejects(timeline_drop_projection, mutate)


def test_timeline_reason_swap_is_independently_rejected(
    clean_projection: DecisionProjectionV22,
) -> None:
    _rejects(
        clean_projection,
        lambda value: _gate(value, "timeline").update({"reason_codes": ["timeline_drift"]}),
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [("record_ap_years", 4.1), ("record_invoice_processing", False)],
)
def test_record_scalars_must_equal_released_evidence(
    clean_projection: DecisionProjectionV22,
    field: str,
    value: object,
) -> None:
    def mutate(canonical: Json) -> None:
        for gate in (_gate(canonical, "provenance"), _gate(canonical, "candidate_validation")):
            inventory = cast(Json, gate["evidence_inventory"])
            inventory[field] = value

    _rejects(clean_projection, mutate)


def test_inventory_is_audit_bound_but_action_inert(
    clean_projection: DecisionProjectionV22,
) -> None:
    provenance = next(
        gate
        for gate in clean_projection.trust_gates
        if gate.candidate_id == "AP-001" and gate.stage == "provenance"
    )
    assert provenance.evidence_inventory is not None
    changed_inventory = provenance.evidence_inventory.model_copy(
        update={"record_ap_years": provenance.evidence_inventory.record_ap_years + 0.1}
    )
    changed_gate = provenance.model_copy(update={"evidence_inventory": changed_inventory})
    changed = clean_projection.model_copy(
        update={
            "trust_gates": tuple(
                changed_gate if gate.gate_id == provenance.gate_id else gate
                for gate in clean_projection.trust_gates
            )
        }
    )
    assert changed.action_semantic_digest() == clean_projection.action_semantic_digest()
    assert changed.audit_digest() != clean_projection.audit_digest()
