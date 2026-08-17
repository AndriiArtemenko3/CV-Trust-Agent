"""Independent V2.2 evaluator regressions for a material timeline-drift hold."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import date
from typing import Any, cast

import pytest

from cv_trust_agent.evidence_validation import compute_evidence_value_hash
from cv_trust_agent.models import ClaimKind
from evaluation.release_spec_v22 import (
    DecisionProjectionV22,
    ReleaseSpecV22Error,
    canonical_json_bytes,
)
from tests.test_engine_unit import SNAPSHOT_ID, _Case, _case, _record, _run

Json = dict[str, Any]


def _drift_observation(*, unsupported_category: bool = False) -> Json:
    record = _record(
        "AP-001",
        ap_years=1.0,
        spreadsheet="Oracle Sheets" if unsupported_category else "Excel",
    )
    case = _case((record,))
    request = case.requests[0]
    output = case.outputs[(SNAPSHOT_ID, record.candidate_id)]
    endpoints = {
        "employment_start": date(2023, 1, 1),
        "employment_end": date(2026, 1, 1),
    }
    request = request.model_copy(
        update={
            "evidence_catalog": tuple(
                item.model_copy(
                    update={
                        "semantic_hash": compute_evidence_value_hash(
                            endpoints[item.field_path.rsplit(".", maxsplit=1)[-1]].isoformat()
                        )
                    }
                )
                if item.field_path is not None
                and item.field_path.rsplit(".", maxsplit=1)[-1] in endpoints
                else item
                for item in request.evidence_catalog
            )
        }
    )
    output = output.model_copy(
        update={
            "claims": tuple(
                claim.model_copy(
                    update={
                        "start_date": endpoints["employment_start"],
                        "end_date": endpoints["employment_end"],
                    }
                )
                if claim.kind is ClaimKind.EMPLOYMENT_INTERVAL
                else claim
                for claim in output.claims
            )
        }
    )
    drift_case = _Case(
        case.index,
        case.records,
        (request,),
        {(SNAPSHOT_ID, record.candidate_id): output},
    )
    return cast(Json, _run(drift_case).model_dump(mode="json", exclude_none=True))


@pytest.fixture(scope="module")
def drift_projection() -> DecisionProjectionV22:
    return DecisionProjectionV22.from_observation(_drift_observation())


@pytest.fixture(scope="module")
def clean_projection() -> DecisionProjectionV22:
    observation = cast(
        Json,
        _run(_case((_record("AP-001", ap_years=1.0),))).model_dump(mode="json", exclude_none=True),
    )
    return DecisionProjectionV22.from_observation(observation)


def _canonical(projection: DecisionProjectionV22) -> Json:
    return cast(Json, json.loads(canonical_json_bytes(projection.canonical_object())))


def _record_gate(value: Json, stage: str) -> Json:
    return next(
        gate
        for gate in cast(list[Json], value["trust_gates"])
        if gate["candidate_id"] == "AP-001" and gate["stage"] == stage
    )


def _endpoint_hash(value: str) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _terminal_receipt(value: Json, version: int, kind: str) -> Json:
    return next(
        receipt
        for receipt in cast(list[Json], value["receipts"])
        if receipt["plan_version"] == version
        and receipt["command_kind"] == kind
        and receipt["status"] != "started"
    )


def _batch_gate(value: Json, stage: str, reason: str) -> Json:
    return next(
        gate
        for gate in cast(list[Json], value["trust_gates"])
        if gate["candidate_id"] is None
        and gate["stage"] == stage
        and reason in cast(list[str], gate["reason_codes"])
    )


def _replace_start_date(value: Json, replacement: str) -> None:
    for stage in ("provenance", "candidate_validation"):
        inventory = cast(Json, _record_gate(value, stage)["evidence_inventory"])
        for item in cast(list[Json], inventory["entries"]):
            reference = cast(Json, item["reference"])
            if reference["field_path"] == "resume.employment_start":
                item["date_value"] = replacement
                reference["semantic_hash"] = _endpoint_hash(replacement)


def _mutate_hostile_drift_hold(value: Json, mutation: str) -> None:
    plans = cast(list[Json], value["plans"])
    ledger = cast(list[Json], value["trust_gates"])
    if mutation == "wrong_v3_trigger":
        plans[2]["trigger_codes"] = ["evidence_admissible"]
        cast(Json, value["plan_diff"])["trigger_codes"] = ["evidence_admissible"]
    elif mutation == "changed_v2_status":
        receipt = _terminal_receipt(value, 2, "rank_supported_evidence")
        receipt["status"] = "failed"
        receipt["reason_codes"] = ["command_failed"]
    elif mutation == "duplicate_mapping_catalog_id":
        receipt = _terminal_receipt(value, 1, "map_candidate_claims")
        evidence_ids = cast(list[str], receipt["evidence_ids"])
        evidence_ids.append(evidence_ids[0])
        evidence_ids.sort()
    elif mutation == "blocked_gate_evidence":
        blocked = _batch_gate(value, "pre_release", "pre_release_blocked")
        blocked["evidence_ids"] = [
            cast(list[str], _record_gate(value, "provenance")["evidence_ids"])[0]
        ]
    elif mutation == "rejected_planning_reason":
        planning = _batch_gate(value, "planning", "plan_revised")
        if "pre_release_blocked" in cast(list[str], planning["reason_codes"]):
            planning = next(
                gate
                for gate in ledger
                if gate["candidate_id"] is None
                and gate["stage"] == "planning"
                and gate["reason_codes"] == ["plan_revised"]
            )
        planning["reason_codes"] = ["plan_revised", "pre_release_blocked"]
    elif mutation == "inexact_hold_route":
        route = cast(list[Json], value["routes"])[0]
        route["band"] = "EVIDENCE_UNAVAILABLE"
        route["queue"] = "AWAITING_EVIDENCE"
    elif mutation == "coherent_non_drift_hold":
        _replace_start_date(value, "2025-01-01")
        timeline = _record_gate(value, "timeline")
        timeline.update(
            {
                "state": "USABLE",
                "outcome": "ALLOW",
                "reason_codes": ["timeline_valid"],
            }
        )
        terminal = _record_gate(value, "candidate_validation")
        terminal.update(
            {
                "state": "USABLE",
                "outcome": "ALLOW",
                "reason_codes": [
                    "cross_source_match",
                    "evidence_admissible",
                    "timeline_valid",
                ],
            }
        )
        value["explanations"] = [
            item
            for item in cast(list[Json], value["explanations"])
            if item["template"] != "record_degraded"
        ]
    elif mutation == "inexact_drift_explanation":
        explanation = next(
            item
            for item in cast(list[Json], value["explanations"])
            if item["template"] == "record_degraded"
        )
        explanation["reason_codes"] = ["cross_source_match", "evidence_admissible"]
    elif mutation == "duplicate_identity_gate":
        identity = _record_gate(value, "identity")
        duplicate = deepcopy(identity)
        duplicate["gate_id"] = "g9997"
        ledger.insert(ledger.index(identity) + 1, duplicate)
    elif mutation == "missing_terminal_inventory":
        _record_gate(value, "candidate_validation")["evidence_inventory"] = None
    elif mutation == "inventory_scalar_mismatch":
        inventory = cast(
            Json,
            _record_gate(value, "candidate_validation")["evidence_inventory"],
        )
        inventory["record_ap_years"] = 1.1
    elif mutation == "terminal_endpoint_rewrite":
        inventory = cast(
            Json,
            _record_gate(value, "candidate_validation")["evidence_inventory"],
        )
        item = next(
            entry
            for entry in cast(list[Json], inventory["entries"])
            if cast(Json, entry["reference"])["field_path"] == "resume.employment_start"
        )
        item["date_value"] = "2022-01-01"
        cast(Json, item["reference"])["semantic_hash"] = _endpoint_hash("2022-01-01")
    elif mutation == "wrong_ap_scalar_hash":
        for stage in ("provenance", "candidate_validation"):
            inventory = cast(Json, _record_gate(value, stage)["evidence_inventory"])
            item = next(
                entry
                for entry in cast(list[Json], inventory["entries"])
                if entry["claim_kind"] == "ap_years"
            )
            cast(Json, item["reference"])["semantic_hash"] = "a" * 64
    elif mutation == "timeline_conflict_not_drift":
        _replace_start_date(value, "2025-12-01")
    elif mutation == "fabricated_disposition_state":
        inventory = cast(
            Json,
            _record_gate(value, "candidate_validation")["evidence_inventory"],
        )
        item = next(
            entry
            for entry in cast(list[Json], inventory["entries"])
            if entry["claim_kind"] == "reconciliation"
        )
        item["state"] = "dropped_cross_source"
    elif mutation == "released_edge_missing_from_stage":
        cross_source = _record_gate(value, "cross_source")
        cross_source["evidence_ids"] = [
            item
            for item in cast(list[str], cross_source["evidence_ids"])
            if not item.endswith(":reconciliation") or item.startswith("json:")
        ]
    elif mutation == "unsupported_drop_still_in_stage":
        for stage in ("provenance", "candidate_validation"):
            inventory = cast(Json, _record_gate(value, stage)["evidence_inventory"])
            item = next(
                entry
                for entry in cast(list[Json], inventory["entries"])
                if entry["claim_kind"] == "spreadsheet"
            )
            cast(Json, item["reference"])["semantic_hash"] = _endpoint_hash("Oracle Sheets")
            if stage == "candidate_validation":
                item["state"] = "dropped_unsupported_category"
        cross_source = _record_gate(value, "cross_source")
        cross_source["reason_codes"] = ["category_not_supported", "cross_source_match"]
    elif mutation == "degraded_cross_source":
        _record_gate(value, "cross_source").update({"state": "DEGRADED", "outcome": "RESTRICT"})
    elif mutation == "terminal_missing_identity_edge":
        terminal = _record_gate(value, "candidate_validation")
        identity_ids = set(cast(list[str], _record_gate(value, "identity")["evidence_ids"]))
        terminal["evidence_ids"] = [
            item for item in cast(list[str], terminal["evidence_ids"]) if item not in identity_ids
        ]
    elif mutation == "unpaired_endpoint_role":
        for stage in ("provenance", "candidate_validation"):
            inventory = cast(Json, _record_gate(value, stage)["evidence_inventory"])
            item = next(
                entry
                for entry in cast(list[Json], inventory["entries"])
                if cast(Json, entry["reference"])["field_path"] == "resume.employment_start"
            )
            cast(Json, item["reference"])["field_path"] = "resume.employment_end"
    else:  # pragma: no cover - the parametrization is a closed local vocabulary
        raise AssertionError(mutation)


def test_material_drift_is_represented_by_the_exact_failed_closed_v3_hold(
    drift_projection: DecisionProjectionV22,
) -> None:
    assert drift_projection.execution_mode == "FAILED_CLOSED"
    assert drift_projection.strategy == "BATCH_INTEGRITY_HOLD"
    assert drift_projection.ranking_scope == "NONE"
    assert [plan.strategy for plan in drift_projection.plans] == [
        "FULL_EVIDENCE_RANKING",
        "SUPPORTED_ONLY_RANKING",
        "BATCH_INTEGRITY_HOLD",
    ]
    assert drift_projection.plan_diff is not None
    assert (drift_projection.plan_diff.from_version, drift_projection.plan_diff.to_version) == (
        2,
        3,
    )
    assert drift_projection.plan_diff.trigger_codes == ("pre_release_blocked",)
    assert all(
        route.rank_key is None and not route.evidence_ids for route in drift_projection.routes
    )
    assert (
        DecisionProjectionV22.from_canonical(drift_projection.canonical_object()).audit_digest()
        == drift_projection.audit_digest()
    )


def test_material_drift_with_an_unsupported_category_retains_exact_drop_accounting() -> None:
    projection = DecisionProjectionV22.from_observation(
        _drift_observation(unsupported_category=True)
    )
    canonical = _canonical(projection)
    inventory = cast(
        Json,
        _record_gate(canonical, "candidate_validation")["evidence_inventory"],
    )

    assert [
        (item["claim_kind"], item["state"])
        for item in cast(list[Json], inventory["entries"])
        if item["state"] != "released"
    ] == [("spreadsheet", "dropped_unsupported_category")]
    assert projection.strategy == "BATCH_INTEGRITY_HOLD"


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong_v3_trigger",
        "changed_v2_status",
        "duplicate_mapping_catalog_id",
        "blocked_gate_evidence",
        "rejected_planning_reason",
        "inexact_hold_route",
        "coherent_non_drift_hold",
        "inexact_drift_explanation",
        "duplicate_identity_gate",
        "missing_terminal_inventory",
        "inventory_scalar_mismatch",
        "terminal_endpoint_rewrite",
        "wrong_ap_scalar_hash",
        "timeline_conflict_not_drift",
        "fabricated_disposition_state",
        "released_edge_missing_from_stage",
        "unsupported_drop_still_in_stage",
        "degraded_cross_source",
        "terminal_missing_identity_edge",
        "unpaired_endpoint_role",
    ],
)
def test_graph_free_drift_hold_rejects_coherent_hostile_edge_mutations(
    drift_projection: DecisionProjectionV22,
    mutation: str,
) -> None:
    value = _canonical(drift_projection)
    _mutate_hostile_drift_hold(value, mutation)

    with pytest.raises(ReleaseSpecV22Error):
        DecisionProjectionV22.from_canonical(value)


def test_material_drift_cannot_retain_or_reconstruct_a_ranked_route(
    drift_projection: DecisionProjectionV22,
    clean_projection: DecisionProjectionV22,
) -> None:
    value = _canonical(drift_projection)
    clean = _canonical(clean_projection)
    cast(list[Json], value["routes"])[0] = deepcopy(cast(list[Json], clean["routes"])[0])

    with pytest.raises(ReleaseSpecV22Error):
        DecisionProjectionV22.from_canonical(value)


def test_forged_drift_marker_with_non_drift_dates_is_rejected(
    drift_projection: DecisionProjectionV22,
) -> None:
    value = _canonical(drift_projection)
    replacement = "2025-01-01"
    for stage in ("provenance", "candidate_validation"):
        inventory = cast(Json, _record_gate(value, stage)["evidence_inventory"])
        for item in cast(list[Json], inventory["entries"]):
            reference = cast(Json, item["reference"])
            if reference["field_path"] == "resume.employment_start":
                item["date_value"] = replacement
                reference["semantic_hash"] = _endpoint_hash(replacement)

    with pytest.raises(ReleaseSpecV22Error):
        DecisionProjectionV22.from_canonical(value)


@pytest.mark.parametrize("mutation", ["missing_date", "wrong_hash", "reversed_interval"])
def test_typed_endpoint_mutations_cannot_authorize_a_drift_hold(
    drift_projection: DecisionProjectionV22,
    mutation: str,
) -> None:
    value = _canonical(drift_projection)
    for stage in ("provenance", "candidate_validation"):
        inventory = cast(Json, _record_gate(value, stage)["evidence_inventory"])
        entries = cast(list[Json], inventory["entries"])
        start = next(
            item
            for item in entries
            if cast(Json, item["reference"])["field_path"] == "resume.employment_start"
        )
        end = next(
            item
            for item in entries
            if cast(Json, item["reference"])["field_path"] == "resume.employment_end"
        )
        if mutation == "missing_date":
            start["date_value"] = None
        elif mutation == "wrong_hash":
            cast(Json, start["reference"])["semantic_hash"] = "f" * 64
        else:
            start["date_value"] = "2027-01-01"
            cast(Json, start["reference"])["semantic_hash"] = _endpoint_hash("2027-01-01")
            end["date_value"] = "2026-01-01"
            cast(Json, end["reference"])["semantic_hash"] = _endpoint_hash("2026-01-01")

    with pytest.raises(ReleaseSpecV22Error):
        DecisionProjectionV22.from_canonical(value)


def test_terminal_drift_plan_diff_cannot_omit_prior_removed_commands(
    drift_projection: DecisionProjectionV22,
) -> None:
    value = _canonical(drift_projection)
    diff = cast(Json, value["plan_diff"])
    cast(list[str], diff["removed_command_ids"]).pop()

    with pytest.raises(ReleaseSpecV22Error):
        DecisionProjectionV22.from_canonical(value)
