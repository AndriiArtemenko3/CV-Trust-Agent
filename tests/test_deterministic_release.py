from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeAlias

import pytest

from evaluation.deterministic_release import (
    DeterministicReleaseError,
    validate_deterministic_release_artifact,
)
from evaluation.deterministic_release_v2 import (
    DeterministicReleaseV2Error,
    _explanation_summary,
)
from evaluation.oracle_spec_v2 import ExplanationExpectationV2
from evaluation.release_spec_v2 import ExplanationV2

JsonObject: TypeAlias = dict[str, Any]
REPOSITORY_ROOT = Path(__file__).parents[1]
FULL_REPORT = REPOSITORY_ROOT / "evidence" / "deterministic-summary.json"
DEFAULT_ORACLE = REPOSITORY_ROOT / "evaluation" / "oracle.json"


@pytest.fixture
def valid_report() -> JsonObject:
    loaded = json.loads(FULL_REPORT.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _write_json(tmp_path: Path, value: object, *, name: str = "artifact.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    return path


def test_v2_explanation_reason_codes_have_set_semantics() -> None:
    observed = ExplanationV2(
        template="candidate_unavailable",
        candidate_id="AP-008",
        reason_codes=("candidate_unavailable", "retrieval_failed"),
    )
    expected = ExplanationExpectationV2(
        template="candidate_unavailable",
        candidate_id="AP-008",
        reason_codes=("retrieval_failed", "candidate_unavailable"),
    )
    assert _explanation_summary(observed.model_dump(mode="json")) == _explanation_summary(
        expected.model_dump(mode="json")
    )


def test_v2_explanation_summary_rejects_noncanonical_reason_code_encoding() -> None:
    with pytest.raises(
        DeterministicReleaseV2Error,
        match="reason codes are not canonical JSON",
    ):
        _explanation_summary(
            {
                "template": "candidate_unavailable",
                "candidate_id": "AP-008",
                "reason_codes": ("candidate_unavailable", "retrieval_failed"),
            }
        )


def test_full_default_release_returns_only_bounded_hash_metadata() -> None:
    metadata = validate_deterministic_release_artifact(FULL_REPORT)

    assert metadata.passed is True
    assert metadata.schema_version == 1
    assert metadata.case_count == 22
    assert metadata.invariant_count == 44
    assert metadata.artifact_sha256 == hashlib.sha256(FULL_REPORT.read_bytes()).hexdigest()
    assert metadata.oracle_sha256 == hashlib.sha256(DEFAULT_ORACLE.read_bytes()).hexdigest()
    assert metadata.suite_id.startswith("cv-trust-agent/deterministic-release/v1:")
    assert len(metadata.suite_id) < 128
    assert all(
        len(digest) == 64 and set(digest) <= set("0123456789abcdef")
        for digest in (
            metadata.artifact_sha256,
            metadata.oracle_sha256,
            metadata.release_binding_sha256,
        )
    )
    expected_binding = hashlib.sha256(
        json.dumps(
            {
                "artifact_sha256": metadata.artifact_sha256,
                "oracle_sha256": metadata.oracle_sha256,
                "suite_id": metadata.suite_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    assert metadata.release_binding_sha256 == expected_binding


def test_semantically_identical_expected_oracle_keeps_stable_suite_id(tmp_path: Path) -> None:
    original = validate_deterministic_release_artifact(FULL_REPORT)
    oracle = json.loads(DEFAULT_ORACLE.read_text(encoding="utf-8"))
    reformatted = _write_json(tmp_path, oracle, name="expected-oracle.json")

    copied = validate_deterministic_release_artifact(FULL_REPORT, reformatted)

    assert copied.suite_id == original.suite_id
    assert copied.oracle_sha256 == hashlib.sha256(reformatted.read_bytes()).hexdigest()
    assert copied.oracle_sha256 != original.oracle_sha256
    assert copied.release_binding_sha256 != original.release_binding_sha256


def test_explicit_custom_oracle_cannot_promote_a_custom_run(
    tmp_path: Path,
    valid_report: JsonObject,
) -> None:
    oracle = json.loads(DEFAULT_ORACLE.read_text(encoding="utf-8"))
    oracle["cases"][0]["expected_strategy"] = "SUPPORTED_ONLY_RANKING"
    valid_report["cases"][0]["strategy"] = "SUPPORTED_ONLY_RANKING"
    oracle_path = _write_json(tmp_path, oracle, name="custom-oracle.json")
    artifact_path = _write_json(tmp_path, valid_report)

    with pytest.raises(DeterministicReleaseError, match="complete default suite"):
        validate_deterministic_release_artifact(artifact_path, oracle_path)


@pytest.mark.parametrize("selection", ["one", "showcase"])
def test_partial_and_showcase_reports_are_diagnostic_only(
    tmp_path: Path,
    valid_report: JsonObject,
    selection: str,
) -> None:
    if selection == "one":
        selected = valid_report["cases"][:1]
    else:
        showcase_names = {
            "clean",
            "structured_note_directive",
            "semantic_no_directive",
            "compound",
        }
        selected = [case for case in valid_report["cases"] if case["name"] in showcase_names]
    valid_report["cases"] = selected
    valid_report["case_count"] = len(selected)
    valid_report["passed_case_count"] = len(selected)

    with pytest.raises(DeterministicReleaseError, match="full passing suite"):
        validate_deterministic_release_artifact(_write_json(tmp_path, valid_report))


def test_missing_or_reordered_cases_are_rejected(
    tmp_path: Path,
    valid_report: JsonObject,
) -> None:
    valid_report["cases"][0], valid_report["cases"][1] = (
        valid_report["cases"][1],
        valid_report["cases"][0],
    )
    with pytest.raises(DeterministicReleaseError, match="ordered default suite"):
        validate_deterministic_release_artifact(_write_json(tmp_path, valid_report))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda report: report.update({"passed": False}),
        lambda report: report["cases"][0].update({"passed": False}),
        lambda report: report["cases"][0]["checks"].update({"strategy": False}),
        lambda report: report["invariants"].update({"failure_matrix_distinct": False}),
    ],
    ids=("report", "case", "check", "invariant"),
)
def test_every_report_case_check_and_invariant_must_pass(
    tmp_path: Path,
    valid_report: JsonObject,
    mutation: Callable[[JsonObject], None],
) -> None:
    mutation(valid_report)
    with pytest.raises(DeterministicReleaseError, match=r"did not pass|must all pass"):
        validate_deterministic_release_artifact(_write_json(tmp_path, valid_report))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda report: report.update({"unexpected": True}),
        lambda report: report["cases"][0].update({"unexpected": True}),
        lambda report: report["cases"][0]["checks"].update({"unexpected": True}),
        lambda report: report["invariants"].update({"unexpected": True}),
        lambda report: report["cases"][0]["routes"][0].update({"unexpected": True}),
        lambda report: report["cases"][0]["routes"][0]["rank_key"].update({"unexpected": 1}),
        lambda report: report["cases"][0]["receipts"][0].update({"unexpected": True}),
    ],
    ids=("root", "case", "checks", "invariants", "route", "rank-key", "receipt"),
)
def test_every_public_object_has_an_exact_allow_listed_schema(
    tmp_path: Path,
    valid_report: JsonObject,
    mutation: Callable[[JsonObject], None],
) -> None:
    mutation(valid_report)
    with pytest.raises(DeterministicReleaseError, match="invalid schema"):
        validate_deterministic_release_artifact(_write_json(tmp_path, valid_report))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda report: report.update({"passed": 1}),
        lambda report: report["cases"][0].update({"fingerprint": "A" * 64}),
        lambda report: report["cases"][0].update({"strategy": "X" * 65}),
        lambda report: report["cases"][0]["routes"][0].update({"band": "X" * 65}),
        lambda report: report["cases"][0]["routes"][0].update({"evidence_rank": True}),
        lambda report: report["cases"][0]["receipts"][0].update({"command_id": "x" * 129}),
    ],
    ids=("bool-as-int", "uppercase-digest", "strategy", "band", "rank-bool", "command-id"),
)
def test_public_values_have_exact_types_and_bounded_strings(
    tmp_path: Path,
    valid_report: JsonObject,
    mutation: Callable[[JsonObject], None],
) -> None:
    mutation(valid_report)
    with pytest.raises(DeterministicReleaseError):
        validate_deterministic_release_artifact(_write_json(tmp_path, valid_report))


def test_truncated_routes_and_oracle_disagreement_are_rejected(
    tmp_path: Path,
    valid_report: JsonObject,
) -> None:
    truncated = copy.deepcopy(valid_report)
    truncated["cases"][0]["routes"] = truncated["cases"][0]["routes"][:-1]
    with pytest.raises(DeterministicReleaseError, match="array length"):
        validate_deterministic_release_artifact(_write_json(tmp_path, truncated))

    disagrees = copy.deepcopy(valid_report)
    disagrees["cases"][0]["routes"][0].update(
        {
            "band": "POTENTIAL_EVIDENCE_MATCH",
            "queue": "STANDARD_HUMAN_REVIEW",
        }
    )
    with pytest.raises(DeterministicReleaseError, match="disagrees with the oracle"):
        validate_deterministic_release_artifact(_write_json(tmp_path, disagrees))


def test_incomplete_receipt_pairs_are_rejected(
    tmp_path: Path,
    valid_report: JsonObject,
) -> None:
    valid_report["cases"][0]["receipts"][1]["status"] = "failed"
    with pytest.raises(DeterministicReleaseError, match="command pair"):
        validate_deterministic_release_artifact(_write_json(tmp_path, valid_report))


@pytest.mark.parametrize("kind", ["raw-string", "truncated", "duplicate-key", "oversized-integer"])
def test_non_object_and_non_strict_json_reports_are_rejected(
    tmp_path: Path,
    kind: str,
) -> None:
    content = FULL_REPORT.read_text(encoding="utf-8")
    if kind == "raw-string":
        content = json.dumps(content)
    elif kind == "truncated":
        content = content[:100]
    else:
        if kind == "duplicate-key":
            content = content.replace(
                '"case_count": 22,',
                '"case_count": 22, "case_count": 22,',
                1,
            )
        else:
            content = '{"schema_version":' + ("9" * 5_000) + "}"
    artifact = tmp_path / "artifact.json"
    artifact.write_text(content, encoding="utf-8")

    with pytest.raises(DeterministicReleaseError):
        validate_deterministic_release_artifact(artifact)


def test_oversized_artifact_is_rejected_before_json_parsing(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.json"
    artifact.write_bytes(b'"' + (b"x" * 1_048_576) + b'"')

    with pytest.raises(DeterministicReleaseError, match="byte length"):
        validate_deterministic_release_artifact(artifact)
