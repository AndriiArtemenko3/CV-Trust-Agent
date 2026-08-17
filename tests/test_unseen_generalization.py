"""End-to-end and metamorphic release gates for ``unseen-canonical-v1``.

The evaluator owns the cohort and its oracle.  Runtime modules see only the
documented HTTP/detail/text-PDF contracts exercised by these tests.
"""

from __future__ import annotations

import ast
import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any, NamedTuple

import httpx
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from cv_trust_agent.models import (
    CandidateRoute,
    ClaimKind,
    ReviewBand,
    ReviewQueue,
    Strategy,
    TrustState,
    ValidatedBatchEvidence,
    ValidatedCandidateEvidence,
)
from cv_trust_agent.policy import DecisionController
from evaluation.release_spec_v2 import DecisionProjectionV2
from evaluation.unseen_cohort import (
    UNSEEN_COHORT,
    UNSEEN_DIRECTIVE_TARGET,
    UNSEEN_STRUCTURED_DIRECTIVE,
    UnseenCandidateSpec,
    UnseenScenario,
    materialize_unseen_fixture_root,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"
UNSEEN_IDS = tuple(candidate.candidate_id for candidate in UNSEEN_COHORT)


class _ExpectedRoute(NamedTuple):
    band: ReviewBand
    queue: ReviewQueue
    rank_key: tuple[int, int, int, int]
    evidence_rank: int
    display_position: int


EXPECTED_CLEAN_ROUTES = {
    "NC-101": _ExpectedRoute(
        ReviewBand.STRONG_EVIDENCE_MATCH,
        ReviewQueue.PRIORITY_HUMAN_REVIEW,
        (2, 4, 3, 8),
        1,
        1,
    ),
    "NC-102": _ExpectedRoute(
        ReviewBand.STRONG_EVIDENCE_MATCH,
        ReviewQueue.PRIORITY_HUMAN_REVIEW,
        (2, 4, 3, 8),
        1,
        2,
    ),
    "NC-103": _ExpectedRoute(
        ReviewBand.STRONG_EVIDENCE_MATCH,
        ReviewQueue.PRIORITY_HUMAN_REVIEW,
        (2, 4, 2, 8),
        2,
        3,
    ),
    "NC-104": _ExpectedRoute(
        ReviewBand.STRONG_EVIDENCE_MATCH,
        ReviewQueue.PRIORITY_HUMAN_REVIEW,
        (2, 4, 1, 7),
        3,
        4,
    ),
    "NC-105": _ExpectedRoute(
        ReviewBand.POTENTIAL_EVIDENCE_MATCH,
        ReviewQueue.STANDARD_HUMAN_REVIEW,
        (1, 4, 0, 7),
        4,
        5,
    ),
    "NC-106": _ExpectedRoute(
        ReviewBand.POTENTIAL_EVIDENCE_MATCH,
        ReviewQueue.STANDARD_HUMAN_REVIEW,
        (1, 3, 2, 7),
        5,
        6,
    ),
    "NC-107": _ExpectedRoute(
        ReviewBand.POTENTIAL_EVIDENCE_MATCH,
        ReviewQueue.STANDARD_HUMAN_REVIEW,
        (1, 3, 2, 7),
        5,
        7,
    ),
    "NC-108": _ExpectedRoute(
        ReviewBand.POTENTIAL_EVIDENCE_MATCH,
        ReviewQueue.STANDARD_HUMAN_REVIEW,
        (1, 3, 0, 6),
        6,
        8,
    ),
    "NC-109": _ExpectedRoute(
        ReviewBand.INSUFFICIENT_SUPPORTED_EVIDENCE,
        ReviewQueue.EVIDENCE_CHECK,
        (0, 2, 2, 7),
        7,
        9,
    ),
    "NC-110": _ExpectedRoute(
        ReviewBand.INSUFFICIENT_SUPPORTED_EVIDENCE,
        ReviewQueue.EVIDENCE_CHECK,
        (0, 1, 0, 4),
        8,
        10,
    ),
}


@pytest.fixture(scope="module")
def unseen_http_results(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[UnseenScenario, dict[str, Any]]:
    root = tmp_path_factory.mktemp("unseen-http")
    return {
        scenario: _run_public_http_case(root / scenario.value, scenario)
        for scenario in UnseenScenario
    }


def test_unseen_clean_public_http_run_matches_exact_frozen_oracle(
    unseen_http_results: dict[UnseenScenario, dict[str, Any]],
) -> None:
    payload = unseen_http_results[UnseenScenario.CLEAN]
    _assert_complete_public_fetch(payload)
    assert payload["strategy"] == Strategy.FULL_EVIDENCE_RANKING.value
    assert payload["ranking_scope"] == "COMPLETE"

    projection = DecisionProjectionV2.from_observation(payload)
    assert len(projection.routes) == len(EXPECTED_CLEAN_ROUTES) == 10
    for route in projection.routes:
        expected = EXPECTED_CLEAN_ROUTES[route.candidate_id]
        assert route.band == expected.band.value
        assert route.queue == expected.queue.value
        assert route.rank_key is not None
        assert route.rank_key.tuple() == expected.rank_key
        assert route.evidence_rank == expected.evidence_rank
        assert route.display_position == expected.display_position


def test_unseen_structured_directive_has_complete_semantic_noninterference(
    unseen_http_results: dict[UnseenScenario, dict[str, Any]],
) -> None:
    clean_payload = unseen_http_results[UnseenScenario.CLEAN]
    directive_payload = unseen_http_results[UnseenScenario.STRUCTURED_NOTE_DIRECTIVE]
    _assert_complete_public_fetch(directive_payload)

    clean = DecisionProjectionV2.from_observation(clean_payload)
    directive = DecisionProjectionV2.from_observation(directive_payload)
    assert directive.canonical_object() == clean.canonical_object()
    assert directive.digest() == clean.digest()
    assert (
        UNSEEN_STRUCTURED_DIRECTIVE.casefold()
        not in json.dumps(
            directive_payload,
            sort_keys=True,
        ).casefold()
    )


def test_unseen_conflict_quarantines_only_target_and_preserves_other_rank_semantics(
    unseen_http_results: dict[UnseenScenario, dict[str, Any]],
) -> None:
    clean_payload = unseen_http_results[UnseenScenario.CLEAN]
    conflict_payload = unseen_http_results[UnseenScenario.SEMANTIC_CONFLICT]
    _assert_complete_public_fetch(conflict_payload)
    assert conflict_payload["strategy"] == Strategy.SUPPORTED_ONLY_RANKING.value
    assert conflict_payload["ranking_scope"] == "PARTIAL"

    clean = DecisionProjectionV2.from_observation(clean_payload)
    conflict = DecisionProjectionV2.from_observation(conflict_payload)
    clean_routes = {route.candidate_id: route for route in clean.routes}
    conflict_routes = {route.candidate_id: route for route in conflict.routes}
    assert set(clean_routes) == set(conflict_routes) == set(UNSEEN_IDS)

    target = conflict_routes[UNSEEN_DIRECTIVE_TARGET]
    assert target.band == ReviewBand.INTEGRITY_HOLD.value
    assert target.queue == ReviewQueue.INTEGRITY_REVIEW.value
    assert target.rank_key is None
    assert target.evidence_rank is None
    assert target.display_position is None
    assert target.support_graph is None

    for candidate_id in set(UNSEEN_IDS) - {UNSEEN_DIRECTIVE_TARGET}:
        before = clean_routes[candidate_id]
        after = conflict_routes[candidate_id]
        assert after.band == before.band
        assert after.queue == before.queue
        assert after.rank_key == before.rank_key
        assert after.evidence_rank == before.evidence_rank


def _ap_years_strategy(spec: UnseenCandidateSpec) -> st.SearchStrategy[float]:
    if spec.ap_years == 2.0:
        return st.just(2.0)
    if spec.ap_years > 2.0:
        return st.integers(min_value=21, max_value=70).map(lambda value: value / 10)
    return st.integers(min_value=0, max_value=19).map(lambda value: value / 10)


def _volume_strategy(spec: UnseenCandidateSpec) -> st.SearchStrategy[int | None]:
    if spec.monthly_invoice_volume is None:
        return st.none()
    if spec.monthly_invoice_volume == 300:
        return st.just(300)
    if spec.monthly_invoice_volume > 300:
        return st.integers(min_value=301, max_value=1_000)
    return st.integers(min_value=0, max_value=299)


_RENAMED_IDS = tuple(f"GX-{number:02d}" for number in range(10))
_ID_PERMUTATIONS = st.permutations(_RENAMED_IDS)
_INPUT_PERMUTATIONS = st.permutations(tuple(range(len(UNSEEN_COHORT))))


@settings(max_examples=35, deadline=None, derandomize=True, database=None)
@given(renamed_ids=_ID_PERMUTATIONS)
def test_unseen_property_safe_id_renaming_preserves_rank_semantics(
    renamed_ids: Sequence[str],
) -> None:
    baseline = _rank_specs(UNSEEN_COHORT)
    renamed = _rank_specs(UNSEEN_COHORT, candidate_ids=renamed_ids)

    for original, renamed_id in zip(UNSEEN_IDS, renamed_ids, strict=True):
        assert _rank_semantics(renamed[renamed_id]) == _rank_semantics(baseline[original])


@settings(max_examples=35, deadline=None, derandomize=True, database=None)
@given(renamed_ids=_ID_PERMUTATIONS)
def test_unseen_property_safe_id_renaming_changes_display_only_inside_exact_ties(
    renamed_ids: Sequence[str],
) -> None:
    baseline = _rank_specs(UNSEEN_COHORT)
    renamed = _rank_specs(UNSEEN_COHORT, candidate_ids=renamed_ids)
    tie_positions = ({1, 2}, {6, 7})

    for original, renamed_id in zip(UNSEEN_IDS, renamed_ids, strict=True):
        before = baseline[original]
        after = renamed[renamed_id]
        if before.display_position in {1, 2, 6, 7}:
            expected_positions = next(
                positions for positions in tie_positions if before.display_position in positions
            )
            assert after.display_position in expected_positions
        else:
            assert after.display_position == before.display_position


@settings(max_examples=35, deadline=None, derandomize=True, database=None)
@given(order=_INPUT_PERMUTATIONS)
def test_unseen_property_input_permutation_is_fully_invariant(order: Sequence[int]) -> None:
    baseline = _rank_specs(UNSEEN_COHORT)
    permuted = tuple(UNSEEN_COHORT[index] for index in order)
    assert _rank_specs(permuted) == baseline


@settings(max_examples=35, deadline=None, derandomize=True, database=None)
@given(
    ap_years=st.tuples(*(_ap_years_strategy(spec) for spec in UNSEEN_COHORT)),
    monthly_volumes=st.tuples(*(_volume_strategy(spec) for spec in UNSEEN_COHORT)),
)
def test_unseen_property_non_threshold_value_variation_is_invariant(
    ap_years: Sequence[float],
    monthly_volumes: Sequence[int | None],
) -> None:
    varied = tuple(
        replace(spec, ap_years=years, monthly_invoice_volume=volume)
        for spec, years, volume in zip(
            UNSEEN_COHORT,
            ap_years,
            monthly_volumes,
            strict=True,
        )
    )
    assert _rank_specs(varied) == _rank_specs(UNSEEN_COHORT)


@settings(max_examples=35, deadline=None, derandomize=True, database=None)
@given(
    renamed_ids=_ID_PERMUTATIONS,
    order=_INPUT_PERMUTATIONS,
    ap_years=st.tuples(*(_ap_years_strategy(spec) for spec in UNSEEN_COHORT)),
    monthly_volumes=st.tuples(*(_volume_strategy(spec) for spec in UNSEEN_COHORT)),
)
def test_unseen_property_renaming_permutation_and_value_variation_compose(
    renamed_ids: Sequence[str],
    order: Sequence[int],
    ap_years: Sequence[float],
    monthly_volumes: Sequence[int | None],
) -> None:
    varied = tuple(
        replace(spec, ap_years=years, monthly_invoice_volume=volume)
        for spec, years, volume in zip(
            UNSEEN_COHORT,
            ap_years,
            monthly_volumes,
            strict=True,
        )
    )
    renamed_by_original = dict(zip(UNSEEN_IDS, renamed_ids, strict=True))
    permuted = tuple(varied[index] for index in order)
    permuted_ids = tuple(renamed_by_original[spec.candidate_id] for spec in permuted)
    changed = _rank_specs(permuted, candidate_ids=permuted_ids)
    baseline = _rank_specs(UNSEEN_COHORT)

    for original, renamed_id in renamed_by_original.items():
        assert _rank_semantics(changed[renamed_id]) == _rank_semantics(baseline[original])


def test_runtime_has_no_unseen_cohort_or_evaluator_oracle_knowledge() -> None:
    forbidden_literals = {"unseen-canonical-v1", *UNSEEN_IDS}
    for path in sorted((SOURCE_ROOT / "cv_trust_agent").rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        assert forbidden_literals.isdisjoint(source.split()), path
        assert not any(literal in source for literal in forbidden_literals), path
        tree = ast.parse(source, filename=path.as_posix())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(alias.name != "evaluation" for alias in node.names), path
                assert all(not alias.name.startswith("evaluation.") for alias in node.names), path
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                assert node.module != "evaluation", path
                assert not node.module.startswith("evaluation."), path


def _run_public_http_case(root: Path, scenario: UnseenScenario) -> dict[str, Any]:
    port = _loopback_port_or_skip()
    source_url = f"http://127.0.0.1:{port}"
    fixture_root = materialize_unseen_fixture_root(
        root / "fixture",
        scenario,
        source_base_url=source_url,
    )
    environment = _subprocess_environment()
    process = subprocess.Popen(
        (
            sys.executable,
            "-m",
            "cv_trust_agent.cli",
            "serve",
            "--scenario",
            "clean",
            "--fixture-root",
            fixture_root.as_posix(),
            "--port",
            str(port),
        ),
        cwd=root,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_for_health(process, source_url)
        completed = subprocess.run(
            (
                sys.executable,
                "-m",
                "cv_trust_agent.cli",
                "run",
                "--source-url",
                source_url,
                "--mapper",
                "deterministic",
            ),
            cwd=root,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    finally:
        _terminate(process)
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert isinstance(payload, dict)
    return payload


def _assert_complete_public_fetch(payload: dict[str, Any]) -> None:
    assert payload["index_fetched"] is True
    assert payload["candidate_details_parsed"] == 10
    assert payload["resumes_parsed"] == 10
    assert payload["unavailable_candidate_count"] == 0
    assert payload["http_request_count"] == 21
    requests = payload["http_requests"]
    assert len(requests) == 21
    assert requests[0]["path"] == "/v1/applications"
    assert [request["path"] for request in requests[1:11]] == [
        f"/v1/applications/{candidate_id}" for candidate_id in UNSEEN_IDS
    ]
    assert [request["path"] for request in requests[11:]] == [
        f"/v1/resumes/{candidate_id}.pdf" for candidate_id in UNSEEN_IDS
    ]
    assert all("?" not in request["path"] for request in requests)
    assert payload["execution_mode"] == "EXECUTED"


def _rank_specs(
    specs: Sequence[UnseenCandidateSpec],
    *,
    candidate_ids: Sequence[str] | None = None,
) -> dict[str, CandidateRoute]:
    selected_ids = (
        tuple(spec.candidate_id for spec in specs)
        if candidate_ids is None
        else tuple(candidate_ids)
    )
    assert len(specs) == len(selected_ids)
    candidates = tuple(
        _validated_candidate(spec, candidate_id)
        for spec, candidate_id in zip(specs, selected_ids, strict=True)
    )
    batch = ValidatedBatchEvidence(
        batch_id="generalisation-property",
        snapshot_id="generalisation-snapshot",
        candidates=candidates,
        batch_integrity_valid=True,
        mapper_disagreement=False,
    )
    routes = DecisionController().rank(batch, Strategy.FULL_EVIDENCE_RANKING)
    return {route.candidate_id: route for route in routes}


def _validated_candidate(
    spec: UnseenCandidateSpec,
    candidate_id: str,
) -> ValidatedCandidateEvidence:
    claim_kinds = [
        ClaimKind.AP_YEARS,
        ClaimKind.INVOICE_PROCESSING,
        ClaimKind.RECONCILIATION,
        ClaimKind.EMPLOYMENT_INTERVAL,
    ]
    for present, kind in (
        (spec.spreadsheet is not None, ClaimKind.SPREADSHEET),
        (spec.accounting_platform is not None, ClaimKind.ACCOUNTING_PLATFORM),
        (spec.monthly_invoice_volume is not None, ClaimKind.MONTHLY_INVOICE_VOLUME),
        (spec.qualification is not None, ClaimKind.QUALIFICATION),
    ):
        if present:
            claim_kinds.append(kind)
    return ValidatedCandidateEvidence(
        candidate_id=candidate_id,
        snapshot_id="generalisation-snapshot",
        trust_state=TrustState.USABLE,
        ap_years=spec.ap_years,
        invoice_processing=spec.invoice_processing,
        reconciliation=spec.reconciliation,
        spreadsheet_supported=spec.spreadsheet is not None,
        accounting_platform_supported=spec.accounting_platform is not None,
        monthly_invoice_volume=spec.monthly_invoice_volume,
        qualification_supported=spec.qualification is not None,
        corroborated_claim_kinds=tuple(claim_kinds),
    )


def _rank_semantics(route: CandidateRoute) -> tuple[object, ...]:
    return (
        route.band,
        route.queue,
        route.rank_key,
        route.evidence_rank,
    )


def _loopback_port_or_skip() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            return int(probe.getsockname()[1])
    except OSError as exc:
        pytest.skip(f"platform forbids loopback bind: {exc}")


def _wait_for_health(process: subprocess.Popen[str], source_url: str) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.communicate(timeout=1)[0]
            pytest.fail(f"source process exited before health check:\n{output}")
        try:
            response = httpx.get(f"{source_url}/health", timeout=0.2)
        except httpx.HTTPError:
            time.sleep(0.05)
            continue
        if response.status_code == 200:
            return
        time.sleep(0.05)
    pytest.fail("source process did not become healthy")


def _terminate(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def _subprocess_environment() -> dict[str, str]:
    environment = os.environ.copy()
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        f"{SOURCE_ROOT}{os.pathsep}{REPOSITORY_ROOT}{os.pathsep}{existing}"
        if existing
        else f"{SOURCE_ROOT}{os.pathsep}{REPOSITORY_ROOT}"
    )
    return environment
