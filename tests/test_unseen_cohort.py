"""Independent input and source-boundary tests for unseen-canonical-v1."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, cast

from fastapi.testclient import TestClient

from cv_trust_agent.dataset import clean_cohort, compute_index_manifest_hash, compute_semantic_hash
from cv_trust_agent.models import BatchIndex, CandidateRecord
from cv_trust_agent.pdf_evidence import extract_pdf_evidence
from cv_trust_agent.source import create_app
from evaluation.fixture_commitment import normalized_fixture_tree_hash
from evaluation.unseen_cohort import (
    FROZEN_SPEC_SHA256,
    UNSEEN_COHORT,
    UNSEEN_DIRECTIVE_TARGET,
    UNSEEN_INDEX_ID,
    UNSEEN_STRUCTURED_DIRECTIVE,
    UnseenScenario,
    materialize_unseen_fixture_root,
    unseen_spec_sha256,
)


def test_unseen_specification_is_frozen_and_disjoint_from_canonical_fixture() -> None:
    assert unseen_spec_sha256() == FROZEN_SPEC_SHA256
    unseen_ids = {candidate.candidate_id for candidate in UNSEEN_COHORT}
    canonical_ids = {candidate.candidate_id for candidate in clean_cohort()}
    assert unseen_ids == {f"NC-{number}" for number in range(101, 111)}
    assert unseen_ids.isdisjoint(canonical_ids)
    canonical_records = {
        tuple(
            sorted(
                (key, value) for key, value in asdict(candidate).items() if key != "candidate_id"
            )
        )
        for candidate in clean_cohort()
    }
    assert all(
        tuple(
            sorted(
                (key, value) for key, value in asdict(candidate).items() if key != "candidate_id"
            )
        )
        not in canonical_records
        for candidate in UNSEEN_COHORT
    )


def test_unseen_fixture_is_deterministic_strict_and_fully_committed(tmp_path: Path) -> None:
    first = materialize_unseen_fixture_root(
        tmp_path / "first",
        UnseenScenario.CLEAN,
        source_base_url="http://127.0.0.1:8101",
    )
    second = materialize_unseen_fixture_root(
        tmp_path / "second",
        UnseenScenario.CLEAN,
        source_base_url="http://127.0.0.1:8102",
    )

    assert normalized_fixture_tree_hash(first) == normalized_fixture_tree_hash(second)
    raw_index = _json_object(first / "applications.json")
    index = BatchIndex.model_validate(raw_index)
    assert len(index.candidates) == 10
    raw_candidates = cast(list[dict[str, Any]], raw_index["candidates"])
    assert compute_index_manifest_hash(raw_candidates) == index.manifest_hash
    for entry in index.candidates:
        raw_detail = _json_object(first / "details" / f"{entry.candidate_id}.json")
        detail = CandidateRecord.model_validate(raw_detail)
        pdf_bytes = (first / "resumes" / f"{entry.candidate_id}.pdf").read_bytes()
        extraction = extract_pdf_evidence(pdf_bytes)
        assert detail.candidate_id == entry.candidate_id
        assert compute_semantic_hash(raw_detail) == detail.semantic_hash == entry.semantic_hash
        assert hashlib.sha256(pdf_bytes).hexdigest() == entry.resume_sha256
        assert extraction.page_count == 1
        assert f"Candidate ID: {entry.candidate_id}" in extraction.visible_text


def test_unseen_variants_are_strict_minimal_pairs(tmp_path: Path) -> None:
    clean = materialize_unseen_fixture_root(
        tmp_path / "clean",
        UnseenScenario.CLEAN,
        source_base_url="http://127.0.0.1:8200",
    )
    directive = materialize_unseen_fixture_root(
        tmp_path / "directive",
        UnseenScenario.STRUCTURED_NOTE_DIRECTIVE,
        source_base_url="http://127.0.0.1:8200",
    )
    conflict = materialize_unseen_fixture_root(
        tmp_path / "conflict",
        UnseenScenario.SEMANTIC_CONFLICT,
        source_base_url="http://127.0.0.1:8200",
    )

    target = UNSEEN_DIRECTIVE_TARGET
    for candidate in UNSEEN_COHORT:
        candidate_id = candidate.candidate_id
        clean_pdf = (clean / "resumes" / f"{candidate_id}.pdf").read_bytes()
        assert (directive / "resumes" / f"{candidate_id}.pdf").read_bytes() == clean_pdf
        assert (conflict / "resumes" / f"{candidate_id}.pdf").read_bytes() == clean_pdf
        clean_detail = _json_object(clean / "details" / f"{candidate_id}.json")
        directive_detail = _json_object(directive / "details" / f"{candidate_id}.json")
        conflict_detail = _json_object(conflict / "details" / f"{candidate_id}.json")
        if candidate_id != target:
            assert directive_detail == clean_detail
            assert conflict_detail == clean_detail

    clean_target = _json_object(clean / "details" / f"{target}.json")
    directive_target = _json_object(directive / "details" / f"{target}.json")
    conflict_target = _json_object(conflict / "details" / f"{target}.json")
    assert directive_target["note"] == (f"{clean_target['note']} {UNSEEN_STRUCTURED_DIRECTIVE}")
    assert {key for key in clean_target if clean_target[key] != directive_target[key]} == {
        "note",
        "semantic_hash",
    }
    assert conflict_target["ap_years"] == 8.0
    assert {key for key in clean_target if clean_target[key] != conflict_target[key]} == {
        "ap_years",
        "semantic_hash",
    }


def test_source_serves_prebuilt_unseen_root_without_runtime_scenario_knowledge(
    tmp_path: Path,
) -> None:
    root = materialize_unseen_fixture_root(
        tmp_path,
        UnseenScenario.CLEAN,
        source_base_url="http://127.0.0.1:8000",
    )
    expected_tree = normalized_fixture_tree_hash(root)
    app = create_app(scenario="clean", fixture_root=root)

    with TestClient(app) as client:
        index = client.get("/v1/applications")
        detail = client.get("/v1/applications/NC-107")
        resume = client.get("/v1/resumes/NC-107.pdf")
        old_fixture_id = client.get("/v1/applications/AP-005")

    assert index.status_code == detail.status_code == resume.status_code == 200
    assert index.headers["x-index-id"] == UNSEEN_INDEX_ID
    assert detail.headers["x-index-id"] == UNSEEN_INDEX_ID
    assert {entry["candidate_id"] for entry in index.json()["candidates"]} == {
        f"NC-{number}" for number in range(101, 111)
    }
    assert detail.json()["candidate_id"] == "NC-107"
    assert resume.content.startswith(b"%PDF")
    assert old_fixture_id.status_code == 404
    assert normalized_fixture_tree_hash(root) == expected_tree


def _json_object(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value
