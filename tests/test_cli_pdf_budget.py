"""Integration regression for the one-budget-per-PDF-batch contract."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

import cv_trust_agent.cli as cli_module
from cv_trust_agent.dataset import (
    Scenario,
    materialize_fixture_root,
    read_application_index,
    read_candidate_detail,
    resume_path,
)
from cv_trust_agent.engine import ResumeFetchMaterial
from cv_trust_agent.intake import prepare_candidate_detail, prepare_candidate_resume
from cv_trust_agent.models import BatchIndex
from cv_trust_agent.pdf_evidence import PdfBatchBudget
from cv_trust_agent.retrieval import HttpSourceClient, RetrievedCandidateDetail, RetrievedResume


def test_cli_resume_batch_shares_one_wall_clock_budget(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Every parser worker in one agent batch must debit the same wall budget."""

    fixture_root = materialize_fixture_root(tmp_path / "fixture", Scenario.CLEAN)
    index = BatchIndex.model_validate(read_application_index(fixture_root))
    selected_entries = index.candidates[:2]
    details = tuple(
        prepare_candidate_detail(
            entry,
            RetrievedCandidateDetail(
                entry.candidate_id,
                read_candidate_detail(fixture_root, entry.candidate_id),
                (),
            ),
        )
        for entry in selected_entries
    )
    resumes = tuple(
        RetrievedResume(
            entry.candidate_id,
            resume_path(fixture_root, entry.candidate_id).read_bytes(),
            (),
        )
        for entry in selected_entries
    )
    fetched = ResumeFetchMaterial(resumes, details)

    observed_budgets: list[PdfBatchBudget | None] = []

    def recording_prepare(
        *args: Any,
        batch_budget: PdfBatchBudget | None = None,
        **kwargs: Any,
    ) -> Any:
        observed_budgets.append(batch_budget)
        return prepare_candidate_resume(*args, batch_budget=batch_budget, **kwargs)

    monkeypatch.setattr("cv_trust_agent.cli.prepare_candidate_resume", recording_prepare)
    provider = cli_module._HttpCandidateEvidenceProvider(cast(HttpSourceClient, object()), [])

    material = provider.parse_candidate_resumes(index, fetched)

    assert len(material.mapper_requests) == 2
    assert len(observed_budgets) == 2
    assert observed_budgets[0] is not None
    assert observed_budgets[1] is observed_budgets[0]
