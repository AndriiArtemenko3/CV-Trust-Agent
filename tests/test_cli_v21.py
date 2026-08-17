"""Focused CLI regressions for the V2.1 public fault adapter."""

from __future__ import annotations

import pytest

from cv_trust_agent.cli import _validated_fault_candidate


@pytest.mark.parametrize(
    "candidate_id",
    (
        "https:example.com",
        "scheme:value",
        "path/segment",
        "path\\segment",
        "encoded%2Fsegment",
        "two words",
        " leading",
        "trailing ",
        "control\x1bvalue",
    ),
)
def test_fault_adapter_rejects_non_source_identifier_shapes(candidate_id: str) -> None:
    with pytest.raises(ValueError, match="safe identifier contract"):
        _validated_fault_candidate(candidate_id)


@pytest.mark.parametrize("candidate_id", ("AP-005", "NC_101", "batch.v2", "candidate-9"))
def test_fault_adapter_accepts_bounded_safe_identifiers(candidate_id: str) -> None:
    assert _validated_fault_candidate(candidate_id) == candidate_id
