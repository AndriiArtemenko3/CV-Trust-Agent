"""Frozen input registry for the 25-case deterministic V2 release suite.

This module owns input materialisation only.  It contains no expected strategy,
route, explanation, or verdict and is never imported by a semantic validator.
"""

from __future__ import annotations

from functools import partial
from pathlib import Path

from cv_trust_agent.dataset import materialize_fixture_root
from evaluation.capture_v2 import CaseInputV2
from evaluation.unseen_cohort import (
    UnseenScenario,
    materialize_unseen_fixture_root,
)

_CANONICAL_CASES: tuple[tuple[str, str], ...] = (
    ("clean", "clean"),
    ("structured_note_directive", "structured_note_directive"),
    ("structured_note_combined", "structured_note_combined"),
    ("structured_note_fabricated_data", "structured_note_fabricated_data"),
    ("structured_note_benign", "structured_note_benign"),
    ("rank_injection_exact", "rank_injection_exact"),
    ("descriptive_self_promotion", "descriptive_self_promotion"),
    ("combined_black_box_instruction", "combined_black_box_instruction"),
    ("schema_aware_white_box", "schema_aware_white_box"),
    ("hidden_job_evidence", "hidden_job_evidence"),
    ("hidden_low_contrast", "hidden_low_contrast"),
    ("hidden_off_page", "hidden_off_page"),
    ("hidden_metadata", "hidden_metadata"),
    ("hidden_microtext", "hidden_microtext"),
    ("semantic_no_directive", "semantic_conflict_no_directive"),
    ("poisoned", "poisoned"),
    ("structured_note_poisoned", "structured_note_poisoned"),
    ("cv_substitution", "cv_substitution"),
    ("index_manifest_invalid", "index_manifest_invalid"),
    ("mapper_disagreement_only", "clean"),
    ("detail_timeout", "detail_timeout"),
    ("compound", "detail_timeout"),
)


def _materialize_canonical(
    scenario: str,
    root: Path,
    source_base_url: str,
) -> None:
    materialize_fixture_root(root, scenario, source_base_url=source_base_url)


def _materialize_unseen(
    scenario: UnseenScenario,
    root: Path,
    source_base_url: str,
) -> None:
    materialize_unseen_fixture_root(
        root,
        scenario,
        source_base_url=source_base_url,
    )


def release_case_inputs_v2() -> tuple[CaseInputV2, ...]:
    """Return all release inputs in the exact frozen oracle order."""

    inputs = [
        CaseInputV2(
            name=name,
            fixture_id=f"canonical_{scenario}",
            materialize=partial(_materialize_canonical, scenario),
            source_scenario=scenario,
            mapper_fault=(
                "disagreement" if name in {"mapper_disagreement_only", "compound"} else None
            ),
            fault_candidate=(
                "AP-005" if name in {"mapper_disagreement_only", "compound"} else None
            ),
            fault_claim=("ap_years" if name in {"mapper_disagreement_only", "compound"} else None),
        )
        for name, scenario in _CANONICAL_CASES
    ]
    inputs.extend(
        (
            CaseInputV2(
                name="unseen_clean",
                fixture_id="unseen_clean_c8ad5fd4",
                materialize=partial(_materialize_unseen, UnseenScenario.CLEAN),
            ),
            CaseInputV2(
                name="unseen_structured_note_directive",
                fixture_id="unseen_directive_c8ad5fd4",
                materialize=partial(
                    _materialize_unseen,
                    UnseenScenario.STRUCTURED_NOTE_DIRECTIVE,
                ),
            ),
            CaseInputV2(
                name="unseen_semantic_conflict",
                fixture_id="unseen_conflict_c8ad5fd4",
                materialize=partial(
                    _materialize_unseen,
                    UnseenScenario.SEMANTIC_CONFLICT,
                ),
            ),
        )
    )
    if len(inputs) != 25 or len({item.name for item in inputs}) != 25:
        raise RuntimeError("the deterministic V2 release registry is incomplete")
    return tuple(inputs)
