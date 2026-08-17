"""Render release results only after complete V2 semantic revalidation."""

from __future__ import annotations

from pathlib import Path

from evaluation.aggregate_v2 import validate_aggregate_v2


def render_release_results_v2(
    evidence_directory: Path,
    *,
    repository_root: Path,
    deterministic_oracle_path: Path,
    heldout_oracle_path: Path,
) -> str:
    """Recheck the current tree and render only validator-derived observations."""

    release = validate_aggregate_v2(
        evidence_directory / "manifest-v2.json",
        deterministic_oracle_path=deterministic_oracle_path,
        heldout_oracle_path=heldout_oracle_path,
        repository_root=repository_root,
    )
    secure = release.secure
    naive = release.naive
    return "\n".join(
        (
            "## Validated V2 evidence",
            "",
            "| Evidence | Derived result |",
            "|---|---|",
            (
                "| Deterministic suite | "
                f"{release.deterministic.case_count} cases; "
                f"{release.artifact_invariant_count} artifact invariants + "
                f"{release.property_gate_count} executed property-gate families = "
                f"{release.total_release_gate_count} release gates |"
            ),
            (
                "| Secure protocol completeness | "
                f"{secure.attempt_count}/12 attempts retained; "
                f"{'complete' if secure.protocol_complete else 'incomplete'} |"
            ),
            (
                "| Secure execution success | "
                f"{secure.execution_success_count}/12 attempts completed successfully |"
            ),
            (
                "| Secure safety | "
                f"{secure.unsupported_claim_count} unsupported claims; "
                f"{'passed' if secure.safety_passed else 'failed'} |"
            ),
            (f"| Secure hard gate | {'passed' if secure.hard_gate_passed else 'failed'} |"),
            (
                "| Secure canonical binding | "
                f"{secure.canonical_bound_count}/6 bound to deterministic clean |"
            ),
            (
                "| Secure canonical noninterference | "
                f"{secure.canonical_noninterference_pair_count}/"
                f"{secure.canonical_evaluable_pair_count} evaluable pairs invariant |"
            ),
            (
                "| Held-out mapper utility | "
                f"{secure.clean_utility_run_count}/3 clean runs met the utility observation |"
            ),
            (
                "| Held-out mapper noninterference | "
                f"{secure.heldout_noninterference_pair_count}/"
                f"{secure.heldout_evaluable_pair_count} evaluable pairs invariant |"
            ),
            (
                "| Naïve attack pairs | "
                f"{naive.attack.evaluable_pair_count}/8 evaluable; "
                f"{naive.attack.positive_rank_gain_count} positive rank gains; "
                f"{naive.attack.failed_attempt_count} failed attempts |"
            ),
            (
                "| Naïve clean controls | "
                f"{naive.clean_control.evaluable_pair_count}/8 evaluable; "
                f"{naive.clean_control.positive_rank_gain_count} positive rank gains; "
                f"{naive.clean_control.failed_attempt_count} failed attempts |"
            ),
            (
                "| Naïve protocol completeness | "
                f"{naive.attempt_count}/32 attempts across {naive.block_count}/8 blocks; "
                f"{'complete' if naive.protocol_complete else 'incomplete'} |"
            ),
            "",
            (
                "The held-out utility result is an observation, not a repaired fallback or a "
                "claim of general real-CV support."
            ),
            "",
        )
    )
