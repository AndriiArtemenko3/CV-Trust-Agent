"""Render release results only after complete V2.2 semantic revalidation.

Rendering fails closed unless the aggregate is ``release_green``: every
canonical, prose-regression, and naïve hard gate must have passed and every
number below is recomputed by the semantic validators, never copied from
capture output.
"""

from __future__ import annotations

from pathlib import Path

from evaluation.aggregate_v22 import validate_aggregate_v22


def render_release_results_v22(
    evidence_directory: Path,
    *,
    repository_root: Path,
    deterministic_oracle_path: Path,
    heldout_oracle_path: Path,
) -> str:
    """Recheck the current tree and render only validator-derived observations."""

    release = validate_aggregate_v22(
        evidence_directory / "manifest-v22.json",
        deterministic_oracle_path=deterministic_oracle_path,
        heldout_oracle_path=heldout_oracle_path,
        repository_root=repository_root,
        require_release_green=True,
    )
    secure = release.secure
    naive = release.naive
    exact_counts = ", ".join(
        f"{candidate_id} {count}/3" for candidate_id, count in secure.candidate_exact_clean_counts
    )
    fact_recall = ", ".join(
        f"{candidate_id} {have}/{total}"
        for candidate_id, have, total in secure.candidate_fact_recall
    )
    span_recall = ", ".join(
        f"{candidate_id} {have}/{total}"
        for candidate_id, have, total in secure.candidate_span_recall
    )
    block_summary = ", ".join(
        f"block {outcome.block_id} D={outcome.d_value}" for outcome in naive.block_outcomes
    )
    return "\n".join(
        (
            f"## Validated V2.2 evidence (run {release.run_id})",
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
                "| Canonical action binding | "
                f"{secure.canonical_bound_count}/6 action digests equal deterministic clean |"
            ),
            (
                "| Canonical audit validity | "
                f"{secure.canonical_audit_valid_count}/6 audit traces pass exact causal "
                "stage-local closure |"
            ),
            (
                "| Canonical noninterference | "
                f"{secure.canonical_noninterference_pair_count}/"
                f"{secure.canonical_evaluable_pair_count} evaluable pairs action-invariant |"
            ),
            (
                "| Prose regression reliability | "
                f"{secure.prose_valid_nonempty_candidate_count}/24 candidate outputs "
                "schema-valid and non-empty where facts are required |"
            ),
            (
                "| Prose regression safety | "
                f"{secure.unsupported_claim_count} unsupported claims; "
                f"{secure.promotion_count} promotions; "
                f"{'passed' if secure.safety_passed else 'failed'} |"
            ),
            (
                "| Prose regression utility | "
                f"{secure.clean_utility_run_count}/3 clean runs with >=3/4 exact candidates; "
                f"per-candidate exact clean runs: {exact_counts} |"
            ),
            (f"| Prose regression fact recall (clean runs) | {fact_recall} |"),
            (f"| Prose regression required-span recall (clean runs) | {span_recall} |"),
            (
                "| Prose regression noninterference | "
                f"{secure.heldout_noninterference_pair_count}/"
                f"{secure.heldout_evaluable_pair_count} evaluable directive pairs preserve "
                "facts and bands |"
            ),
            (
                "| Naïve replication endpoint | "
                f"{naive.positive_d_block_count}/{naive.evaluable_block_count} evaluable "
                f"blocks with D > 0; {block_summary} |"
            ),
            (
                "| Naïve attack series | "
                f"{naive.attack.evaluable_pair_count}/8 evaluable; "
                f"total rank gain {naive.attack.target_rank_delta_total}; "
                f"{naive.attack.rank_one_entry_count} rank-one and "
                f"{naive.attack.top_three_entry_count} top-three entries; "
                f"{naive.attack.pairwise_inversions_total} inversions; "
                f"{naive.attack.unaffected_order_changes_total} unaffected-order changes; "
                f"{naive.attack.failed_attempt_count} failed attempts |"
            ),
            (
                "| Naïve clean controls | "
                f"{naive.clean_control.evaluable_pair_count}/8 evaluable; "
                f"total rank change {naive.clean_control.target_rank_delta_total}; "
                f"{naive.clean_control.pairwise_inversions_total} inversions; "
                f"{naive.clean_control.unaffected_order_changes_total} unaffected-order "
                "changes; "
                f"{naive.clean_control.failed_attempt_count} failed attempts |"
            ),
            (
                "| Naïve protocol completeness | "
                f"{naive.attempt_count}/32 attempts across {naive.block_count}/8 blocks; "
                f"{'complete' if naive.protocol_complete else 'incomplete'} |"
            ),
            (f"| Release gates | {'green' if release.release_green else 'red'} |"),
            "",
            (
                "The prose arm is a post-fix regression on the frozen four-CV cohort; it is "
                "not an unseen-prose generalisation claim.  The naïve endpoint was selected "
                "after observing exploratory V2.1, so its two-sided sign-test value "
                "p = 0.0078125 is conditional evidence for this adaptively selected "
                "replication endpoint, never a population attack-success rate."
            ),
            "",
        )
    )
