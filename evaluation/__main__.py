"""Command-line entry point for the repository-only evaluation package."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cv_trust_agent.mappers import DEFAULT_OPENAI_MODEL
from evaluation.aggregate_v2 import (
    canonical_oracle_paths_v2,
    execute_property_gate_families_v2,
    validate_aggregate_v2,
    write_release_manifest_v2,
)
from evaluation.aggregate_v22 import (
    AggregateV22Error,
    canonical_oracle_paths_v22,
    execute_property_gate_families_v22,
    validate_aggregate_v22,
    write_release_manifest_v22,
)
from evaluation.capture_environment_v2 import (
    CaptureEnvironmentV2Error,
    validate_capture_environment_v2,
)
from evaluation.capture_v2 import (
    PublicCommandCaptureV2,
    capture_deterministic_cases_v2,
    capture_secure_live_v2,
    write_deterministic_observations_v2,
)
from evaluation.capture_v22 import (
    PublicCommandCaptureV22,
    capture_deterministic_cases_v22,
    capture_secure_live_v22,
    write_deterministic_observations_v22,
)
from evaluation.core import PublicCommandRunner, evaluate_cases, load_oracle
from evaluation.deterministic_release_v2 import (
    RELEASE_ARTIFACT_INVARIANT_COUNT_V2,
    RELEASE_PROPERTY_GATE_COUNT_V2,
    RELEASE_TOTAL_GATE_COUNT_V2,
    validate_deterministic_release_v2,
)
from evaluation.deterministic_release_v22 import (
    RELEASE_ARTIFACT_INVARIANT_COUNT_V22,
    RELEASE_PROPERTY_GATE_COUNT_V22,
    RELEASE_TOTAL_GATE_COUNT_V22,
    validate_deterministic_release_v22,
)
from evaluation.evidence import (
    write_aggregate_evidence_manifest,
    write_deterministic_evidence_bundle,
)
from evaluation.heldout import score_heldout_results, validate_heldout_corpus
from evaluation.live import (
    run_all_live_evidence,
    run_canonical_live_evidence,
    run_heldout_live_evidence,
)
from evaluation.oracle_spec_v2 import load_deterministic_oracle_v2
from evaluation.oracle_spec_v22 import load_deterministic_oracle_v22
from evaluation.protocol_v22 import FROZEN_RUN_ID_V22
from evaluation.release_cases_v2 import release_case_inputs_v2
from evaluation.release_spec_v2 import (
    implementation_tree_sha256_v2,
    release_implementation_paths_v2,
)
from evaluation.results import render_release_results
from evaluation.results_v2 import render_release_results_v2
from evaluation.results_v22 import render_release_results_v22


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("showcase", "full"):
        command = subparsers.add_parser(name)
        command.add_argument("--cv-trust-bin", default="cv-trust")
        command.add_argument("--oracle", type=Path, default=None)
        command.add_argument("--evidence-dir", type=Path, default=None)
    heldout = subparsers.add_parser("heldout")
    heldout.add_argument("--results", type=Path, required=True)
    heldout.add_argument("--oracle", type=Path, default=None)
    heldout_validate = subparsers.add_parser("heldout-validate")
    heldout_validate.add_argument("--repository-root", type=Path, default=Path("."))
    heldout_validate.add_argument("--oracle", type=Path, default=None)
    live_canonical = subparsers.add_parser("live-canonical")
    live_canonical.add_argument("--execute-live-api", action="store_true")
    live_canonical.add_argument("--output", type=Path, required=True)
    live_canonical.add_argument("--repository-root", type=Path, default=Path("."))
    live_canonical.add_argument("--cv-trust-bin", default="cv-trust")
    live_heldout = subparsers.add_parser("live-heldout")
    live_heldout.add_argument("--execute-live-api", action="store_true")
    live_heldout.add_argument("--output", type=Path, required=True)
    live_heldout.add_argument("--repository-root", type=Path, default=Path("."))
    live_heldout.add_argument("--model", default=None)
    live_all = subparsers.add_parser("live-all")
    live_all.add_argument("--execute-live-api", action="store_true")
    live_all.add_argument("--output", type=Path, required=True)
    live_all.add_argument("--repository-root", type=Path, default=Path("."))
    live_all.add_argument("--cv-trust-bin", default="cv-trust")
    live_all.add_argument("--heldout-model", default=None)
    aggregate = subparsers.add_parser("aggregate-manifest")
    aggregate.add_argument("--output", type=Path, required=True)
    aggregate.add_argument("--deterministic-manifest", type=Path, required=True)
    aggregate.add_argument("--naive-artifact", type=Path, required=True)
    aggregate.add_argument(
        "--live-manifest",
        type=Path,
        required=True,
        help="Pass the one combined secure-smokes.manifest.json live-all sidecar.",
    )
    aggregate.add_argument("--repository-root", type=Path, default=Path("."))
    render_results = subparsers.add_parser("render-results")
    render_results.add_argument("--evidence-dir", type=Path, default=Path("evidence"))
    render_results.add_argument("--output", type=Path, default=None)
    v2_deterministic = subparsers.add_parser(
        "v2-deterministic",
        help="capture and independently validate the no-paid V2 deterministic release gate",
    )
    v2_deterministic.add_argument("--cv-trust-bin", default="cv-trust")
    v2_deterministic.add_argument(
        "--output",
        type=Path,
        required=True,
        help="new target named deterministic-v2.json; existing files are never overwritten",
    )
    v2_deterministic.add_argument("--repository-root", type=Path, default=Path("."))
    v2_secure = subparsers.add_parser(
        "v2-secure",
        help="capture the exact 12-attempt secure V2 protocol without deriving verdicts",
    )
    v2_secure.add_argument(
        "--execute-live-api",
        action="store_true",
        help="explicitly authorize the frozen 12-attempt paid provider protocol",
    )
    v2_secure.add_argument(
        "--output",
        type=Path,
        required=True,
        help="new target named secure-v2.jsonl; existing files are never overwritten",
    )
    v2_secure.add_argument("--repository-root", type=Path, default=Path("."))
    v2_secure.add_argument("--cv-trust-bin", default="cv-trust")
    v2_secure.add_argument("--canonical-model", default=DEFAULT_OPENAI_MODEL)
    v2_secure.add_argument("--heldout-model", default=DEFAULT_OPENAI_MODEL)
    v2_manifest = subparsers.add_parser(
        "v2-manifest",
        help="commit three already-captured V2 artifacts after semantic validation",
    )
    _add_v2_release_arguments(v2_manifest)
    v2_validate = subparsers.add_parser(
        "v2-validate",
        help="revalidate a complete V2 release and its current implementation tree",
    )
    _add_v2_release_arguments(v2_validate)
    v2_results = subparsers.add_parser(
        "v2-results",
        help="render results only from a complete semantically valid V2 release",
    )
    _add_v2_release_arguments(v2_results)
    v2_results.add_argument("--output", type=Path, default=None)
    v22_deterministic = subparsers.add_parser(
        "v22-deterministic",
        help="capture and independently validate the no-paid V2.2 deterministic release gate",
    )
    v22_deterministic.add_argument("--cv-trust-bin", default="cv-trust")
    v22_deterministic.add_argument(
        "--output",
        type=Path,
        required=True,
        help="new target named deterministic-v22.json; existing files are never overwritten",
    )
    v22_deterministic.add_argument("--repository-root", type=Path, default=Path("."))
    v22_secure = subparsers.add_parser(
        "v22-secure",
        help="capture the exact 12-attempt secure V2.2 protocol without deriving verdicts",
    )
    v22_secure.add_argument(
        "--execute-live-api",
        action="store_true",
        help="explicitly authorize the frozen 12-attempt paid provider protocol",
    )
    v22_secure.add_argument(
        "--output",
        type=Path,
        required=True,
        help="new target named secure-v22.jsonl; existing files are never overwritten",
    )
    v22_secure.add_argument(
        "--slot-ledger",
        type=Path,
        required=True,
        help="exact new secure-slots-v22.jsonl beside the attempt artifact",
    )
    v22_secure.add_argument("--repository-root", type=Path, default=Path("."))
    v22_secure.add_argument("--cv-trust-bin", default="cv-trust")
    v22_secure.add_argument("--canonical-model", default=DEFAULT_OPENAI_MODEL)
    v22_secure.add_argument("--heldout-model", default=DEFAULT_OPENAI_MODEL)
    v22_manifest = subparsers.add_parser(
        "v22-manifest",
        help="commit three already-captured V2.2 artifacts after semantic validation",
    )
    _add_v22_release_arguments(v22_manifest)
    v22_validate = subparsers.add_parser(
        "v22-validate",
        help="revalidate a complete V2.2 release; fails closed unless release_green",
    )
    _add_v22_release_arguments(v22_validate)
    v22_results = subparsers.add_parser(
        "v22-results",
        help="render results only from a release-green semantically valid V2.2 release",
    )
    _add_v22_release_arguments(v22_results)
    v22_results.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    if args.command == "v22-secure":
        if not args.execute_live_api:
            parser.error("v22-secure requires explicit --execute-live-api authorization")
        if args.output.name != "secure-v22.jsonl":
            parser.error("v22-secure output must be named secure-v22.jsonl")
        root = args.repository_root.resolve()
        implementation_paths = release_implementation_paths_v2(root)
        output_target = args.output.resolve()
        slot_ledger_target = args.slot_ledger.resolve()
        if _target_is_in_implementation_tree(output_target, implementation_paths):
            parser.error("V2.2 capture output cannot be inside the hashed implementation tree")
        if _target_is_in_implementation_tree(slot_ledger_target, implementation_paths):
            parser.error("V2.2 slot ledger cannot be inside the hashed implementation tree")
        if (
            slot_ledger_target.name != "secure-slots-v22.jsonl"
            or slot_ledger_target.parent != output_target.parent
            or output_target.parent.name != FROZEN_RUN_ID_V22
        ):
            parser.error("V2.2 secure artifacts must share the exact frozen run directory")
        _require_v2_capture_environment(parser, root, args.cv_trust_bin)
        _, heldout_oracle = canonical_oracle_paths_v22(root)
        tree_before = implementation_tree_sha256_v2(
            implementation_paths,
            repository_root=root,
        )
        captured_v22 = capture_secure_live_v22(
            output_target,
            execute_live_api=True,
            repository_root=root,
            slot_ledger_path=slot_ledger_target,
            executable=args.cv_trust_bin,
            canonical_model=args.canonical_model,
            heldout_model=args.heldout_model,
            heldout_oracle_path=heldout_oracle,
        )
        tree_after = implementation_tree_sha256_v2(
            implementation_paths,
            repository_root=root,
        )
        if tree_after != tree_before or captured_v22.implementation_tree_sha256 != tree_before:
            raise RuntimeError("implementation tree changed during secure V2.2 capture")
        print(
            json.dumps(
                {
                    "status": "captured_unvalidated",
                    "artifact_path": _v2_output_label(captured_v22.artifact_path, root),
                    "slot_ledger_path": _v2_output_label(captured_v22.slot_ledger_path, root),
                    "attempt_count": captured_v22.attempt_count,
                    "implementation_tree_sha256": captured_v22.implementation_tree_sha256,
                    "final_chain_sha256": captured_v22.final_chain_sha256,
                    "producer_verdicts": 0,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return

    if args.command == "v22-deterministic":
        if args.output.name != "deterministic-v22.json":
            parser.error("v22-deterministic output must be named deterministic-v22.json")
        root = args.repository_root.resolve()
        _require_v2_capture_environment(parser, root, args.cv_trust_bin)
        implementation_paths = release_implementation_paths_v2(root)
        output_target = args.output.resolve()
        if output_target.parent.name != FROZEN_RUN_ID_V22:
            parser.error("V2.2 deterministic output must use the frozen run directory")
        if _target_is_in_implementation_tree(output_target, implementation_paths):
            parser.error("V2.2 capture output cannot be inside the hashed implementation tree")
        oracle_path, _ = canonical_oracle_paths_v22(root)
        deterministic_oracle_v22 = load_deterministic_oracle_v22(oracle_path)
        cases = release_case_inputs_v2()
        registered = tuple((case.name, case.fixture_id) for case in cases)
        expected = tuple((case.name, case.fixture_id) for case in deterministic_oracle_v22.cases)
        if registered != expected:
            raise RuntimeError("V2.2 capture registry differs from the frozen oracle")

        tree_before = implementation_tree_sha256_v2(
            implementation_paths,
            repository_root=root,
        )
        observations_v22 = capture_deterministic_cases_v22(
            cases,
            PublicCommandCaptureV22(executable=args.cv_trust_bin),
        )
        tree_after = implementation_tree_sha256_v2(
            implementation_paths,
            repository_root=root,
        )
        if tree_after != tree_before:
            raise RuntimeError("implementation tree changed during V2.2 capture")
        artifact = write_deterministic_observations_v22(
            output_target,
            observations=observations_v22,
            oracle=deterministic_oracle_v22,
            implementation_tree_sha256=tree_before,
        )
        deterministic_release_v22 = validate_deterministic_release_v22(artifact, oracle_path)
        property_report_v22 = execute_property_gate_families_v22(root)
        tree_at_release = implementation_tree_sha256_v2(
            implementation_paths,
            repository_root=root,
        )
        if tree_at_release != tree_before:
            raise RuntimeError("implementation tree changed during V2.2 release gates")
        if (
            deterministic_release_v22.case_count != len(cases)
            or deterministic_release_v22.artifact_invariant_count
            != RELEASE_ARTIFACT_INVARIANT_COUNT_V22
            or property_report_v22.property_gate_count != RELEASE_PROPERTY_GATE_COUNT_V22
            or property_report_v22.total_release_gate_count != RELEASE_TOTAL_GATE_COUNT_V22
        ):
            raise RuntimeError("V2.2 deterministic release-gate accounting is incomplete")
        print(
            json.dumps(
                {
                    "status": "valid",
                    "artifact_path": _v2_output_label(artifact, root),
                    "case_count": deterministic_release_v22.case_count,
                    "artifact_invariant_count": (
                        deterministic_release_v22.artifact_invariant_count
                    ),
                    "property_gate_count": property_report_v22.property_gate_count,
                    "property_gate_names": property_report_v22.names,
                    "total_release_gate_count": RELEASE_TOTAL_GATE_COUNT_V22,
                    "implementation_tree_sha256": tree_before,
                    "paid_api_calls": 0,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return

    if args.command in {"v22-manifest", "v22-validate", "v22-results"}:
        root = args.repository_root.resolve()
        evidence_directory = args.evidence_dir.resolve()
        deterministic_oracle, heldout_oracle = canonical_oracle_paths_v22(root)
        if args.command == "v22-manifest":
            manifest = write_release_manifest_v22(
                evidence_directory,
                run_id=FROZEN_RUN_ID_V22,
                deterministic_oracle_path=deterministic_oracle,
                heldout_oracle_path=heldout_oracle,
                repository_root=root,
            )
            print(
                json.dumps(
                    {"manifest_path": _v2_output_label(manifest, root)},
                    indent=2,
                    sort_keys=True,
                )
            )
            return
        if args.command == "v22-validate":
            # Integrity checks still fail closed inside the validator; only the
            # final release_green summary is reported instead of raised, so a
            # red run prints its per-gate breakdown and exits non-zero.
            aggregate_release_v22 = validate_aggregate_v22(
                evidence_directory / "manifest-v22.json",
                deterministic_oracle_path=deterministic_oracle,
                heldout_oracle_path=heldout_oracle,
                repository_root=root,
                require_release_green=False,
            )
            secure_v22 = aggregate_release_v22.secure
            naive_v22 = aggregate_release_v22.naive
            print(
                json.dumps(
                    {
                        "status": ("valid" if aggregate_release_v22.release_green else "red"),
                        "release_green": aggregate_release_v22.release_green,
                        "integrity_valid": aggregate_release_v22.integrity_valid,
                        "run_id": aggregate_release_v22.run_id,
                        "provider_slot_count": aggregate_release_v22.provider_slot_count,
                        "manifest_sha256": aggregate_release_v22.manifest_sha256,
                        "case_count": aggregate_release_v22.deterministic.case_count,
                        "artifact_invariant_count": (
                            aggregate_release_v22.artifact_invariant_count
                        ),
                        "property_gate_count": aggregate_release_v22.property_gate_count,
                        "property_gate_names": aggregate_release_v22.property_gate_names,
                        "total_release_gate_count": (
                            aggregate_release_v22.total_release_gate_count
                        ),
                        "secure_canonical_gate_passed": secure_v22.canonical_gate_passed,
                        "secure_prose_gate_passed": secure_v22.prose_gate_passed,
                        "secure_safety_passed": secure_v22.safety_passed,
                        "secure_hard_gate_passed": secure_v22.hard_gate_passed,
                        "unsupported_claim_count": secure_v22.unsupported_claim_count,
                        "promotion_count": secure_v22.promotion_count,
                        "clean_utility_run_count": secure_v22.clean_utility_run_count,
                        "candidate_exact_clean_counts": dict(
                            sorted(secure_v22.candidate_exact_clean_counts)
                        ),
                        "heldout_noninterference_pair_count": (
                            secure_v22.heldout_noninterference_pair_count
                        ),
                        "naive_hard_gate_passed": naive_v22.hard_gate_passed,
                        "naive_evaluable_block_count": naive_v22.evaluable_block_count,
                        "naive_positive_d_block_count": naive_v22.positive_d_block_count,
                        "secure_ledger_completed_count": (
                            aggregate_release_v22.secure_ledger.completed_count
                        ),
                        "secure_ledger_failed_count": (
                            aggregate_release_v22.secure_ledger.failed_count
                        ),
                        "secure_ledger_unobserved_count": (
                            aggregate_release_v22.secure_ledger.unobserved_count
                        ),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            if not aggregate_release_v22.release_green:
                raise SystemExit(1)
            return
        markdown = render_release_results_v22(
            evidence_directory,
            repository_root=root,
            deterministic_oracle_path=deterministic_oracle,
            heldout_oracle_path=heldout_oracle,
        )
        if args.output is None:
            print(markdown, end="")
        else:
            target = args.output.resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(markdown, encoding="utf-8")
            print(
                json.dumps(
                    {"results_path": _v2_output_label(target, root)},
                    indent=2,
                    sort_keys=True,
                )
            )
        return

    if args.command == "v2-secure":
        if not args.execute_live_api:
            parser.error("v2-secure requires explicit --execute-live-api authorization")
        if args.output.name != "secure-v2.jsonl":
            parser.error("v2-secure output must be named secure-v2.jsonl")
        root = args.repository_root.resolve()
        implementation_paths = release_implementation_paths_v2(root)
        output_target = args.output.resolve()
        if _target_is_in_implementation_tree(output_target, implementation_paths):
            parser.error("V2 capture output cannot be inside the hashed implementation tree")
        _require_v2_capture_environment(parser, root, args.cv_trust_bin)
        _, heldout_oracle = canonical_oracle_paths_v2(root)
        tree_before = implementation_tree_sha256_v2(
            implementation_paths,
            repository_root=root,
        )
        captured = capture_secure_live_v2(
            output_target,
            execute_live_api=True,
            repository_root=root,
            executable=args.cv_trust_bin,
            canonical_model=args.canonical_model,
            heldout_model=args.heldout_model,
            heldout_oracle_path=heldout_oracle,
        )
        tree_after = implementation_tree_sha256_v2(
            implementation_paths,
            repository_root=root,
        )
        if tree_after != tree_before or captured.implementation_tree_sha256 != tree_before:
            raise RuntimeError("implementation tree changed during secure V2 capture")
        print(
            json.dumps(
                {
                    "status": "captured_unvalidated",
                    "artifact_path": _v2_output_label(captured.artifact_path, root),
                    "attempt_count": captured.attempt_count,
                    "implementation_tree_sha256": captured.implementation_tree_sha256,
                    "producer_verdicts": 0,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return

    if args.command == "v2-deterministic":
        if args.output.name != "deterministic-v2.json":
            parser.error("v2-deterministic output must be named deterministic-v2.json")
        root = args.repository_root.resolve()
        _require_v2_capture_environment(parser, root, args.cv_trust_bin)
        implementation_paths = release_implementation_paths_v2(root)
        output_target = args.output.resolve()
        if _target_is_in_implementation_tree(output_target, implementation_paths):
            parser.error("V2 capture output cannot be inside the hashed implementation tree")
        oracle_path, _ = canonical_oracle_paths_v2(root)
        deterministic_oracle_v2 = load_deterministic_oracle_v2(oracle_path)
        cases = release_case_inputs_v2()
        registered = tuple((case.name, case.fixture_id) for case in cases)
        expected = tuple((case.name, case.fixture_id) for case in deterministic_oracle_v2.cases)
        if registered != expected:
            raise RuntimeError("V2 capture registry differs from the frozen oracle")

        tree_before = implementation_tree_sha256_v2(
            implementation_paths,
            repository_root=root,
        )
        observations = capture_deterministic_cases_v2(
            cases,
            PublicCommandCaptureV2(executable=args.cv_trust_bin),
        )
        tree_after = implementation_tree_sha256_v2(
            implementation_paths,
            repository_root=root,
        )
        if tree_after != tree_before:
            raise RuntimeError("implementation tree changed during V2 capture")
        artifact = write_deterministic_observations_v2(
            output_target,
            observations=observations,
            oracle=deterministic_oracle_v2,
            implementation_tree_sha256=tree_before,
        )
        deterministic_release = validate_deterministic_release_v2(artifact, oracle_path)
        property_report = execute_property_gate_families_v2(root)
        tree_at_release = implementation_tree_sha256_v2(
            implementation_paths,
            repository_root=root,
        )
        if tree_at_release != tree_before:
            raise RuntimeError("implementation tree changed during V2 release gates")
        if (
            deterministic_release.case_count != len(cases)
            or deterministic_release.artifact_invariant_count != RELEASE_ARTIFACT_INVARIANT_COUNT_V2
            or property_report.property_gate_count != RELEASE_PROPERTY_GATE_COUNT_V2
            or property_report.total_release_gate_count != RELEASE_TOTAL_GATE_COUNT_V2
        ):
            raise RuntimeError("V2 deterministic release-gate accounting is incomplete")
        print(
            json.dumps(
                {
                    "status": "valid",
                    "artifact_path": _v2_output_label(artifact, root),
                    "case_count": deterministic_release.case_count,
                    "artifact_invariant_count": deterministic_release.artifact_invariant_count,
                    "property_gate_count": property_report.property_gate_count,
                    "property_gate_names": property_report.names,
                    "total_release_gate_count": RELEASE_TOTAL_GATE_COUNT_V2,
                    "implementation_tree_sha256": tree_before,
                    "paid_api_calls": 0,
                },
                indent=2,
                sort_keys=True,
            )
        )
        return

    if args.command in {"v2-manifest", "v2-validate", "v2-results"}:
        root = args.repository_root.resolve()
        evidence_directory = args.evidence_dir.resolve()
        deterministic_oracle, heldout_oracle = canonical_oracle_paths_v2(root)
        if args.command == "v2-manifest":
            manifest = write_release_manifest_v2(
                evidence_directory,
                deterministic_oracle_path=deterministic_oracle,
                heldout_oracle_path=heldout_oracle,
                repository_root=root,
            )
            print(
                json.dumps(
                    {"manifest_path": _v2_output_label(manifest, root)},
                    indent=2,
                    sort_keys=True,
                )
            )
            return
        if args.command == "v2-validate":
            aggregate_release = validate_aggregate_v2(
                evidence_directory / "manifest-v2.json",
                deterministic_oracle_path=deterministic_oracle,
                heldout_oracle_path=heldout_oracle,
                repository_root=root,
            )
            print(
                json.dumps(
                    {
                        "status": "valid",
                        "manifest_sha256": aggregate_release.manifest_sha256,
                        "case_count": aggregate_release.deterministic.case_count,
                        "artifact_invariant_count": aggregate_release.artifact_invariant_count,
                        "property_gate_count": aggregate_release.property_gate_count,
                        "property_gate_names": aggregate_release.property_gate_names,
                        "total_release_gate_count": aggregate_release.total_release_gate_count,
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return
        markdown = render_release_results_v2(
            evidence_directory,
            repository_root=root,
            deterministic_oracle_path=deterministic_oracle,
            heldout_oracle_path=heldout_oracle,
        )
        if args.output is None:
            print(markdown, end="")
        else:
            target = args.output.resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(markdown, encoding="utf-8")
            print(
                json.dumps(
                    {"results_path": _v2_output_label(target, root)},
                    indent=2,
                    sort_keys=True,
                )
            )
        return

    if args.command == "render-results":
        markdown = render_release_results(args.evidence_dir)
        if args.output is None:
            print(markdown, end="")
        else:
            target = args.output.resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(markdown, encoding="utf-8")
            print(json.dumps({"results_path": target.as_posix()}, indent=2, sort_keys=True))
        return

    if args.command == "aggregate-manifest":
        root = args.repository_root.resolve()
        aggregate_command = (
            "python",
            "-m",
            "evaluation",
            "aggregate-manifest",
            "--output",
            _public_repo_path(args.output, root),
            "--deterministic-manifest",
            _public_repo_path(args.deterministic_manifest, root),
            "--naive-artifact",
            _public_repo_path(args.naive_artifact, root),
            "--live-manifest",
            _public_repo_path(args.live_manifest, root),
            "--repository-root",
            ".",
        )
        aggregate_output = write_aggregate_evidence_manifest(
            args.output,
            deterministic_manifest=args.deterministic_manifest,
            naive_artifact=args.naive_artifact,
            live_manifests=(args.live_manifest,),
            command=aggregate_command,
            implementation_paths=(
                root / "src",
                root / "evaluation",
                root / "experiments",
                root / "pyproject.toml",
                root / "uv.lock",
            ),
        )
        print(
            json.dumps(
                {"manifest_path": aggregate_output.as_posix()},
                indent=2,
                sort_keys=True,
            )
        )
        return

    if args.command == "live-all":
        kwargs = {
            "execute_live_api": args.execute_live_api,
            "repository_root": args.repository_root,
            "executable": args.cv_trust_bin,
        }
        if args.heldout_model is not None:
            kwargs["heldout_model"] = args.heldout_model
        summary = run_all_live_evidence(args.output, **kwargs)
        print(json.dumps(_live_summary_json(summary), indent=2, sort_keys=True))
        if not summary.hard_gate_passed:
            raise SystemExit(1)
        return

    if args.command == "live-canonical":
        summary = run_canonical_live_evidence(
            args.output,
            execute_live_api=args.execute_live_api,
            repository_root=args.repository_root,
            executable=args.cv_trust_bin,
        )
        print(json.dumps(_live_summary_json(summary), indent=2, sort_keys=True))
        if not summary.hard_gate_passed:
            raise SystemExit(1)
        return

    if args.command == "live-heldout":
        kwargs = {
            "execute_live_api": args.execute_live_api,
            "repository_root": args.repository_root,
        }
        if args.model is not None:
            kwargs["model"] = args.model
        summary = run_heldout_live_evidence(args.output, **kwargs)
        print(json.dumps(_live_summary_json(summary), indent=2, sort_keys=True))
        if not summary.hard_gate_passed:
            raise SystemExit(1)
        return

    if args.command == "heldout-validate":
        validation = validate_heldout_corpus(
            args.repository_root,
            oracle_path=args.oracle,
        )
        print(
            json.dumps(
                {
                    "status": "valid",
                    "candidate_count": validation.candidate_count,
                    "pdf_count": validation.pdf_count,
                    "page_count": validation.page_count,
                    "annotation_count": validation.annotation_count,
                    "layout_count": validation.layout_count,
                    "directive_target": validation.directive_target,
                    "changed_candidate_ids": validation.changed_candidate_ids,
                    "regenerated_bytes_match": validation.regenerated_bytes_match,
                    "live_status": "unexecuted",
                },
                indent=2,
                sort_keys=True,
            )
        )
        return

    if args.command == "heldout":
        raw = json.loads(args.results.read_text(encoding="utf-8"))
        if not isinstance(raw, list) or any(not isinstance(item, dict) for item in raw):
            parser.error("--results must contain a JSON array of objects")
        score = score_heldout_results(raw, oracle_path=args.oracle)
        heldout_output = {
            "passed_safety": score.passed_safety,
            "met_utility_observation": score.met_utility_observation,
            "candidate_checks": dict(sorted(score.candidate_checks.items())),
        }
        print(json.dumps(heldout_output, indent=2, sort_keys=True))
        raise SystemExit(0 if score.passed_safety else 1)

    v1_oracle = load_oracle(args.oracle)
    runner = PublicCommandRunner(executable=args.cv_trust_bin)
    report = evaluate_cases(v1_oracle, runner, showcase_only=args.command == "showcase")
    report_output = report.public_json()
    if args.evidence_dir is not None:
        root = Path.cwd().resolve()
        paths = (
            root / "src",
            root / "evaluation",
            root / "experiments",
            root / "pyproject.toml",
            root / "uv.lock",
        )
        oracle_path = (args.oracle or root / "evaluation" / "oracle.json").resolve()
        evidence_command = (
            "python",
            "-m",
            "evaluation",
            args.command,
            "--cv-trust-bin",
            _public_executable(args.cv_trust_bin),
            "--oracle",
            _public_repo_path(oracle_path, root),
            "--evidence-dir",
            _public_repo_path(args.evidence_dir, root),
        )
        deterministic_summary, manifest = write_deterministic_evidence_bundle(
            args.evidence_dir,
            report,
            command=evidence_command,
            implementation_paths=paths,
            fixture_paths=(root / "fixtures" / "generated",),
        )
        report_output["evidence_files"] = [
            deterministic_summary.as_posix(),
            manifest.as_posix(),
        ]
    print(json.dumps(report_output, indent=2, sort_keys=True))
    raise SystemExit(0 if report.passed else 1)


def _live_summary_json(summary: object) -> dict[str, object]:
    from evaluation.live import LiveEvidenceSummary

    if not isinstance(summary, LiveEvidenceSummary):
        raise TypeError("live runner returned an invalid summary")
    return {
        "artifact_path": summary.artifact_path.as_posix(),
        "manifest_path": summary.manifest_path.as_posix(),
        "planned_run_count": summary.planned_run_count,
        "completed_run_count": summary.completed_run_count,
        "successful_run_count": summary.successful_run_count,
        "pair_count": summary.pair_count,
        "passed_pair_count": summary.passed_pair_count,
        "hard_gate_passed": summary.hard_gate_passed,
        "utility_observation_passed": summary.utility_observation_passed,
    }


def _add_v2_release_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--evidence-dir", type=Path, default=Path("evidence/v2"))
    parser.add_argument("--repository-root", type=Path, default=Path("."))


def _add_v22_release_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        default=Path("evidence/v2.2") / FROZEN_RUN_ID_V22,
    )
    parser.add_argument("--repository-root", type=Path, default=Path("."))


def _require_v2_capture_environment(
    parser: argparse.ArgumentParser,
    repository_root: Path,
    executable: str,
) -> None:
    if not executable or Path(executable).is_absolute() or "/" in executable or "\\" in executable:
        parser.error("V2 capture executable must be a PATH command name")
    try:
        validate_capture_environment_v2(repository_root, executable)
    except CaptureEnvironmentV2Error as exc:
        parser.error(str(exc))


def _target_is_in_implementation_tree(target: Path, implementation_paths: tuple[Path, ...]) -> bool:
    resolved_target = target.resolve()
    for selected in implementation_paths:
        resolved = selected.resolve()
        if resolved.is_dir() and (
            resolved_target == resolved or resolved in resolved_target.parents
        ):
            return True
        if not resolved.is_dir() and resolved_target == resolved:
            return True
    return False


def _v2_output_label(path: Path, repository_root: Path) -> str:
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(repository_root.resolve())
    except ValueError:
        return resolved.name
    if relative == Path(".") or ".." in relative.parts:
        return resolved.name
    return relative.as_posix()


def _public_repo_path(path: Path, repository_root: Path) -> str:
    resolved = path.resolve()
    root = repository_root.resolve()
    try:
        relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("public evidence paths must be repository-relative") from exc
    if relative == Path(".") or ".." in relative.parts:
        raise ValueError("public evidence path is invalid")
    return relative.as_posix()


def _public_executable(value: str) -> str:
    if not value or Path(value).is_absolute() or "/" in value or "\\" in value:
        raise ValueError("public cv-trust executable must be a PATH command name")
    return value


def _entrypoint() -> None:
    """Keep untrusted V2 failures out of the public terminal boundary."""

    try:
        main()
    except AggregateV22Error as exc:
        # Aggregate integrity messages are code-authored constants with no
        # untrusted interpolation, so surfacing them costs nothing and tells
        # the operator which frozen commitment failed.
        command = sys.argv[1] if len(sys.argv) > 1 else ""
        if command.startswith("v22-"):
            raise SystemExit(f"error: V2.2 operation failed: {exc}") from None
        raise
    except (OSError, RuntimeError, ValueError):
        command = sys.argv[1] if len(sys.argv) > 1 else ""
        if command.startswith("v22-"):
            raise SystemExit("error: V2.2 operation failed") from None
        if command.startswith("v2-"):
            raise SystemExit("error: V2 operation failed") from None
        raise


if __name__ == "__main__":
    _entrypoint()
