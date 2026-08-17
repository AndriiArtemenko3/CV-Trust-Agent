"""Enforce coverage for the trusted workflow, release, and validation core."""

from __future__ import annotations

import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CoverageTargetResult:
    path_suffix: str
    percent_covered: float | None
    passed: bool


DEFAULT_TARGETS: tuple[str, ...] = (
    "src/cv_trust_agent/workflow.py",
    "src/cv_trust_agent/policy.py",
    "src/cv_trust_agent/evidence_validation.py",
    "src/cv_trust_agent/release.py",
    "src/cv_trust_agent/engine.py",
    "src/cv_trust_agent/mapper_wire.py",
    "evaluation/release_spec_v2.py",
    "evaluation/deterministic_release_v2.py",
    "evaluation/secure_release_v2.py",
    "evaluation/naive_release_v2.py",
    "evaluation/aggregate_v2.py",
    "evaluation/release_spec_v22.py",
    "evaluation/deterministic_release_v22.py",
    "evaluation/secure_release_v22.py",
    "evaluation/naive_release_v22.py",
    "evaluation/aggregate_v22.py",
    "evaluation/slot_ledger_v22.py",
    "evaluation/property_gate_runner.py",
)
MINIMUM_PERCENT = 90.0


def evaluate_coverage(
    report: Mapping[str, object],
    *,
    targets: Sequence[str] = DEFAULT_TARGETS,
    minimum_percent: float = MINIMUM_PERCENT,
) -> tuple[CoverageTargetResult, ...]:
    """Read pytest-cov's JSON summary without weakening missing-file failures."""

    files = report.get("files")
    if not isinstance(files, dict):
        raise ValueError("coverage report does not contain a files object")
    results: list[CoverageTargetResult] = []
    for suffix in targets:
        matches = [
            item
            for path, item in files.items()
            if isinstance(path, str) and path.replace("\\", "/").endswith(suffix)
        ]
        percent: float | None = None
        if len(matches) == 1 and isinstance(matches[0], dict):
            summary = matches[0].get("summary")
            if isinstance(summary, dict):
                value = summary.get("percent_covered")
                if isinstance(value, int | float) and not isinstance(value, bool):
                    percent = float(value)
        results.append(
            CoverageTargetResult(
                path_suffix=suffix,
                percent_covered=percent,
                passed=percent is not None and percent >= minimum_percent,
            )
        )
    return tuple(results)


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python -m evaluation.coverage_gate COVERAGE_JSON")
    path = Path(sys.argv[1])
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise SystemExit("coverage report root must be an object")
    results = evaluate_coverage(raw)
    passed = all(item.passed for item in results)
    print(
        json.dumps(
            {
                "passed": passed,
                "minimum_percent": MINIMUM_PERCENT,
                "targets": [
                    {
                        "path": item.path_suffix,
                        "percent_covered": item.percent_covered,
                        "passed": item.passed,
                    }
                    for item in results
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
