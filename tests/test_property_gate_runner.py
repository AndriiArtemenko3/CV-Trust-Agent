"""Hostile regressions for the independently attested property subprocess."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import evaluation.aggregate_v22 as aggregate_v22
import evaluation.property_gate_runner as property_gate_runner
from evaluation.property_gate_runner import PropertyGateRunnerError

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PROPERTY_NODE_IDS = (
    "tests/test_unseen_generalization.py::"
    "test_unseen_property_safe_id_renaming_preserves_rank_semantics",
    "tests/test_unseen_generalization.py::"
    "test_unseen_property_input_permutation_is_fully_invariant",
)
FORBIDDEN_AMBIENT_KEYS = {
    "CI",
    "COVERAGE_PROCESS_CONFIG",
    "COVERAGE_PROCESS_START",
    "HYPOTHESIS_PROFILE",
    "PYTEST_ADDOPTS",
    "PYTEST_PLUGINS",
    "PYTHONHOME",
    "PYTHONSTARTUP",
}


def _fake_repository(tmp_path: Path) -> Path:
    repository_root = tmp_path / "repository"
    tests = repository_root / "tests"
    tests.mkdir(parents=True)
    (repository_root / "src").mkdir()
    (repository_root / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\naddopts = "-ra"\n',
        encoding="utf-8",
    )
    (tests / "test_unseen_generalization.py").write_text(
        "def placeholder():\n    pass\n",
        encoding="utf-8",
    )
    return repository_root


def _valid_report(nonce: str, node_ids: tuple[str, ...]) -> dict[str, object]:
    return {
        "collected_node_ids": list(node_ids),
        "collection_observed": True,
        "nonce": nonce,
        "phase_reports": [
            {
                "node_id": node_id,
                "outcome": "passed",
                "was_xfail": False,
                "when": phase,
            }
            for node_id in node_ids
            for phase in ("setup", "call", "teardown")
        ],
        "schema_version": 1,
        "session_exit_status": 0,
    }


def _signed_report(
    nonce: str,
    node_ids: tuple[str, ...],
    secret: bytes,
) -> dict[str, object]:
    report = _valid_report(nonce, node_ids)
    report["hmac_sha256"] = property_gate_runner._report_hmac(report, secret)
    return report


def _absolute_target(repository_root: Path, node_id: str) -> str:
    relative_file, separator, test_name = node_id.partition("::")
    return f"{repository_root / relative_file}{separator}{test_name}"


def test_controlled_runner_scrubs_ambient_pytest_and_plugin_injection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository_root = _fake_repository(tmp_path)
    for name in FORBIDDEN_AMBIENT_KEYS:
        monkeypatch.setenv(name, "attacker-controlled")

    def successful_run(command: tuple[str, ...], **kwargs: object) -> SimpleNamespace:
        environment = cast(dict[str, str], kwargs["env"])
        assert not FORBIDDEN_AMBIENT_KEYS.intersection(environment)
        assert environment["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] == "1"
        assert environment["PYTHONNOUSERSITE"] == "1"
        assert environment["HOME"].endswith("/home")
        assert environment["TMPDIR"].endswith("/storage")
        assert Path(cast(Path, kwargs["cwd"])).name == "work"
        assert command[1:5] == ("-I", "-B", "-X", "utf8")
        assert "-m" not in command
        assert "PYTHONPATH" not in environment

        report_path = Path(command[command.index("--report") + 1])
        nonce = command[command.index("--nonce") + 1]
        secret = cast(bytes, kwargs["input"])
        assert len(secret) == 32
        report_path.write_text(
            json.dumps(_signed_report(nonce, PROPERTY_NODE_IDS, secret)),
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", successful_run)
    assert (
        property_gate_runner.execute_property_gate_nodes(
            repository_root,
            PROPERTY_NODE_IDS,
        )
        == PROPERTY_NODE_IDS
    )


def test_actual_five_node_gate_ignores_collect_only_and_plugin_injection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PYTEST_ADDOPTS", "--collect-only")
    monkeypatch.setenv("PYTEST_PLUGINS", "cv_trust_nonexistent_attacker_plugin")
    monkeypatch.setenv("COVERAGE_PROCESS_CONFIG", "attacker-controlled")
    monkeypatch.setenv("HYPOTHESIS_PROFILE", "attacker-controlled")
    monkeypatch.setenv("CI", "attacker-controlled")

    assert aggregate_v22._execute_property_gate_families(REPOSITORY_ROOT) == (
        "unseen_identity_renaming_and_input_permutation",
        "unseen_value_equivalence_and_composed_transform",
    )


def test_isolated_bootstrap_never_loads_unbound_root_python_or_conftest(
    tmp_path: Path,
) -> None:
    repository_root = _fake_repository(tmp_path)
    marker = repository_root / "unbound-module-loaded"
    attack = f"from pathlib import Path\nPath({str(marker)!r}).write_text('loaded')\n"
    for filename in ("pytest.py", "sitecustomize.py", "conftest.py"):
        (repository_root / filename).write_text(attack, encoding="utf-8")
    (repository_root / "tests" / "__init__.py").write_text("", encoding="utf-8")
    (repository_root / "tests" / "test_unseen_generalization.py").write_text(
        "def test_unseen_property_safe_id_renaming_preserves_rank_semantics():\n    assert True\n",
        encoding="utf-8",
    )

    assert property_gate_runner.execute_property_gate_nodes(
        repository_root,
        (PROPERTY_NODE_IDS[0],),
    ) == (PROPERTY_NODE_IDS[0],)
    assert not marker.exists()


def test_exit_zero_without_an_execution_report_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository_root = _fake_repository(tmp_path)
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0),
    )
    with pytest.raises(PropertyGateRunnerError, match="report is missing"):
        property_gate_runner.execute_property_gate_nodes(repository_root, PROPERTY_NODE_IDS)


@pytest.mark.parametrize("failure", ["nonzero", "timeout", "oserror"])
def test_subprocess_failure_never_produces_a_property_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    repository_root = _fake_repository(tmp_path)

    def failed_run(*_args: object, **_kwargs: object) -> object:
        if failure == "timeout":
            raise subprocess.TimeoutExpired("pytest", 240)
        if failure == "oserror":
            raise OSError("process unavailable")
        return SimpleNamespace(returncode=1)

    monkeypatch.setattr(subprocess, "run", failed_run)
    with pytest.raises(PropertyGateRunnerError, match="subprocess"):
        property_gate_runner.execute_property_gate_nodes(repository_root, PROPERTY_NODE_IDS)


@pytest.mark.parametrize(
    "mutation",
    [
        "collect_only",
        "wrong_collected_node",
        "duplicate_collected_node",
        "wrong_call_node",
        "duplicate_call_node",
        "failed_call",
        "failed_setup",
        "skipped_teardown",
        "xfail_call",
        "wrong_nonce",
        "invalid_version",
        "invalid_hmac",
        "collection_not_observed",
        "nonzero_session",
        "non_string_collected_node",
        "invalid_phase_schema",
        "reordered_phase",
        "extra_field",
        "hmac_tamper",
        "duplicate_key",
        "nonfinite",
        "empty",
        "oversized",
    ],
)
def test_wrong_duplicate_or_tampered_machine_reports_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    repository_root = _fake_repository(tmp_path)

    def tampered_run(command: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
        report_path = Path(command[command.index("--report") + 1])
        nonce = command[command.index("--nonce") + 1]
        secret = cast(bytes, _kwargs["input"])
        report = _valid_report(nonce, PROPERTY_NODE_IDS)
        if mutation == "collect_only":
            report["phase_reports"] = []
        elif mutation == "wrong_collected_node":
            cast(list[str], report["collected_node_ids"])[0] = "tests/test_wrong.py::test_wrong"
        elif mutation == "duplicate_collected_node":
            report["collected_node_ids"] = [PROPERTY_NODE_IDS[0], PROPERTY_NODE_IDS[0]]
        elif mutation == "wrong_call_node":
            cast(list[dict[str, object]], report["phase_reports"])[1]["node_id"] = (
                "tests/test_wrong.py::test_wrong"
            )
        elif mutation == "duplicate_call_node":
            reports = cast(list[dict[str, object]], report["phase_reports"])
            reports[4]["node_id"] = reports[1]["node_id"]
        elif mutation == "failed_call":
            cast(list[dict[str, object]], report["phase_reports"])[1]["outcome"] = "failed"
        elif mutation == "failed_setup":
            cast(list[dict[str, object]], report["phase_reports"])[0]["outcome"] = "failed"
        elif mutation == "skipped_teardown":
            cast(list[dict[str, object]], report["phase_reports"])[2]["outcome"] = "skipped"
        elif mutation == "xfail_call":
            cast(list[dict[str, object]], report["phase_reports"])[1]["was_xfail"] = True
        elif mutation == "wrong_nonce":
            report["nonce"] = "0" * 64
        elif mutation == "invalid_version":
            report["schema_version"] = True
        elif mutation == "collection_not_observed":
            report["collection_observed"] = False
        elif mutation == "nonzero_session":
            report["session_exit_status"] = 5
        elif mutation == "non_string_collected_node":
            cast(list[object], report["collected_node_ids"])[0] = 42
        elif mutation == "invalid_phase_schema":
            cast(list[dict[str, object]], report["phase_reports"])[0]["extra"] = True
        elif mutation == "reordered_phase":
            reports = cast(list[dict[str, object]], report["phase_reports"])
            reports[0], reports[1] = reports[1], reports[0]
        elif mutation == "extra_field":
            report["producer_passed"] = True

        report["hmac_sha256"] = property_gate_runner._report_hmac(report, secret)
        if mutation == "hmac_tamper":
            cast(list[dict[str, object]], report["phase_reports"])[1]["outcome"] = "failed"
        elif mutation == "invalid_hmac":
            report["hmac_sha256"] = "not-a-digest"

        if mutation == "duplicate_key":
            report_path.write_bytes(b'{"schema_version":1,"schema_version":1}')
        elif mutation == "nonfinite":
            report_path.write_bytes(b'{"not_finite":NaN}')
        elif mutation == "empty":
            report_path.write_bytes(b"")
        elif mutation == "oversized":
            report_path.write_bytes(b"{" + b" " * (32 * 1024) + b"}")
        else:
            report_path.write_text(json.dumps(report), encoding="utf-8")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", tampered_run)
    with pytest.raises(PropertyGateRunnerError):
        property_gate_runner.execute_property_gate_nodes(repository_root, PROPERTY_NODE_IDS)


def test_reporter_records_exact_clean_call_phase_proof(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    nonce = "a" * 64
    secret = b"s" * 32
    reporter = property_gate_runner._PropertyGateReporter(report_path, nonce, secret)
    session = cast(
        Any,
        SimpleNamespace(items=[SimpleNamespace(nodeid=node_id) for node_id in PROPERTY_NODE_IDS]),
    )
    reporter.pytest_collection_finish(session)
    for node_id in PROPERTY_NODE_IDS:
        for phase in ("setup", "call", "teardown"):
            reporter.pytest_runtest_logreport(
                cast(Any, SimpleNamespace(nodeid=node_id, outcome="passed", when=phase))
            )
    reporter.pytest_sessionfinish(cast(Any, SimpleNamespace()), 0)

    property_gate_runner._validate_property_report(
        report_path,
        expected_node_ids=PROPERTY_NODE_IDS,
        expected_nonce=nonce,
        expected_secret=secret,
    )
    assert json.loads(report_path.read_text(encoding="utf-8"))["phase_reports"][1] == {
        "node_id": PROPERTY_NODE_IDS[0],
        "outcome": "passed",
        "was_xfail": False,
        "when": "call",
    }


def test_reporter_will_not_overwrite_an_existing_report(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text("attacker-controlled", encoding="utf-8")
    reporter = property_gate_runner._PropertyGateReporter(report_path, "a" * 64, b"s" * 32)
    with pytest.raises(FileExistsError):
        reporter.pytest_sessionfinish(cast(Any, SimpleNamespace()), 0)


def test_worker_builds_the_pinned_pytest_invocation_and_authenticated_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository_root = _fake_repository(tmp_path)
    report_path = tmp_path / "worker-report.json"
    secret = b"w" * 32
    monkeypatch.setattr(
        sys,
        "stdin",
        cast(Any, SimpleNamespace(buffer=io.BytesIO(secret))),
    )
    monkeypatch.setattr(sys, "path", list(sys.path))

    import pytest as pytest_module

    def fake_pytest_main(arguments: list[str], *, plugins: list[object]) -> int:
        assert "--noconftest" in arguments
        assert "--import-mode=importlib" in arguments
        plugin_index = arguments.index("-p")
        assert arguments[plugin_index + 1] == "no:cacheprovider"
        reporter = cast(property_gate_runner._PropertyGateReporter, plugins[0])
        reporter.pytest_collection_finish(
            cast(Any, SimpleNamespace(items=[SimpleNamespace(nodeid=PROPERTY_NODE_IDS[0])]))
        )
        for phase in ("setup", "call", "teardown"):
            reporter.pytest_runtest_logreport(
                cast(
                    Any,
                    SimpleNamespace(
                        nodeid=PROPERTY_NODE_IDS[0],
                        outcome="passed",
                        when=phase,
                    ),
                )
            )
        reporter.pytest_sessionfinish(cast(Any, SimpleNamespace()), 0)
        return 0

    monkeypatch.setattr(pytest_module, "main", fake_pytest_main)
    target = _absolute_target(repository_root, PROPERTY_NODE_IDS[0])
    assert (
        property_gate_runner._worker_main(
            (
                "--worker",
                "--repository-root",
                str(repository_root),
                "--config",
                str(repository_root / "pyproject.toml"),
                "--report",
                str(report_path),
                "--nonce",
                "b" * 64,
                target,
            )
        )
        == 0
    )
    property_gate_runner._validate_property_report(
        report_path,
        expected_node_ids=(PROPERTY_NODE_IDS[0],),
        expected_nonce="b" * 64,
        expected_secret=secret,
    )


@pytest.mark.parametrize("failure", ["secret", "target"])
def test_worker_rejects_invalid_secret_or_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    repository_root = _fake_repository(tmp_path)
    secret = b"short" if failure == "secret" else b"w" * 32
    monkeypatch.setattr(
        sys,
        "stdin",
        cast(Any, SimpleNamespace(buffer=io.BytesIO(secret))),
    )
    target = (
        "/outside/test.py::test_outside"
        if failure == "target"
        else _absolute_target(repository_root, PROPERTY_NODE_IDS[0])
    )
    with pytest.raises(PropertyGateRunnerError, match=failure):
        property_gate_runner._worker_main(
            (
                "--worker",
                "--repository-root",
                str(repository_root),
                "--config",
                str(repository_root / "pyproject.toml"),
                "--report",
                str(tmp_path / "report.json"),
                "--nonce",
                "b" * 64,
                target,
            )
        )


@pytest.mark.parametrize(
    "node_ids",
    [
        (),
        (PROPERTY_NODE_IDS[0], PROPERTY_NODE_IDS[0]),
        ("tests/../escape.py::test_escape",),
        ("tests/missing.py::test_missing",),
    ],
)
def test_runner_rejects_missing_duplicate_or_unregistered_nodes(
    tmp_path: Path,
    node_ids: tuple[str, ...],
) -> None:
    repository_root = _fake_repository(tmp_path)
    with pytest.raises(PropertyGateRunnerError):
        property_gate_runner.execute_property_gate_nodes(repository_root, node_ids)


def test_runner_rejects_missing_configuration_and_unbounded_timeout(tmp_path: Path) -> None:
    repository_root = tmp_path / "repository"
    test_file = repository_root / "tests" / "test_unseen_generalization.py"
    test_file.parent.mkdir(parents=True)
    test_file.write_text("def placeholder():\n    pass\n", encoding="utf-8")
    with pytest.raises(PropertyGateRunnerError, match="configuration"):
        property_gate_runner.execute_property_gate_nodes(repository_root, PROPERTY_NODE_IDS)

    (repository_root / "pyproject.toml").write_text("", encoding="utf-8")
    with pytest.raises(PropertyGateRunnerError, match="timeout"):
        property_gate_runner.execute_property_gate_nodes(
            repository_root,
            PROPERTY_NODE_IDS,
            timeout_seconds=0,
        )


def test_runner_rejects_a_registered_test_path_symlinked_outside_root(tmp_path: Path) -> None:
    repository_root = _fake_repository(tmp_path)
    registered = repository_root / "tests" / "test_unseen_generalization.py"
    registered.unlink()
    outside = tmp_path / "outside.py"
    outside.write_text("def test_outside():\n    pass\n", encoding="utf-8")
    registered.symlink_to(outside)

    with pytest.raises(PropertyGateRunnerError, match="escapes"):
        property_gate_runner.execute_property_gate_nodes(
            repository_root,
            (PROPERTY_NODE_IDS[0],),
        )


@pytest.mark.parametrize(
    "arguments",
    [
        (),
        (
            "--worker",
            "--repository-root",
            "/missing",
            "--config",
            "/missing/pyproject.toml",
            "--report",
            "/missing/report.json",
            "--nonce",
            "bad",
            "tests/test.py::test_bad",
        ),
    ],
)
def test_worker_rejects_missing_or_invalid_configuration(arguments: tuple[str, ...]) -> None:
    with pytest.raises((PropertyGateRunnerError, SystemExit)):
        property_gate_runner._worker_main(arguments)
