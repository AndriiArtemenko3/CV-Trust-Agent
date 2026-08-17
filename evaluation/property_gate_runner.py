"""Isolated pytest execution with exact machine-readable property-gate proof.

The parent runner supplies a minimal, code-owned environment and a private
temporary workspace.  The same tree-bound file is launched as an isolated
worker and supplies an in-memory pytest plugin.  Its single-use report is
authenticated with a one-use secret delivered only over the child's stdin.
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from _pytest.main import Session
    from _pytest.reports import TestReport

_REPORT_SCHEMA_VERSION = 1
_MAX_REPORT_BYTES = 32 * 1024
_NONCE_PATTERN = re.compile(r"[0-9a-f]{64}")
_NODE_ID_PATTERN = re.compile(r"tests/[A-Za-z0-9_.-]+\.py::[A-Za-z0-9_]+")
_REPORT_HMAC_DOMAIN = b"cv-trust/property-gate-report/v1\x00"
_PYTEST_PHASES = ("setup", "call", "teardown")


class PropertyGateRunnerError(RuntimeError):
    """The controlled property subprocess or its execution proof is invalid."""


def execute_property_gate_nodes(
    repository_root: Path,
    node_ids: Sequence[str],
    *,
    timeout_seconds: int = 240,
) -> tuple[str, ...]:
    """Run exactly ``node_ids`` and require one passing call report for each."""

    root = repository_root.resolve()
    expected_node_ids = tuple(node_ids)
    _validate_expected_node_ids(root, expected_node_ids)
    if not 1 <= timeout_seconds <= 600:
        raise PropertyGateRunnerError("property-gate timeout is outside its bounded range")

    configuration = root / "pyproject.toml"
    if not configuration.is_file():
        raise PropertyGateRunnerError("property-gate pytest configuration is missing")

    with TemporaryDirectory(prefix="cv-trust-property-gate-") as temporary_name:
        temporary_root = Path(temporary_name).resolve()
        home = temporary_root / "home"
        work = temporary_root / "work"
        storage = temporary_root / "storage"
        for directory in (home, work, storage):
            directory.mkdir(mode=0o700)

        report_path = storage / "pytest-property-report.json"
        nonce = secrets.token_hex(32)
        report_secret = secrets.token_bytes(32)
        worker = Path(__file__).resolve()
        command = (
            sys.executable,
            "-I",
            "-B",
            "-X",
            "utf8",
            str(worker),
            "--worker",
            "--repository-root",
            str(root),
            "--config",
            str(configuration),
            "--report",
            str(report_path),
            "--nonce",
            nonce,
            "--",
            *(_absolute_pytest_target(root, node_id) for node_id in expected_node_ids),
        )
        environment = _controlled_property_environment(
            temporary_root=temporary_root,
        )
        try:
            completed = subprocess.run(
                command,
                cwd=work,
                env=environment,
                input=report_secret,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PropertyGateRunnerError("property-gate subprocess execution failed") from exc
        if completed.returncode != 0:
            raise PropertyGateRunnerError("property-gate subprocess did not pass")

        _validate_property_report(
            report_path,
            expected_node_ids=expected_node_ids,
            expected_nonce=nonce,
            expected_secret=report_secret,
        )
    return expected_node_ids


def _controlled_property_environment(
    *,
    temporary_root: Path,
) -> dict[str, str]:
    """Build an allow-listed environment; no ambient pytest state is copied."""

    executable_directory = str(Path(sys.executable).resolve().parent)
    path_entries = tuple(dict.fromkeys((executable_directory, *os.defpath.split(os.pathsep))))
    environment = {
        "HOME": str(temporary_root / "home"),
        "PATH": os.pathsep.join(path_entries),
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "TEMP": str(temporary_root / "storage"),
        "TMP": str(temporary_root / "storage"),
        "TMPDIR": str(temporary_root / "storage"),
        "XDG_CACHE_HOME": str(temporary_root / "storage" / "cache"),
        "XDG_CONFIG_HOME": str(temporary_root / "storage" / "config"),
        "XDG_DATA_HOME": str(temporary_root / "storage" / "data"),
    }
    if os.name == "nt":
        for name in ("SYSTEMROOT", "WINDIR"):
            value = os.environ.get(name)
            if value is not None:
                environment[name] = value
    return environment


def _validate_expected_node_ids(repository_root: Path, node_ids: tuple[str, ...]) -> None:
    if not node_ids or len(node_ids) > 16 or len(set(node_ids)) != len(node_ids):
        raise PropertyGateRunnerError("property-gate node IDs are incomplete or duplicated")
    for node_id in node_ids:
        if _NODE_ID_PATTERN.fullmatch(node_id) is None:
            raise PropertyGateRunnerError("property-gate node ID is outside the closed registry")
        relative_file, _separator, _test_name = node_id.partition("::")
        target = (repository_root / relative_file).resolve()
        try:
            target.relative_to(repository_root)
        except ValueError as exc:
            raise PropertyGateRunnerError("property-gate node escapes the repository") from exc
        if not target.is_file():
            raise PropertyGateRunnerError("property-gate test file is missing")


def _absolute_pytest_target(repository_root: Path, node_id: str) -> str:
    relative_file, separator, test_name = node_id.partition("::")
    return f"{(repository_root / relative_file).resolve()}{separator}{test_name}"


def _validate_property_report(
    report_path: Path,
    *,
    expected_node_ids: tuple[str, ...],
    expected_nonce: str,
    expected_secret: bytes,
) -> None:
    try:
        raw = report_path.read_bytes()
    except OSError as exc:
        raise PropertyGateRunnerError("property-gate execution report is missing") from exc
    if not raw or len(raw) > _MAX_REPORT_BYTES:
        raise PropertyGateRunnerError("property-gate execution report has an invalid size")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise PropertyGateRunnerError("property-gate execution report is not strict JSON") from exc
    if not isinstance(value, dict) or set(value) != {
        "collected_node_ids",
        "collection_observed",
        "hmac_sha256",
        "nonce",
        "phase_reports",
        "schema_version",
        "session_exit_status",
    }:
        raise PropertyGateRunnerError("property-gate execution report schema is invalid")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != _REPORT_SCHEMA_VERSION
    ):
        raise PropertyGateRunnerError("property-gate execution report version is invalid")
    if value["nonce"] != expected_nonce or _NONCE_PATTERN.fullmatch(expected_nonce) is None:
        raise PropertyGateRunnerError("property-gate execution report nonce is invalid")
    observed_hmac = value["hmac_sha256"]
    if not isinstance(observed_hmac, str) or _NONCE_PATTERN.fullmatch(observed_hmac) is None:
        raise PropertyGateRunnerError("property-gate execution report authentication is invalid")
    unsigned_value = dict(value)
    del unsigned_value["hmac_sha256"]
    if not hmac.compare_digest(observed_hmac, _report_hmac(unsigned_value, expected_secret)):
        raise PropertyGateRunnerError("property-gate execution report authentication is invalid")
    if value["collection_observed"] is not True:
        raise PropertyGateRunnerError("property-gate collection was not observed")
    if type(value["session_exit_status"]) is not int or value["session_exit_status"] != 0:
        raise PropertyGateRunnerError("property-gate pytest session did not pass")

    collected = value["collected_node_ids"]
    if not isinstance(collected, list) or any(
        not isinstance(node_id, str) for node_id in collected
    ):
        raise PropertyGateRunnerError("property-gate collected node ID is invalid")
    if tuple(collected) != expected_node_ids:
        raise PropertyGateRunnerError("property-gate collected nodes differ from the registry")

    reports = value["phase_reports"]
    if not isinstance(reports, list) or len(reports) != len(expected_node_ids) * 3:
        raise PropertyGateRunnerError("property-gate phase proof is incomplete")
    observed_phases: list[tuple[str, str]] = []
    for report in reports:
        if not isinstance(report, dict) or set(report) != {
            "node_id",
            "outcome",
            "was_xfail",
            "when",
        }:
            raise PropertyGateRunnerError("property-gate phase report schema is invalid")
        node_id = report["node_id"]
        phase = report["when"]
        if (
            not isinstance(node_id, str)
            or not isinstance(phase, str)
            or report["outcome"] != "passed"
            or phase not in _PYTEST_PHASES
            or report["was_xfail"] is not False
        ):
            raise PropertyGateRunnerError("property-gate phase report is not a clean pass")
        observed_phases.append((node_id, phase))
    expected_phases = tuple(
        (node_id, phase) for node_id in expected_node_ids for phase in _PYTEST_PHASES
    )
    if tuple(observed_phases) != expected_phases:
        raise PropertyGateRunnerError("property-gate executed phases differ from the registry")


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON constant: {value}")


def _canonical_report_bytes(value: Mapping[str, object]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _report_hmac(value: Mapping[str, object], secret: bytes) -> str:
    return hmac.new(
        secret, _REPORT_HMAC_DOMAIN + _canonical_report_bytes(value), "sha256"
    ).hexdigest()


@dataclass
class _PropertyGateReporter:
    report_path: Path
    nonce: str
    report_secret: bytes = field(repr=False)
    collected_node_ids: list[str] = field(default_factory=list)
    phase_reports: list[dict[str, object]] = field(default_factory=list)
    collection_observed: bool = False

    def pytest_collection_finish(self, session: Session) -> None:
        self.collection_observed = True
        self.collected_node_ids = [item.nodeid for item in session.items]

    def pytest_runtest_logreport(self, report: TestReport) -> None:
        if report.when in _PYTEST_PHASES:
            self.phase_reports.append(
                {
                    "node_id": report.nodeid,
                    "outcome": report.outcome,
                    "was_xfail": hasattr(report, "wasxfail"),
                    "when": report.when,
                }
            )

    def pytest_sessionfinish(self, session: Session, exitstatus: int) -> None:
        del session
        payload = {
            "collected_node_ids": self.collected_node_ids,
            "collection_observed": self.collection_observed,
            "nonce": self.nonce,
            "phase_reports": self.phase_reports,
            "schema_version": _REPORT_SCHEMA_VERSION,
            "session_exit_status": int(exitstatus),
        }
        payload["hmac_sha256"] = _report_hmac(payload, self.report_secret)
        encoded = _canonical_report_bytes(payload)
        descriptor = os.open(
            self.report_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(descriptor)


def _worker_main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--worker", action="store_true", required=True)
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("node_ids", nargs="+")
    parsed = parser.parse_args(arguments)

    repository_root = Path(parsed.repository_root).resolve()
    configuration = Path(parsed.config).resolve()
    report_path = Path(parsed.report)
    nonce = parsed.nonce
    if (
        not report_path.is_absolute()
        or not report_path.parent.is_dir()
        or report_path.exists()
        or _NONCE_PATTERN.fullmatch(nonce) is None
        or configuration != repository_root / "pyproject.toml"
        or not configuration.is_file()
    ):
        raise PropertyGateRunnerError("property-gate worker configuration is invalid")

    report_secret = sys.stdin.buffer.read(33)
    if len(report_secret) != 32:
        raise PropertyGateRunnerError("property-gate worker secret is invalid")

    pytest_targets = tuple(parsed.node_ids)
    if not 1 <= len(pytest_targets) <= 16 or any(
        not target.startswith(f"{repository_root}{os.sep}tests{os.sep}") or "::" not in target
        for target in pytest_targets
    ):
        raise PropertyGateRunnerError("property-gate worker targets are invalid")

    import pytest

    sys.path.append(str(repository_root))
    sys.path.append(str(repository_root / "src"))
    reporter = _PropertyGateReporter(
        report_path=report_path,
        nonce=nonce,
        report_secret=report_secret,
    )
    pytest_arguments = [
        "-q",
        "-c",
        str(configuration),
        "--rootdir",
        str(repository_root),
        "--noconftest",
        "--import-mode=importlib",
        "-p",
        "no:cacheprovider",
        *pytest_targets,
    ]
    return int(pytest.main(pytest_arguments, plugins=[reporter]))


if __name__ == "__main__":
    raise SystemExit(_worker_main())
