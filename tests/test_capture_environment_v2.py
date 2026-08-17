"""Release-environment binding tests for public V2 capture."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

import evaluation as evaluation_package
import evaluation.capture_environment_v2 as capture_environment
from evaluation.capture_environment_v2 import (
    CaptureEnvironmentV2Error,
    validate_capture_environment_v2,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_capture_environment_binds_the_real_editable_project_venv() -> None:
    validated = validate_capture_environment_v2(REPOSITORY_ROOT, "cv-trust")

    assert validated.executable == REPOSITORY_ROOT / ".venv" / "bin" / "cv-trust"
    assert validated.interpreter.parent == REPOSITORY_ROOT / ".venv" / "bin"
    assert validated.interpreter.name.startswith("python")


def test_capture_environment_rejects_an_external_path_binary(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    external_bin = tmp_path / "bin"
    external_bin.mkdir()
    external = external_bin / "cv-trust"
    external.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    external.chmod(0o755)
    monkeypatch.setenv("PATH", external_bin.as_posix())

    with pytest.raises(CaptureEnvironmentV2Error, match="outside the project venv"):
        validate_capture_environment_v2(REPOSITORY_ROOT, "cv-trust")


def test_capture_environment_rejects_a_different_evaluator_tree(tmp_path: Path) -> None:
    with pytest.raises(CaptureEnvironmentV2Error, match="evaluator is outside"):
        validate_capture_environment_v2(tmp_path, "cv-trust")


def test_capture_environment_rejects_a_wrapper_shebang(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    evaluator = tmp_path / "evaluation"
    evaluator.mkdir()
    evaluator_init = evaluator / "__init__.py"
    evaluator_init.write_text("", encoding="utf-8")
    monkeypatch.setattr(evaluation_package, "__file__", evaluator_init.as_posix())
    venv_bin = tmp_path / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    executable = venv_bin / "cv-trust"
    executable.write_text("#!/usr/bin/env python\n", encoding="utf-8")
    executable.chmod(0o755)

    with pytest.raises(CaptureEnvironmentV2Error, match="wrapper interpreter"):
        validate_capture_environment_v2(tmp_path, executable.as_posix())


def test_capture_environment_rejects_a_replaced_console_script(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    evaluator = tmp_path / "evaluation"
    evaluator.mkdir()
    evaluator_init = evaluator / "__init__.py"
    evaluator_init.write_text("", encoding="utf-8")
    monkeypatch.setattr(evaluation_package, "__file__", evaluator_init.as_posix())
    venv_bin = tmp_path / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    interpreter = venv_bin / "python3"
    interpreter.symlink_to(Path(sys.executable))
    executable = venv_bin / "cv-trust"
    executable.write_text(
        f"#!{interpreter.as_posix()}\nimport sys\nsys.exit(0)\n",
        encoding="utf-8",
    )
    executable.chmod(0o755)

    with pytest.raises(CaptureEnvironmentV2Error, match="executable is a wrapper"):
        validate_capture_environment_v2(tmp_path, executable.as_posix())


def test_capture_environment_rejects_an_interpreter_importing_another_tree(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    evaluator = tmp_path / "evaluation"
    evaluator.mkdir()
    evaluator_init = evaluator / "__init__.py"
    evaluator_init.write_text("", encoding="utf-8")
    monkeypatch.setattr(evaluation_package, "__file__", evaluator_init.as_posix())
    venv_bin = tmp_path / ".venv" / "bin"
    venv_bin.mkdir(parents=True)
    interpreter = venv_bin / "python3"
    interpreter.symlink_to(Path(sys.executable))
    executable = venv_bin / "cv-trust"
    canonical_body = (
        (REPOSITORY_ROOT / ".venv" / "bin" / "cv-trust").read_bytes().split(b"\n", 1)[1]
    )
    executable.write_bytes(f"#!{interpreter.as_posix()}\n".encode() + canonical_body)
    executable.chmod(0o755)
    monkeypatch.setattr(
        capture_environment,
        "_runtime_import_path",
        lambda _interpreter: REPOSITORY_ROOT / "src" / "cv_trust_agent" / "__init__.py",
    )

    with pytest.raises(CaptureEnvironmentV2Error, match="runtime is outside"):
        validate_capture_environment_v2(tmp_path, executable.as_posix())
