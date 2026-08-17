"""Fail-closed release-environment binding for public V2 capture commands."""

from __future__ import annotations

import ast
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import evaluation

_MAX_SHEBANG_BYTES = 4_096
_MAX_IMPORT_PATH_BYTES = 4_096
_MAX_CONSOLE_SCRIPT_BYTES = 16 * 1024
_EXPECTED_CONSOLE_SCRIPT = """\
import sys
from cv_trust_agent.cli import app
if __name__ == "__main__":
    if sys.argv[0].endswith("-script.pyw"):
        sys.argv[0] = sys.argv[0][:-11]
    elif sys.argv[0].endswith(".exe"):
        sys.argv[0] = sys.argv[0][:-4]
    sys.exit(app())
"""
_EXPECTED_CONSOLE_SCRIPT_AST = ast.dump(
    ast.parse(_EXPECTED_CONSOLE_SCRIPT),
    include_attributes=False,
)


class CaptureEnvironmentV2Error(RuntimeError):
    """The capture executable cannot be bound to the selected repository tree."""


@dataclass(frozen=True, slots=True)
class ValidatedCaptureEnvironmentV2:
    """Private execution receipt; paths must not enter evidence or public output."""

    executable: Path
    interpreter: Path


def validate_capture_environment_v2(
    repository_root: Path,
    executable: str,
) -> ValidatedCaptureEnvironmentV2:
    """Bind evaluator, script, interpreter, and imported runtime to one checkout."""

    root = repository_root.resolve()
    expected_evaluator = root / "evaluation" / "__init__.py"
    evaluator_file = getattr(evaluation, "__file__", None)
    if evaluator_file is None or Path(evaluator_file).resolve() != expected_evaluator:
        raise CaptureEnvironmentV2Error("V2 evaluator is outside the selected repository")

    resolved_command = shutil.which(executable)
    if resolved_command is None:
        raise CaptureEnvironmentV2Error("V2 capture executable is unavailable")
    resolved_executable = Path(resolved_command).resolve()
    expected_bin = root / ".venv" / "bin"
    if resolved_executable.parent != expected_bin or resolved_executable.name != "cv-trust":
        raise CaptureEnvironmentV2Error("V2 capture executable is outside the project venv")

    interpreter = _read_venv_interpreter(resolved_executable, expected_bin)
    _validate_console_script(resolved_executable)
    imported_runtime = _runtime_import_path(interpreter)
    expected_runtime = root / "src" / "cv_trust_agent" / "__init__.py"
    if imported_runtime != expected_runtime:
        raise CaptureEnvironmentV2Error("V2 capture runtime is outside the selected repository")
    return ValidatedCaptureEnvironmentV2(
        executable=resolved_executable,
        interpreter=interpreter,
    )


def _read_venv_interpreter(executable: Path, expected_bin: Path) -> Path:
    try:
        with executable.open("rb") as stream:
            first_line = stream.readline(_MAX_SHEBANG_BYTES + 1)
    except OSError as exc:
        raise CaptureEnvironmentV2Error("V2 capture executable cannot be inspected") from exc
    if len(first_line) > _MAX_SHEBANG_BYTES or not first_line.startswith(b"#!"):
        raise CaptureEnvironmentV2Error("V2 capture executable has an invalid interpreter")
    try:
        tokens = shlex.split(first_line[2:].decode("utf-8").strip())
    except (UnicodeError, ValueError) as exc:
        raise CaptureEnvironmentV2Error("V2 capture executable has an invalid interpreter") from exc
    if len(tokens) != 1:
        raise CaptureEnvironmentV2Error("V2 capture executable uses a wrapper interpreter")
    interpreter = Path(tokens[0])
    if (
        not interpreter.is_absolute()
        or interpreter.parent != expected_bin
        or not interpreter.name.startswith("python")
        or not interpreter.is_file()
        or interpreter.resolve() != Path(sys.executable).resolve()
    ):
        raise CaptureEnvironmentV2Error("V2 capture interpreter is outside the project venv")
    return interpreter


def _runtime_import_path(interpreter: Path) -> Path:
    try:
        completed = subprocess.run(
            (
                interpreter.as_posix(),
                "-I",
                "-c",
                "import cv_trust_agent; print(cv_trust_agent.__file__)",
            ),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CaptureEnvironmentV2Error("V2 capture interpreter check failed") from exc
    if (
        completed.returncode != 0
        or not completed.stdout
        or len(completed.stdout) > _MAX_IMPORT_PATH_BYTES
    ):
        raise CaptureEnvironmentV2Error("V2 capture interpreter check failed")
    try:
        raw_path = completed.stdout.decode("utf-8").strip()
    except UnicodeError as exc:
        raise CaptureEnvironmentV2Error("V2 capture interpreter check failed") from exc
    if not raw_path or "\n" in raw_path or "\r" in raw_path:
        raise CaptureEnvironmentV2Error("V2 capture interpreter returned an invalid path")
    return Path(raw_path).resolve()


def _validate_console_script(executable: Path) -> None:
    try:
        payload = executable.read_bytes()
    except OSError as exc:
        raise CaptureEnvironmentV2Error("V2 capture executable cannot be inspected") from exc
    if not payload or len(payload) > _MAX_CONSOLE_SCRIPT_BYTES or b"\n" not in payload:
        raise CaptureEnvironmentV2Error("V2 capture executable is not the project entry point")
    body = payload.split(b"\n", 1)[1]
    try:
        tree = ast.parse(body.decode("utf-8"))
    except (UnicodeError, SyntaxError) as exc:
        raise CaptureEnvironmentV2Error(
            "V2 capture executable is not the project entry point"
        ) from exc
    if ast.dump(tree, include_attributes=False) != _EXPECTED_CONSOLE_SCRIPT_AST:
        raise CaptureEnvironmentV2Error("V2 capture executable is a wrapper")
