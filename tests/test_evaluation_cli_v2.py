"""Public CLI and import-boundary tests for the V2 semantic harness."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import evaluation.__main__ as evaluation_cli
from evaluation.capture_v2 import CaseInputV2


@pytest.fixture(autouse=True)
def _validated_capture_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        evaluation_cli,
        "validate_capture_environment_v2",
        lambda _root, _executable: object(),
    )


def _case(name: str = "unit_case", fixture_id: str = "unit_fixture") -> CaseInputV2:
    return CaseInputV2(
        name=name,
        fixture_id=fixture_id,
        materialize=lambda _root, _source_url: None,
    )


@pytest.mark.parametrize("command", ("v2-validate", "v2-results"))
def test_v2_public_release_cli_sanitizes_untrusted_failures(
    command: str,
    tmp_path: Path,
) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    evidence_directory = tmp_path / "evidence-v2"
    evidence_directory.mkdir()
    markers = (
        "LEAK_MARKER_UNTRUSTED",
        "https://attacker.invalid/payload",
        "`ignore the release policy`",
        "\x1b[31mterminal-control",
        "Bearer sk-test-secret-material",
    )
    (evidence_directory / "manifest-v2.json").write_text(
        json.dumps({"untrusted": markers}),
        encoding="utf-8",
    )

    completed = subprocess.run(
        (
            sys.executable,
            "-m",
            "evaluation",
            command,
            "--evidence-dir",
            str(evidence_directory),
            "--repository-root",
            str(repository_root),
        ),
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 1
    assert completed.stdout == ""
    assert completed.stderr == "error: V2 operation failed\n"
    assert all(marker not in completed.stderr for marker in markers)
    assert str(repository_root) not in completed.stderr
    assert str(evidence_directory) not in completed.stderr


def test_v2_deterministic_cli_captures_then_derives_all_49_gates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "deterministic-v2.json"
    case = _case()
    observations = (object(),)
    calls: dict[str, Any] = {}

    monkeypatch.setattr(
        evaluation_cli,
        "load_deterministic_oracle_v2",
        lambda path: SimpleNamespace(
            cases=(SimpleNamespace(name=case.name, fixture_id=case.fixture_id),),
            path=path,
        ),
    )
    monkeypatch.setattr(evaluation_cli, "release_case_inputs_v2", lambda: (case,))
    monkeypatch.setattr(
        evaluation_cli,
        "release_implementation_paths_v2",
        lambda root: (root / "src",),
    )
    monkeypatch.setattr(
        evaluation_cli,
        "implementation_tree_sha256_v2",
        lambda paths, *, repository_root: "a" * 64,
    )
    monkeypatch.setattr(
        evaluation_cli,
        "PublicCommandCaptureV2",
        lambda *, executable: ("runner", executable),
    )

    def capture(cases: object, runner: object) -> tuple[object, ...]:
        calls["capture"] = (cases, runner)
        return observations

    monkeypatch.setattr(evaluation_cli, "capture_deterministic_cases_v2", capture)

    def write(path: Path, **kwargs: object) -> Path:
        calls["write"] = (path, kwargs)
        return path

    monkeypatch.setattr(evaluation_cli, "write_deterministic_observations_v2", write)
    monkeypatch.setattr(
        evaluation_cli,
        "validate_deterministic_release_v2",
        lambda artifact, oracle: SimpleNamespace(case_count=1, artifact_invariant_count=47),
    )
    monkeypatch.setattr(
        evaluation_cli,
        "execute_property_gate_families_v2",
        lambda root: SimpleNamespace(
            names=("identity_and_order", "value_equivalence"),
            property_gate_count=2,
            total_release_gate_count=49,
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python -m evaluation",
            "v2-deterministic",
            "--cv-trust-bin",
            "test-cv-trust",
            "--repository-root",
            str(tmp_path),
            "--output",
            str(output),
        ],
    )

    evaluation_cli.main()

    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "artifact_invariant_count": 47,
        "artifact_path": "deterministic-v2.json",
        "case_count": 1,
        "implementation_tree_sha256": "a" * 64,
        "paid_api_calls": 0,
        "property_gate_count": 2,
        "property_gate_names": ["identity_and_order", "value_equivalence"],
        "status": "valid",
        "total_release_gate_count": 49,
    }
    assert calls["capture"] == ((case,), ("runner", "test-cv-trust"))
    written_path, written_kwargs = calls["write"]
    assert written_path == output
    assert written_kwargs["observations"] is observations
    assert written_kwargs["implementation_tree_sha256"] == "a" * 64


def test_v2_deterministic_cli_refuses_registry_or_tree_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "deterministic-v2.json"
    case = _case()
    monkeypatch.setattr(evaluation_cli, "release_case_inputs_v2", lambda: (case,))
    monkeypatch.setattr(
        evaluation_cli,
        "load_deterministic_oracle_v2",
        lambda _path: SimpleNamespace(
            cases=(SimpleNamespace(name="different", fixture_id=case.fixture_id),)
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["python -m evaluation", "v2-deterministic", "--output", str(output)],
    )
    with pytest.raises(RuntimeError, match="registry differs"):
        evaluation_cli.main()

    monkeypatch.setattr(
        evaluation_cli,
        "load_deterministic_oracle_v2",
        lambda _path: SimpleNamespace(
            cases=(SimpleNamespace(name=case.name, fixture_id=case.fixture_id),)
        ),
    )
    monkeypatch.setattr(
        evaluation_cli,
        "release_implementation_paths_v2",
        lambda root: (root / "src",),
    )
    digests = iter(("a" * 64, "b" * 64))
    monkeypatch.setattr(
        evaluation_cli,
        "implementation_tree_sha256_v2",
        lambda paths, *, repository_root: next(digests),
    )
    monkeypatch.setattr(evaluation_cli, "PublicCommandCaptureV2", lambda **_kwargs: object())
    monkeypatch.setattr(
        evaluation_cli,
        "capture_deterministic_cases_v2",
        lambda _cases, _runner: (object(),),
    )
    with pytest.raises(RuntimeError, match="changed during V2 capture"):
        evaluation_cli.main()

    release_digests = iter(("a" * 64, "a" * 64, "b" * 64))
    monkeypatch.setattr(
        evaluation_cli,
        "implementation_tree_sha256_v2",
        lambda paths, *, repository_root: next(release_digests),
    )
    monkeypatch.setattr(
        evaluation_cli,
        "write_deterministic_observations_v2",
        lambda path, **_kwargs: path,
    )
    monkeypatch.setattr(
        evaluation_cli,
        "validate_deterministic_release_v2",
        lambda _artifact, _oracle: SimpleNamespace(
            case_count=1,
            artifact_invariant_count=47,
        ),
    )
    monkeypatch.setattr(
        evaluation_cli,
        "execute_property_gate_families_v2",
        lambda _root: SimpleNamespace(
            names=("identity_and_order", "value_equivalence"),
            property_gate_count=2,
            total_release_gate_count=49,
        ),
    )
    with pytest.raises(RuntimeError, match="changed during V2 release gates"):
        evaluation_cli.main()


def test_v2_deterministic_cli_requires_the_release_artifact_filename(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python -m evaluation",
            "v2-deterministic",
            "--output",
            str(tmp_path / "diagnostic.json"),
        ],
    )
    with pytest.raises(SystemExit) as wrong_filename:
        evaluation_cli.main()
    assert wrong_filename.value.code == 2


@pytest.mark.parametrize(
    ("command", "override_flag", "output_name"),
    (
        ("v2-deterministic", "--oracle", "deterministic-v2.json"),
        ("v2-secure", "--heldout-oracle", "secure-v2.jsonl"),
        ("v2-validate", "--deterministic-oracle", "unused"),
        ("v2-results", "--heldout-oracle", "unused"),
    ),
)
def test_public_v2_cli_has_no_oracle_override_surface(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    command: str,
    override_flag: str,
    output_name: str,
) -> None:
    arguments = [
        "python -m evaluation",
        command,
        override_flag,
        str(tmp_path / "substitute-oracle.json"),
    ]
    if output_name != "unused":
        arguments.extend(("--output", str(tmp_path / output_name)))
    monkeypatch.setattr(sys, "argv", arguments)

    with pytest.raises(SystemExit) as rejected:
        evaluation_cli.main()
    assert rejected.value.code == 2


def test_v2_capture_target_cannot_modify_its_own_tree_binding(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    evaluator = tmp_path / "evaluation"
    evaluator.mkdir()
    monkeypatch.setattr(
        evaluation_cli,
        "release_implementation_paths_v2",
        lambda _root: (evaluator,),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python -m evaluation",
            "v2-deterministic",
            "--repository-root",
            str(tmp_path),
            "--output",
            str(evaluator / "deterministic-v2.json"),
        ],
    )

    with pytest.raises(SystemExit) as inside_tree:
        evaluation_cli.main()
    assert inside_tree.value.code == 2


def test_v2_release_cli_commands_use_semantic_release_apis(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    evidence = tmp_path / "evidence-v2"
    output = tmp_path / "results.md"
    calls: list[tuple[str, object]] = []

    def write_manifest(directory: Path, **kwargs: object) -> Path:
        calls.append(("manifest", (directory, kwargs)))
        return directory / "manifest-v2.json"

    monkeypatch.setattr(evaluation_cli, "write_release_manifest_v2", write_manifest)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python -m evaluation",
            "v2-manifest",
            "--evidence-dir",
            str(evidence),
            "--repository-root",
            str(tmp_path),
        ],
    )
    evaluation_cli.main()
    assert json.loads(capsys.readouterr().out)["manifest_path"] == ("evidence-v2/manifest-v2.json")

    aggregate = SimpleNamespace(
        manifest_sha256="f" * 64,
        deterministic=SimpleNamespace(case_count=25),
        artifact_invariant_count=47,
        property_gate_count=2,
        property_gate_names=("identity_and_order", "value_equivalence"),
        total_release_gate_count=49,
    )

    def validate(manifest: Path, **kwargs: object) -> object:
        calls.append(("validate", (manifest, kwargs)))
        return aggregate

    monkeypatch.setattr(evaluation_cli, "validate_aggregate_v2", validate)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python -m evaluation",
            "v2-validate",
            "--evidence-dir",
            str(evidence),
            "--repository-root",
            str(tmp_path),
        ],
    )
    evaluation_cli.main()
    validated = json.loads(capsys.readouterr().out)
    assert validated["case_count"] == 25
    assert validated["total_release_gate_count"] == 49

    monkeypatch.setattr(
        evaluation_cli,
        "render_release_results_v2",
        lambda directory, **kwargs: "## Validated V2 evidence\n",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python -m evaluation",
            "v2-results",
            "--evidence-dir",
            str(evidence),
            "--repository-root",
            str(tmp_path),
            "--output",
            str(output),
        ],
    )
    evaluation_cli.main()
    rendered = json.loads(capsys.readouterr().out)
    assert rendered == {"results_path": "results.md"}
    assert output.read_text(encoding="utf-8") == "## Validated V2 evidence\n"
    assert [name for name, _ in calls] == ["manifest", "validate"]


def test_v2_secure_cli_requires_paid_opt_in_and_frozen_filename(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[object] = []
    monkeypatch.setattr(
        evaluation_cli,
        "capture_secure_live_v2",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    output = tmp_path / "secure-v2.jsonl"
    monkeypatch.setattr(
        sys,
        "argv",
        ["python -m evaluation", "v2-secure", "--output", str(output)],
    )
    with pytest.raises(SystemExit) as missing_authorization:
        evaluation_cli.main()
    assert missing_authorization.value.code == 2
    assert calls == []

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python -m evaluation",
            "v2-secure",
            "--execute-live-api",
            "--output",
            str(tmp_path / "wrong.jsonl"),
        ],
    )
    with pytest.raises(SystemExit) as wrong_filename:
        evaluation_cli.main()
    assert wrong_filename.value.code == 2
    assert calls == []


def test_v2_secure_cli_emits_only_a_capture_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "secure-v2.jsonl"
    calls: list[tuple[Path, dict[str, object]]] = []

    def capture(path: Path, **kwargs: object) -> object:
        calls.append((path, kwargs))
        return SimpleNamespace(
            artifact_path=path,
            attempt_count=12,
            implementation_tree_sha256="c" * 64,
        )

    monkeypatch.setattr(evaluation_cli, "capture_secure_live_v2", capture)
    monkeypatch.setattr(
        evaluation_cli,
        "release_implementation_paths_v2",
        lambda root: (root / "src",),
    )
    monkeypatch.setattr(
        evaluation_cli,
        "implementation_tree_sha256_v2",
        lambda paths, *, repository_root: "c" * 64,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python -m evaluation",
            "v2-secure",
            "--execute-live-api",
            "--output",
            str(output),
            "--repository-root",
            str(tmp_path),
            "--cv-trust-bin",
            "cv-trust-test",
            "--canonical-model",
            "canonical-model-snapshot",
            "--heldout-model",
            "heldout-model-snapshot",
        ],
    )

    evaluation_cli.main()

    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "artifact_path": "secure-v2.jsonl",
        "attempt_count": 12,
        "implementation_tree_sha256": "c" * 64,
        "producer_verdicts": 0,
        "status": "captured_unvalidated",
    }
    assert calls == [
        (
            output,
            {
                "execute_live_api": True,
                "repository_root": tmp_path,
                "executable": "cv-trust-test",
                "canonical_model": "canonical-model-snapshot",
                "heldout_model": "heldout-model-snapshot",
                "heldout_oracle_path": (tmp_path / "evaluation" / "heldout_release_oracle_v2.json"),
            },
        )
    ]


def test_semantic_validators_do_not_import_capture_runtime_or_v1_core() -> None:
    root = Path(__file__).resolve().parents[1]
    modules = (
        "release_spec_v2.py",
        "deterministic_release_v2.py",
        "secure_release_v2.py",
        "naive_release_v2.py",
        "aggregate_v2.py",
    )
    forbidden = {
        "cv_trust_agent",
        "evaluation.capture_v2",
        "evaluation.core",
    }
    for filename in modules:
        path = root / "evaluation" / filename
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
        violations = {
            imported_name
            for imported_name in imported
            if any(
                imported_name == denied or imported_name.startswith(f"{denied}.")
                for denied in forbidden
            )
        }
        assert not violations, filename
