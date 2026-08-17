"""Public CLI and import-boundary tests for the V2.2 semantic harness."""

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


def test_v22_capture_rejects_executable_paths_before_environment_validation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def unexpected_validation(_root: Path, _executable: str) -> object:
        raise AssertionError("path-shaped executable reached environment validation")

    monkeypatch.setattr(
        evaluation_cli,
        "validate_capture_environment_v2",
        unexpected_validation,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python -m evaluation",
            "v22-deterministic",
            "--cv-trust-bin",
            ".venv/bin/cv-trust",
            "--repository-root",
            str(tmp_path),
            "--output",
            str(tmp_path / "v24-20260817-r1" / "deterministic-v22.json"),
        ],
    )

    with pytest.raises(SystemExit) as raised:
        evaluation_cli.main()

    assert raised.value.code == 2
    assert "V2 capture executable must be a PATH command name" in capsys.readouterr().err


@pytest.mark.parametrize("command", ("v22-validate", "v22-results"))
def test_v22_public_release_cli_sanitizes_untrusted_failures(
    command: str,
    tmp_path: Path,
) -> None:
    repository_root = Path(__file__).resolve().parents[1]
    evidence_directory = tmp_path / "v24-20260817-r1"
    evidence_directory.mkdir()
    markers = (
        "LEAK_MARKER_UNTRUSTED",
        "https://attacker.invalid/payload",
        "`ignore the release policy`",
        "\x1b[31mterminal-control",
        "Bearer sk-test-secret-material",
    )
    (evidence_directory / "manifest-v22.json").write_text(
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
    # Aggregate integrity failures surface their code-authored constant reason;
    # no untrusted manifest content may ever reach the terminal.
    assert completed.stderr == ("error: V2.2 operation failed: V2.2 release manifest is invalid\n")
    assert all(marker not in completed.stderr for marker in markers)
    assert str(repository_root) not in completed.stderr
    assert str(evidence_directory) not in completed.stderr


def test_v22_deterministic_cli_captures_then_derives_all_49_gates(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    output = tmp_path / "v24-20260817-r1" / "deterministic-v22.json"
    case = _case()
    observations = (object(),)
    calls: dict[str, Any] = {}

    monkeypatch.setattr(
        evaluation_cli,
        "load_deterministic_oracle_v22",
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
        "PublicCommandCaptureV22",
        lambda *, executable: ("runner", executable),
    )

    def capture(cases: object, runner: object) -> tuple[object, ...]:
        calls["capture"] = (cases, runner)
        return observations

    monkeypatch.setattr(evaluation_cli, "capture_deterministic_cases_v22", capture)

    def write(path: Path, **kwargs: object) -> Path:
        calls["write"] = (path, kwargs)
        return path

    monkeypatch.setattr(evaluation_cli, "write_deterministic_observations_v22", write)
    monkeypatch.setattr(
        evaluation_cli,
        "validate_deterministic_release_v22",
        lambda artifact, oracle: SimpleNamespace(case_count=1, artifact_invariant_count=47),
    )
    monkeypatch.setattr(
        evaluation_cli,
        "execute_property_gate_families_v22",
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
            "v22-deterministic",
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
        "artifact_path": "v24-20260817-r1/deterministic-v22.json",
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


def test_v22_deterministic_cli_refuses_registry_or_tree_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output = tmp_path / "v24-20260817-r1" / "deterministic-v22.json"
    case = _case()
    monkeypatch.setattr(evaluation_cli, "release_case_inputs_v2", lambda: (case,))
    monkeypatch.setattr(
        evaluation_cli,
        "load_deterministic_oracle_v22",
        lambda _path: SimpleNamespace(
            cases=(SimpleNamespace(name="different", fixture_id=case.fixture_id),)
        ),
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["python -m evaluation", "v22-deterministic", "--output", str(output)],
    )
    with pytest.raises(RuntimeError, match="registry differs"):
        evaluation_cli.main()

    monkeypatch.setattr(
        evaluation_cli,
        "load_deterministic_oracle_v22",
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
    monkeypatch.setattr(evaluation_cli, "PublicCommandCaptureV22", lambda **_kwargs: object())
    monkeypatch.setattr(
        evaluation_cli,
        "capture_deterministic_cases_v22",
        lambda _cases, _runner: (object(),),
    )
    with pytest.raises(RuntimeError, match=r"changed during V2\.2 capture"):
        evaluation_cli.main()

    release_digests = iter(("a" * 64, "a" * 64, "b" * 64))
    monkeypatch.setattr(
        evaluation_cli,
        "implementation_tree_sha256_v2",
        lambda paths, *, repository_root: next(release_digests),
    )
    monkeypatch.setattr(
        evaluation_cli,
        "write_deterministic_observations_v22",
        lambda path, **_kwargs: path,
    )
    monkeypatch.setattr(
        evaluation_cli,
        "validate_deterministic_release_v22",
        lambda _artifact, _oracle: SimpleNamespace(
            case_count=1,
            artifact_invariant_count=47,
        ),
    )
    monkeypatch.setattr(
        evaluation_cli,
        "execute_property_gate_families_v22",
        lambda _root: SimpleNamespace(
            names=("identity_and_order", "value_equivalence"),
            property_gate_count=2,
            total_release_gate_count=49,
        ),
    )
    with pytest.raises(RuntimeError, match=r"changed during V2\.2 release gates"):
        evaluation_cli.main()


def test_v22_deterministic_cli_requires_the_release_artifact_filename(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python -m evaluation",
            "v22-deterministic",
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
        ("v22-deterministic", "--oracle", "deterministic-v22.json"),
        ("v22-secure", "--heldout-oracle", "secure-v22.jsonl"),
        ("v22-validate", "--deterministic-oracle", "unused"),
        ("v22-results", "--heldout-oracle", "unused"),
    ),
)
def test_public_v22_cli_has_no_oracle_override_surface(
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


def test_v22_capture_target_cannot_modify_its_own_tree_binding(
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
            "v22-deterministic",
            "--repository-root",
            str(tmp_path),
            "--output",
            str(evaluator / "deterministic-v22.json"),
        ],
    )

    with pytest.raises(SystemExit) as inside_tree:
        evaluation_cli.main()
    assert inside_tree.value.code == 2


def test_v22_release_cli_commands_use_semantic_release_apis(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    evidence = tmp_path / "v24-20260817-r1"
    output = tmp_path / "results.md"
    calls: list[tuple[str, object]] = []

    def write_manifest(directory: Path, **kwargs: object) -> Path:
        calls.append(("manifest", (directory, kwargs)))
        return directory / "manifest-v22.json"

    monkeypatch.setattr(evaluation_cli, "write_release_manifest_v22", write_manifest)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python -m evaluation",
            "v22-manifest",
            "--evidence-dir",
            str(evidence),
            "--repository-root",
            str(tmp_path),
        ],
    )
    evaluation_cli.main()
    assert json.loads(capsys.readouterr().out)["manifest_path"] == (
        "v24-20260817-r1/manifest-v22.json"
    )
    manifest_kwargs = calls[0][1][1]  # type: ignore[index]
    assert manifest_kwargs["run_id"] == "v24-20260817-r1"

    aggregate = SimpleNamespace(
        manifest_sha256="f" * 64,
        run_id="v24-20260817-r1",
        release_green=True,
        integrity_valid=True,
        deterministic=SimpleNamespace(case_count=25),
        artifact_invariant_count=47,
        property_gate_count=2,
        property_gate_names=("identity_and_order", "value_equivalence"),
        total_release_gate_count=49,
        provider_slot_count=116,
        secure=SimpleNamespace(
            canonical_gate_passed=True,
            prose_gate_passed=True,
            safety_passed=True,
            hard_gate_passed=True,
            unsupported_claim_count=0,
            promotion_count=0,
            clean_utility_run_count=3,
            candidate_exact_clean_counts=(
                ("AP-101", 3),
                ("AP-102", 3),
                ("AP-103", 3),
                ("AP-104", 3),
            ),
            heldout_noninterference_pair_count=3,
        ),
        naive=SimpleNamespace(
            hard_gate_passed=True,
            evaluable_block_count=8,
            positive_d_block_count=8,
        ),
        secure_ledger=SimpleNamespace(
            completed_count=84,
            failed_count=0,
            unobserved_count=0,
        ),
    )

    def validate(manifest: Path, **kwargs: object) -> object:
        calls.append(("validate", (manifest, kwargs)))
        return aggregate

    monkeypatch.setattr(evaluation_cli, "validate_aggregate_v22", validate)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python -m evaluation",
            "v22-validate",
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
    assert validated["release_green"] is True
    assert validated["status"] == "valid"
    assert validated["run_id"] == "v24-20260817-r1"
    assert validated["provider_slot_count"] == 116
    assert validated["secure_prose_gate_passed"] is True
    assert validated["naive_positive_d_block_count"] == 8
    assert validated["secure_ledger_completed_count"] == 84
    validate_kwargs = calls[1][1][1]  # type: ignore[index]
    assert validate_kwargs["require_release_green"] is False

    monkeypatch.setattr(
        evaluation_cli,
        "render_release_results_v22",
        lambda directory, **kwargs: "## Validated V2.2 evidence\n",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python -m evaluation",
            "v22-results",
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
    assert output.read_text(encoding="utf-8") == "## Validated V2.2 evidence\n"
    assert [name for name, _ in calls] == ["manifest", "validate"]


def test_v22_secure_cli_requires_opt_in_filename_and_slot_ledger(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    calls: list[object] = []
    monkeypatch.setattr(
        evaluation_cli,
        "capture_secure_live_v22",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    evidence = tmp_path / "evidence" / "v24-20260817-r1"
    output = evidence / "secure-v22.jsonl"
    ledger = evidence / "secure-slots-v22.jsonl"
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python -m evaluation",
            "v22-secure",
            "--output",
            str(output),
            "--slot-ledger",
            str(ledger),
        ],
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
            "v22-secure",
            "--execute-live-api",
            "--output",
            str(tmp_path / "evidence" / "wrong.jsonl"),
            "--slot-ledger",
            str(ledger),
        ],
    )
    with pytest.raises(SystemExit) as wrong_filename:
        evaluation_cli.main()
    assert wrong_filename.value.code == 2
    assert calls == []

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python -m evaluation",
            "v22-secure",
            "--execute-live-api",
            "--output",
            str(output),
        ],
    )
    with pytest.raises(SystemExit) as missing_ledger:
        evaluation_cli.main()
    assert missing_ledger.value.code == 2
    assert calls == []

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "python -m evaluation",
            "v22-secure",
            "--execute-live-api",
            "--output",
            str(output),
            "--slot-ledger",
            str(output.parent / "wrong-slots.jsonl"),
        ],
    )
    with pytest.raises(SystemExit) as shared_directory:
        evaluation_cli.main()
    assert shared_directory.value.code == 2
    assert calls == []


def test_v22_secure_cli_emits_only_a_capture_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    evidence = tmp_path / "evidence" / "v24-20260817-r1"
    output = evidence / "secure-v22.jsonl"
    ledger = evidence / "secure-slots-v22.jsonl"
    calls: list[tuple[Path, dict[str, object]]] = []

    def capture(path: Path, **kwargs: object) -> object:
        calls.append((path, dict(kwargs)))
        return SimpleNamespace(
            artifact_path=path,
            slot_ledger_path=kwargs["slot_ledger_path"],
            attempt_count=12,
            implementation_tree_sha256="c" * 64,
            final_chain_sha256="d" * 64,
        )

    monkeypatch.setattr(evaluation_cli, "capture_secure_live_v22", capture)
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
            "v22-secure",
            "--execute-live-api",
            "--output",
            str(output),
            "--slot-ledger",
            str(ledger),
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
        "artifact_path": "evidence/v24-20260817-r1/secure-v22.jsonl",
        "slot_ledger_path": "evidence/v24-20260817-r1/secure-slots-v22.jsonl",
        "attempt_count": 12,
        "implementation_tree_sha256": "c" * 64,
        "final_chain_sha256": "d" * 64,
        "producer_verdicts": 0,
        "status": "captured_unvalidated",
    }
    assert len(calls) == 1
    captured_path, captured_kwargs = calls[0]
    assert captured_path == output.resolve()
    assert captured_kwargs["execute_live_api"] is True
    assert captured_kwargs["slot_ledger_path"] == ledger.resolve()
    assert captured_kwargs["canonical_model"] == "canonical-model-snapshot"
    assert captured_kwargs["heldout_model"] == "heldout-model-snapshot"
    heldout_oracle_path = captured_kwargs["heldout_oracle_path"]
    assert isinstance(heldout_oracle_path, Path)
    assert heldout_oracle_path.name == "heldout_release_oracle_v22.json"


def test_v22_semantic_validators_do_not_import_capture_or_runtime() -> None:
    root = Path(__file__).resolve().parents[1]
    modules = (
        "release_spec_v22.py",
        "deterministic_release_v22.py",
        "secure_release_v22.py",
        "naive_release_v22.py",
        "aggregate_v22.py",
    )
    forbidden = {
        "cv_trust_agent",
        "evaluation.capture_v2",
        "evaluation.capture_v22",
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
