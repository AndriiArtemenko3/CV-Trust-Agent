from __future__ import annotations

import hashlib
import json
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_TREE = "086b97479e208c32584d3d79560b3d559b5214d6b79ec0701333340fe0142f71"
ARCHIVE_ROOT = REPOSITORY_ROOT / "evidence" / "history" / f"v1-{ARCHIVE_TREE}"


def test_v1_evidence_archive_is_complete_and_byte_preserved() -> None:
    commitment_path = ARCHIVE_ROOT / "archive-sha256.json"
    commitment = json.loads(commitment_path.read_text(encoding="utf-8"))

    assert commitment == {
        "schema_version": 1,
        "archive_kind": "byte_preserved_v1_evidence",
        "implementation_tree_sha256": ARCHIVE_TREE,
        "files": {
            "deterministic-summary.json": (
                "1a651020e4377f2b8c698915e133f4d338e69c9462eda19f8724b79da6c0bb7b"
            ),
            "deterministic.manifest.json": (
                "5b71070553026029b24dda65db5fd0e347760f6afd07c60d6b8d7f90af725b33"
            ),
            "manifest.json": ("db52c3d897ac09491e9fad364f14875e882902d4471d8cbd8959ecb85f8a532d"),
            "naive-pairs.jsonl": (
                "b6126ebdd965ff3b6bb869b6e2a319cdcd10b358c5c63889c51f9f6fb50acc0a"
            ),
            "results.generated.md": (
                "94b8a1c75882523acbf4643aae7339eeaa9b02b4044acbe4bc6ba824184c7d38"
            ),
            "secure-smokes.jsonl": (
                "44c93b09117f6ed7ada8f63ce882cc196d7334fdddad052447681ac62a79d50d"
            ),
            "secure-smokes.manifest.json": (
                "8cfce81f729857e4008ff84a567093d72a0714e37b69bd15ec5e1d7192d75698"
            ),
        },
        "status": "historical_v1_not_upgraded",
    }
    expected = commitment["files"]
    observed_names = {path.name for path in ARCHIVE_ROOT.iterdir() if path != commitment_path}
    assert observed_names == set(expected)
    for filename, expected_digest in expected.items():
        assert hashlib.sha256((ARCHIVE_ROOT / filename).read_bytes()).hexdigest() == (
            expected_digest
        )


def test_v1_internal_manifest_remains_bound_to_the_archived_tree() -> None:
    manifest = json.loads((ARCHIVE_ROOT / "manifest.json").read_text(encoding="utf-8"))
    deterministic = json.loads(
        (ARCHIVE_ROOT / "deterministic.manifest.json").read_text(encoding="utf-8")
    )
    secure = json.loads((ARCHIVE_ROOT / "secure-smokes.manifest.json").read_text(encoding="utf-8"))

    assert {
        manifest["implementation_tree_sha256"],
        deterministic["implementation_tree_sha256"],
        secure["implementation_tree_sha256"],
    } == {ARCHIVE_TREE}
