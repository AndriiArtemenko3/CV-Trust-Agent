"""Stable commitments for deterministic source trees.

Transport URLs vary only because evaluators bind ephemeral localhost ports.
JSON URL fields are therefore normalized to their canonical paths before
hashing; every other JSON value and every non-JSON byte remains committed.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

_TRANSPORT_FIELDS = frozenset({"detail_url", "resume_url"})


def normalized_fixture_tree_hash(root: Path) -> str:
    """Hash one non-empty tree with only endpoint authority normalized."""

    files = sorted(path for path in root.rglob("*") if path.is_file())
    if not files:
        raise ValueError("fixture tree is empty")
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        content = path.read_bytes()
        if path.suffix == ".json":
            parsed = json.loads(content)
            normalized = _normalize_transport(parsed, field_name=None)
            content = json.dumps(
                normalized,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        digest.update(content)
        digest.update(b"\0")
    return digest.hexdigest()


def _normalize_transport(value: object, *, field_name: str | None) -> object:
    if field_name in _TRANSPORT_FIELDS and isinstance(value, str):
        parsed = urlsplit(value)
        return f"source://fixture{parsed.path}"
    if isinstance(value, dict):
        return {
            str(key): _normalize_transport(item, field_name=str(key)) for key, item in value.items()
        }
    if isinstance(value, list):
        return [_normalize_transport(item, field_name=None) for item in value]
    return value
