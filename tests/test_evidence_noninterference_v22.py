"""Output noninterference over the frozen V2.2 evidence surfaces."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_EVIDENCE_ROOT = Path("evidence/v2.2/v24-20260817-r1")
_FORBIDDEN_PATTERNS = (
    ("private user path", r"/Users/[A-Za-z]"),
    ("private home path", r"/home/[A-Za-z]"),
    ("url", r"https?://"),
    ("bearer credential", r"Bearer "),
    ("provider api key", r"sk-[A-Za-z0-9]"),
    ("provider key variable", r"OPENAI_API_KEY"),
    ("terminal control", "\x1b"),
    ("markdown link payload", r"\]\("),
    ("provider request id", r"resp_[A-Za-z0-9]"),
    ("prompt text", r"quarantined resume fact mapper"),
)


@pytest.mark.parametrize(
    "artifact_name",
    ["deterministic-v22.json", "secure-v22.jsonl", "naive-v22.jsonl", "manifest-v22.json"],
)
def test_frozen_v22_evidence_contains_no_untrusted_surfaces(artifact_name: str) -> None:
    path = _EVIDENCE_ROOT / artifact_name
    if not path.exists():
        pytest.skip(f"{artifact_name} has not been captured for this run yet")
    text = path.read_bytes().decode("utf-8")
    for label, pattern in _FORBIDDEN_PATTERNS:
        assert re.search(pattern, text) is None, label
    control = {character for character in set(text) if ord(character) < 32} - {"\n", "\t"}
    assert not control
