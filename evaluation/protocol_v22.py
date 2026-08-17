"""Frozen identifiers shared by V2.2 capture and independent verification."""

from __future__ import annotations

from typing import Final, Literal

FROZEN_RUN_ID_V22: Final[Literal["v24-20260817-r1"]] = "v24-20260817-r1"
SCHEMA_VERSION_V22 = 3
PROTOCOL_VERSION_V22 = "2.2"
CANONICAL_MAPPER_NAME_V22: Final[Literal["openai_responses_mapper"]] = "openai_responses_mapper"

# These identities are part of the frozen paid-call protocol, not a runtime
# ranking oracle.  Binding them into the slot receipts prevents a ledger of
# the right size from being replayed for a different cohort.
CANONICAL_PROVIDER_CANDIDATE_IDS_V22 = tuple(f"AP-{index:03d}" for index in range(1, 11))
CANONICAL_PROVIDER_SNAPSHOT_ID_V22 = "index-1"
HELDOUT_PROVIDER_CANDIDATE_IDS_V22 = tuple(f"AP-{index:03d}" for index in range(101, 105))
HELDOUT_CLEAN_SNAPSHOT_ID_V22 = "heldout-clean-1"
HELDOUT_DIRECTIVE_SNAPSHOT_ID_V22 = "heldout-directive-1"

SECURE_LEDGER_FILENAME_V22 = "secure-slots-v22.jsonl"
NAIVE_LEDGER_FILENAME_V22 = "naive-slots-v22.jsonl"

SECURE_CANONICAL_SLOT_COUNT_V22 = 60
SECURE_HELDOUT_SLOT_COUNT_V22 = 24
SECURE_SLOT_COUNT_V22 = SECURE_CANONICAL_SLOT_COUNT_V22 + SECURE_HELDOUT_SLOT_COUNT_V22
NAIVE_SLOT_COUNT_V22 = 32
TOTAL_PROVIDER_SLOT_COUNT_V22 = SECURE_SLOT_COUNT_V22 + NAIVE_SLOT_COUNT_V22


__all__ = [
    "CANONICAL_MAPPER_NAME_V22",
    "CANONICAL_PROVIDER_CANDIDATE_IDS_V22",
    "CANONICAL_PROVIDER_SNAPSHOT_ID_V22",
    "FROZEN_RUN_ID_V22",
    "HELDOUT_CLEAN_SNAPSHOT_ID_V22",
    "HELDOUT_DIRECTIVE_SNAPSHOT_ID_V22",
    "HELDOUT_PROVIDER_CANDIDATE_IDS_V22",
    "NAIVE_LEDGER_FILENAME_V22",
    "NAIVE_SLOT_COUNT_V22",
    "PROTOCOL_VERSION_V22",
    "SCHEMA_VERSION_V22",
    "SECURE_CANONICAL_SLOT_COUNT_V22",
    "SECURE_HELDOUT_SLOT_COUNT_V22",
    "SECURE_LEDGER_FILENAME_V22",
    "SECURE_SLOT_COUNT_V22",
    "TOTAL_PROVIDER_SLOT_COUNT_V22",
]
