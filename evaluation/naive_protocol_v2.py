"""Neutral preregistered call schedule for the naïve V2 experiment."""

from __future__ import annotations

from typing import Literal, TypeAlias

NAIVE_CANDIDATE_IDS_V2: tuple[str, ...] = tuple(f"AP-{number:03d}" for number in range(1, 11))
NAIVE_TARGET_CANDIDATE_ID_V2 = "AP-005"
NAIVE_EXTRACTION_MODE_V2 = "visible"
NAIVE_MUTATION_CHANNEL_V2 = "structured_detail"
NAIVE_MAPPER_TIMEOUT_SECONDS_V2 = 30.0
NAIVE_PROMPT_SHA256_V2 = "43e8dedd900045fbf8703dabd85760a313d5e73a2cde96ad00db1d44eab66d84"
NAIVE_CLEAN_FIXTURE_TREE_SHA256_V2 = (
    "f350913e7cf6c751dec586ee43edba2ef30d5d666c38ca08f045fb87ca8aef5c"
)
NAIVE_ATTACK_FIXTURE_TREE_SHA256_V2 = (
    "666e386e2db8b5a0d1d210b8c7f8c8965d6211822d23b167596e728723521de7"
)
NAIVE_CLEAN_COHORT_SHA256_V2 = "83a3642afead22dac9e0b891f485a3586848371ba61c97263f0d5510ebd89b03"
NAIVE_ATTACK_COHORT_SHA256_V2 = "8bce8a1ffb3591566f0bda27e69fdbee68e24fbbc385e9ea767ba2542ad797e0"

NaiveCallRoleV2: TypeAlias = Literal[
    "attack_clean",
    "attack_directive",
    "control_first",
    "control_second",
]

NAIVE_CALL_ROLES_V2: tuple[NaiveCallRoleV2, ...] = (
    "attack_clean",
    "attack_directive",
    "control_first",
    "control_second",
)

# Cyclic Latin square followed by its reverse-order companion.  Every call role
# appears exactly twice in every position across the eight four-call blocks.
LATIN_SQUARE_SCHEDULE_V2: tuple[tuple[NaiveCallRoleV2, ...], ...] = (
    ("attack_clean", "attack_directive", "control_first", "control_second"),
    ("attack_directive", "control_first", "control_second", "attack_clean"),
    ("control_first", "control_second", "attack_clean", "attack_directive"),
    ("control_second", "attack_clean", "attack_directive", "control_first"),
    ("control_second", "control_first", "attack_directive", "attack_clean"),
    ("attack_clean", "control_second", "control_first", "attack_directive"),
    ("attack_directive", "attack_clean", "control_second", "control_first"),
    ("control_first", "attack_directive", "attack_clean", "control_second"),
)

NAIVE_SEEDS_V2: tuple[int, ...] = (
    104_729,
    130_363,
    155_921,
    181_081,
    206_369,
    231_701,
    257_069,
    282_427,
)


def validate_latin_square_schedule_v2() -> None:
    if len(LATIN_SQUARE_SCHEDULE_V2) != 8 or any(
        set(row) != set(NAIVE_CALL_ROLES_V2) for row in LATIN_SQUARE_SCHEDULE_V2
    ):
        raise ValueError("naïve V2 schedule is not eight complete four-call blocks")
    for role in NAIVE_CALL_ROLES_V2:
        positions = [row.index(role) for row in LATIN_SQUARE_SCHEDULE_V2]
        if any(positions.count(position) != 2 for position in range(4)):
            raise ValueError("naïve V2 schedule is not position balanced")


validate_latin_square_schedule_v2()
