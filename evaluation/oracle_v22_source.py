"""Human-auditable source for the frozen deterministic V2.2 release oracle.

The 25-case suite, its policy-derived routes, explanations, command
expectations, and the 47 invariants are carried mechanically from the frozen,
hash-audited V2 oracle (``oracle_v2.json``): the documented AP evidence policy
did not change in V2.2, only the projection envelope and digest domains did.
This module rewraps that structure with ``schema_version: 3`` and
``protocol_version: "2.2"`` and replaces each exact case's single V2 semantic
commitment with the two frozen V2.2 commitments below: the action-semantic
digest and the audit digest, both captured through the public ``serve``/``run``
commands against the corrected tree and reproducible byte for byte.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from evaluation.oracle_spec_v2 import load_deterministic_oracle_v2
from evaluation.oracle_spec_v22 import (
    DeterministicOracleV22,
    load_deterministic_oracle_v22,
    oracle_sha256_v22,
)
from evaluation.release_spec_v2 import JsonObject, canonical_json_bytes

# Frozen (action_semantic_sha256, audit_sha256) commitments for the nine
# independently specified exact cases; equal-to cases inherit their reference.
_V22_EXACT_DIGESTS: dict[str, tuple[str, str]] = {
    "clean": (
        "4f9b8317d993199319eb01d1aa8b4359432ab9db5fde532b56a4944373a2ddf7",
        "eddc265c0f3b73ba49fcd2037aa98a67008825f8d0b35197f09303d07bb3d60d",
    ),
    "semantic_no_directive": (
        "d68434b21f8d01d4be9e3d5d0c9e5ee6cd2c4497df873b46b9cbad625afff46f",
        "e8d37c7cc4ba952be56420c9206b0fed2b3636ffa9db1ea22bcc5db9096f9f6f",
    ),
    "cv_substitution": (
        "c6f37e48b3e6c65494d72ffba32497fa9abe0000d3cb381ee65de2e9a7f9c8dc",
        "7586ada963b0af56339987bdfcdaf444e7f53b08572c296d45242e28c8188f4d",
    ),
    "index_manifest_invalid": (
        "6d135eaeb48fc306748c4952c9a4363d0ce57fe0caacc4109c328d78e5f2269c",
        "b5bdbd55151bd6dfa536715d4cadb1ab41f84f8caa8a4b9f8382013908c2e716",
    ),
    "mapper_disagreement_only": (
        "f206061d36052ec28bc444b30151bf5edac7c90fa51e7b99564f5f313915c5d7",
        "110e37fce283c741902af3a9935419899fd8cf761cd497d543b989f67b1bfa61",
    ),
    "detail_timeout": (
        "6b28573ae7b01f345f52796574713d3a90f3fccb140cda67d4293253ee7d8b8f",
        "8ef87296f0d30710dfaf1375290810e173583070872f9a0341de3586f99c7e9c",
    ),
    "compound": (
        "88ba1d3590a4d7b1589fa1b1a17e954e06b9de719f13eba84ca226dd8fc7a54b",
        "9b9ff32be48da765c4f68cbd0ca37c1654c402abd70de89f91f6069b269edc53",
    ),
    "unseen_clean": (
        "a5043c302a734ba234d455e5672e2b9dbb2e5d563d5a9a58022ed19fd630aa78",
        "c8eaacaf4be56799e09507221c00725423f5c750a04ee4083ab042bdb3ba54ad",
    ),
    "unseen_semantic_conflict": (
        "822ee5d5e1ec4a3a09daa2bf0f701799dd5b6be11a69ca5511a087ee2ba3cd78",
        "c00acdfa34df23b254bd33e404fdb814bf1df8a1a91cec99ab18571686ba1bdc",
    ),
}


def release_oracle_v22_object(v2_oracle_path: Path) -> JsonObject:
    """Mechanically rewrap the frozen V2 oracle as the V2.2 oracle object."""

    v2_oracle = load_deterministic_oracle_v2(v2_oracle_path)
    raw = cast(JsonObject, v2_oracle.model_dump(mode="json", exclude_none=False))
    raw["schema_version"] = 3
    raw["protocol_version"] = "2.2"
    raw["suite_id"] = "release_v22"
    exact_names: set[str] = set()
    for case in cast(list[JsonObject], raw["cases"]):
        expectation = cast(JsonObject, case["expectation"])
        if expectation.get("kind") != "exact":
            continue
        name = cast(str, case["name"])
        exact_names.add(name)
        action_digest, audit_digest = _V22_EXACT_DIGESTS[name]
        expectation.pop("decision_semantic_sha256", None)
        expectation["decision_action_sha256"] = action_digest
        expectation["decision_audit_sha256"] = audit_digest
    if exact_names != set(_V22_EXACT_DIGESTS):
        raise ValueError("V2.2 digest table does not match the frozen exact case set")
    return raw


def write_frozen_release_oracle_v22(
    output_path: Path,
    *,
    v2_oracle_path: Path,
) -> DeterministicOracleV22:
    """Write ``oracle_v22.json`` and prove it revalidates before returning."""

    raw = release_oracle_v22_object(v2_oracle_path)
    output_path.write_bytes(canonical_json_bytes(raw) + b"\n")
    oracle = load_deterministic_oracle_v22(output_path)
    digest = oracle_sha256_v22(oracle)
    if not digest:
        raise ValueError("V2.2 oracle digest is empty")
    return oracle


def frozen_release_oracle_matches_v22(oracle_path: Path, v2_oracle_path: Path) -> bool:
    """Report whether the frozen file equals its mechanical derivation."""

    derived = canonical_json_bytes(release_oracle_v22_object(v2_oracle_path)) + b"\n"
    return oracle_path.read_bytes() == derived


if __name__ == "__main__":  # pragma: no cover - explicit regeneration entry
    repository = Path(__file__).resolve().parent.parent
    result = write_frozen_release_oracle_v22(
        repository / "evaluation" / "oracle_v22.json",
        v2_oracle_path=repository / "evaluation" / "oracle_v2.json",
    )
    print(json.dumps({"suite_id": result.suite_id, "cases": len(result.cases)}))
