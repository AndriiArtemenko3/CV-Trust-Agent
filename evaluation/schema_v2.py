"""Mechanical JSON Schema export for the four public V2 evidence artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, cast

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from evaluation.aggregate_v2 import ReleaseManifestV2
from evaluation.naive_release_v2 import NaiveAttemptV2
from evaluation.oracle_spec_v2 import DETERMINISTIC_ARTIFACT_KIND_V2
from evaluation.release_spec_v2 import DecisionProjectionV2, Digest, Token
from evaluation.secure_release_v2 import (
    AttemptFailureV2,
    AttemptMetadataV2,
    HeldoutAttemptV2,
)


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class _DeterministicCaseSchemaV2(_StrictModel):
    case_name: Token
    fixture_id: Token
    fixture_tree_sha256: Digest
    projection: DecisionProjectionV2


class _DeterministicArtifactSchemaV2(_StrictModel):
    schema_version: Literal[2]
    artifact_kind: Literal["deterministic_observations_v2"]
    oracle_sha256: Digest
    implementation_tree_sha256: Digest
    observations: tuple[_DeterministicCaseSchemaV2, ...] = Field(
        min_length=25,
        max_length=25,
    )


class _CanonicalDecisionSchemaV2(_StrictModel):
    kind: Literal["decision"]
    projection: DecisionProjectionV2


class _CanonicalAttemptSchemaV2(AttemptMetadataV2):
    schema_version: Literal[2]
    event: Literal["secure_canonical_attempt_v2"]
    arm: Literal["canonical"]
    result: _CanonicalDecisionSchemaV2 | AttemptFailureV2 = Field(discriminator="kind")


def v2_evidence_schemas() -> dict[str, dict[str, object]]:
    """Return schemas generated from the same strict types used at release."""

    secure_schema = cast(
        dict[str, object],
        TypeAdapter(_CanonicalAttemptSchemaV2 | HeldoutAttemptV2).json_schema(),
    )
    manifest_schema = cast(dict[str, object], ReleaseManifestV2.model_json_schema())
    _close_source_policy_schema_v2(secure_schema, manifest_schema)
    schemas = {
        "deterministic-v2.schema.json": _DeterministicArtifactSchemaV2.model_json_schema(),
        "secure-v2-row.schema.json": secure_schema,
        "naive-v2-row.schema.json": NaiveAttemptV2.model_json_schema(),
        "manifest-v2.schema.json": manifest_schema,
    }
    for filename, schema in schemas.items():
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schema["$id"] = f"https://cv-trust-agent.invalid/evidence/schema/{filename}"
    return schemas


def _close_source_policy_schema_v2(
    secure_schema: dict[str, object],
    manifest_schema: dict[str, object],
) -> None:
    """Render arm-specific custom validators into the public JSON Schemas."""

    secure_defs = cast(dict[str, object], secure_schema["$defs"])
    canonical = cast(dict[str, object], secure_defs["_CanonicalAttemptSchemaV2"])
    canonical_properties = cast(dict[str, object], canonical["properties"])
    canonical_properties["source_timeout_seconds"] = {
        "const": 0.5,
        "type": "number",
    }
    canonical_properties["source_max_attempts"] = {"const": 1, "type": "integer"}
    canonical_required = cast(list[str], canonical["required"])
    canonical_required.extend(("source_timeout_seconds", "source_max_attempts"))

    heldout = cast(dict[str, object], secure_defs["HeldoutAttemptV2"])
    heldout_properties = cast(dict[str, object], heldout["properties"])
    heldout_properties["source_timeout_seconds"] = {"type": "null", "default": None}
    heldout_properties["source_max_attempts"] = {"type": "null", "default": None}

    manifest_defs = cast(dict[str, object], manifest_schema["$defs"])
    manifest_arm = cast(dict[str, object], manifest_defs["SecureArmEntryV2"])
    manifest_arm["allOf"] = [
        {
            "if": {"properties": {"arm": {"const": "canonical"}}, "required": ["arm"]},
            "then": {
                "properties": {
                    "source_timeout_seconds": {"const": 0.5, "type": "number"},
                    "source_max_attempts": {"const": 1, "type": "integer"},
                },
                "required": ["source_timeout_seconds", "source_max_attempts"],
            },
            "else": {
                "properties": {
                    "source_timeout_seconds": {"type": "null"},
                    "source_max_attempts": {"type": "null"},
                }
            },
        }
    ]


def write_v2_evidence_schemas(
    schema_directory: Path, *, overwrite: bool = False
) -> tuple[Path, ...]:
    """Write deterministic canonical schema bytes; refuse accidental overwrite."""

    schema_directory.mkdir(parents=True, exist_ok=True)
    outputs: list[Path] = []
    for filename, schema in sorted(v2_evidence_schemas().items()):
        target = schema_directory / filename
        if target.exists() and not overwrite:
            raise FileExistsError(f"V2 evidence schema already exists: {filename}")
        target.write_text(
            json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        outputs.append(target)
    return tuple(outputs)


if DETERMINISTIC_ARTIFACT_KIND_V2 != "deterministic_observations_v2":
    raise RuntimeError("V2 deterministic schema kind drifted")
