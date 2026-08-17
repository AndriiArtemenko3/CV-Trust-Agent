"""Transitive V2 release-bundle validation over semantic validators only."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Literal, cast

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from evaluation.deterministic_release_v2 import (
    RELEASE_ARTIFACT_INVARIANT_COUNT_V2,
    RELEASE_PROPERTY_GATE_COUNT_V2,
    RELEASE_TOTAL_GATE_COUNT_V2,
    ValidatedDeterministicReleaseV2,
    validate_deterministic_release_v2,
)
from evaluation.naive_release_v2 import (
    ValidatedNaiveReleaseV2,
    validate_naive_semantics_v2,
)
from evaluation.property_gate_runner import (
    PropertyGateRunnerError,
    execute_property_gate_nodes,
)
from evaluation.release_spec_v2 import (
    Digest,
    SafeMetadataLabel,
    canonical_json_bytes,
    implementation_tree_sha256_v2,
    load_strict_json_object,
    release_implementation_paths_v2,
)
from evaluation.secure_release_v2 import (
    ValidatedSecureReleaseV2,
    validate_secure_semantics_v2,
)

_MAX_MANIFEST_BYTES = 256 * 1024
_EXPECTED_ARTIFACTS = {
    "deterministic": "deterministic-v2.json",
    "secure": "secure-v2.jsonl",
    "naive": "naive-v2.jsonl",
}
_CANONICAL_DETERMINISTIC_ORACLE = Path("evaluation/oracle_v2.json")
_CANONICAL_HELDOUT_ORACLE = Path("evaluation/heldout_release_oracle_v2.json")
_PROPERTY_GATE_FAMILIES_V2 = (
    (
        "unseen_identity_renaming_and_input_permutation",
        (
            "tests/test_unseen_generalization.py::"
            "test_unseen_property_safe_id_renaming_preserves_rank_semantics",
            "tests/test_unseen_generalization.py::"
            "test_unseen_property_safe_id_renaming_changes_display_only_inside_exact_ties",
            "tests/test_unseen_generalization.py::"
            "test_unseen_property_input_permutation_is_fully_invariant",
        ),
    ),
    (
        "unseen_value_equivalence_and_composed_transform",
        (
            "tests/test_unseen_generalization.py::"
            "test_unseen_property_non_threshold_value_variation_is_invariant",
            "tests/test_unseen_generalization.py::"
            "test_unseen_property_renaming_permutation_and_value_variation_compose",
        ),
    ),
)
_PROPERTY_GATE_NAMES_V2 = tuple(name for name, _node_ids in _PROPERTY_GATE_FAMILIES_V2)


class AggregateV2Error(ValueError):
    """A V2 release manifest or one of its transitive inputs is invalid."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ArtifactEntryV2(_StrictModel):
    kind: Literal["deterministic", "secure", "naive"]
    path: Literal["deterministic-v2.json", "secure-v2.jsonl", "naive-v2.jsonl"]
    sha256: Digest


class SecureArmEntryV2(_StrictModel):
    arm: Literal["canonical", "heldout"]
    model_identifier: SafeMetadataLabel
    sdk_version: SafeMetadataLabel
    prompt_sha256: Digest
    source_timeout_seconds: float | None = Field(default=None, gt=0, le=60)
    source_max_attempts: Literal[1] | None = None
    mapper_timeout_seconds: float = Field(gt=0, le=600)
    mapper_max_retries: Literal[0]

    @model_validator(mode="after")
    def source_policy_matches_arm(self) -> SecureArmEntryV2:
        if self.arm == "canonical":
            if self.source_timeout_seconds != 0.5 or self.source_max_attempts != 1:
                raise ValueError("canonical manifest arm requires the frozen source policy")
        elif self.source_timeout_seconds is not None or self.source_max_attempts is not None:
            raise ValueError("held-out manifest arm cannot carry a source policy")
        return self


class ReleaseManifestV2(_StrictModel):
    schema_version: Literal[2]
    artifact_kind: Literal["release_manifest_v2"]
    generated_at: AwareDatetime
    implementation_tree_sha256: Digest
    deterministic_oracle_sha256: Digest
    heldout_oracle_sha256: Digest
    artifacts: tuple[ArtifactEntryV2, ...] = Field(min_length=3, max_length=3)
    secure_arm_configurations: tuple[SecureArmEntryV2, ...] = Field(min_length=2, max_length=2)

    @model_validator(mode="after")
    def arms_are_complete(self) -> ReleaseManifestV2:
        if {item.arm for item in self.secure_arm_configurations} != {
            "canonical",
            "heldout",
        }:
            raise ValueError("release manifest must commit both secure arms")
        return self


@dataclass(frozen=True, slots=True)
class ValidatedAggregateV2:
    manifest_sha256: str
    implementation_tree_sha256: str
    deterministic: ValidatedDeterministicReleaseV2
    secure: ValidatedSecureReleaseV2
    naive: ValidatedNaiveReleaseV2
    artifact_invariant_count: int
    property_gate_count: int
    total_release_gate_count: int
    property_gate_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PropertyGateReportV2:
    """Observed execution of the two evaluator-owned metamorphic families."""

    names: tuple[str, ...]
    artifact_invariant_count: int
    property_gate_count: int
    total_release_gate_count: int


def canonical_oracle_paths_v2(repository_root: Path) -> tuple[Path, Path]:
    """Return the only oracle paths admissible at the public release boundary."""

    root = repository_root.resolve()
    return (
        (root / _CANONICAL_DETERMINISTIC_ORACLE).resolve(),
        (root / _CANONICAL_HELDOUT_ORACLE).resolve(),
    )


def _require_canonical_oracle_paths_v2(
    repository_root: Path,
    deterministic_oracle_path: Path,
    heldout_oracle_path: Path,
) -> tuple[Path, Path]:
    expected_deterministic, expected_heldout = canonical_oracle_paths_v2(repository_root)
    if (
        deterministic_oracle_path.resolve() != expected_deterministic
        or heldout_oracle_path.resolve() != expected_heldout
    ):
        raise AggregateV2Error("V2 release requires the canonical repository oracles")
    return expected_deterministic, expected_heldout


def _validate_named_fixture_bindings(
    deterministic: ValidatedDeterministicReleaseV2,
    secure: ValidatedSecureReleaseV2,
    naive: ValidatedNaiveReleaseV2,
) -> None:
    """Cross-bind experimental arms to independently named fixture commitments."""

    expected_clean_fixture = deterministic.fixture_tree_sha256("clean")
    expected_directive_fixture = deterministic.fixture_tree_sha256("structured_note_directive")
    expected_secure = tuple(
        sorted(
            {
                "clean": expected_clean_fixture,
                "directive": expected_directive_fixture,
            }.items()
        )
    )
    if secure.canonical_fixture_commitments != expected_secure:
        raise AggregateV2Error("secure canonical fixtures are not deterministic-case bound")
    if (
        naive.clean_fixture_tree_sha256 != expected_clean_fixture
        or naive.attack_fixture_tree_sha256 != expected_directive_fixture
    ):
        raise AggregateV2Error("naïve fixtures are not bound to named deterministic cases")


def write_release_manifest_v2(
    evidence_directory: Path,
    *,
    deterministic_oracle_path: Path,
    heldout_oracle_path: Path,
    repository_root: Path,
    generated_at: datetime | None = None,
) -> Path:
    """Semantically validate three captures, then atomically commit their manifest."""

    deterministic_oracle_path, heldout_oracle_path = _require_canonical_oracle_paths_v2(
        repository_root,
        deterministic_oracle_path,
        heldout_oracle_path,
    )

    artifact_paths = {
        kind: evidence_directory / filename for kind, filename in _EXPECTED_ARTIFACTS.items()
    }
    if any(not path.is_file() for path in artifact_paths.values()):
        raise AggregateV2Error("V2 manifest writer requires the exact three artifacts")
    deterministic = validate_deterministic_release_v2(
        artifact_paths["deterministic"], deterministic_oracle_path
    )
    secure = validate_secure_semantics_v2(
        artifact_paths["secure"],
        deterministic_release=deterministic,
        heldout_oracle_path=heldout_oracle_path,
    )
    naive = validate_naive_semantics_v2(artifact_paths["naive"])
    current_hash = implementation_tree_sha256_v2(
        release_implementation_paths_v2(repository_root),
        repository_root=repository_root,
    )
    if {
        deterministic.implementation_tree_sha256,
        secure.implementation_tree_sha256,
        naive.implementation_tree_sha256,
    } != {current_hash}:
        raise AggregateV2Error("V2 captures are stale or use mixed implementation trees")
    _validate_named_fixture_bindings(deterministic, secure, naive)
    timestamp = generated_at or datetime.now(UTC)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise AggregateV2Error("V2 manifest timestamp must be timezone aware")
    manifest = ReleaseManifestV2(
        schema_version=2,
        artifact_kind="release_manifest_v2",
        generated_at=timestamp,
        implementation_tree_sha256=current_hash,
        deterministic_oracle_sha256=deterministic.oracle_sha256,
        heldout_oracle_sha256=secure.heldout_oracle_sha256,
        artifacts=tuple(
            ArtifactEntryV2(
                kind=cast(Literal["deterministic", "secure", "naive"], kind),
                path=cast(
                    Literal["deterministic-v2.json", "secure-v2.jsonl", "naive-v2.jsonl"],
                    _EXPECTED_ARTIFACTS[kind],
                ),
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
            )
            for kind, path in artifact_paths.items()
        ),
        secure_arm_configurations=tuple(
            SecureArmEntryV2(
                arm=cast(Literal["canonical", "heldout"], item.arm),
                model_identifier=item.model_identifier,
                sdk_version=item.sdk_version,
                prompt_sha256=item.prompt_sha256,
                source_timeout_seconds=item.source_timeout_seconds,
                source_max_attempts=cast(Literal[1] | None, item.source_max_attempts),
                mapper_timeout_seconds=item.mapper_timeout_seconds,
                mapper_max_retries=cast(Literal[0], item.mapper_max_retries),
            )
            for item in secure.arm_configurations
        ),
    )
    output = evidence_directory / "manifest-v2.json"
    if output.exists():
        raise FileExistsError("V2 release manifest already exists")
    evidence_directory.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with NamedTemporaryFile(
            mode="wb",
            dir=evidence_directory,
            prefix=".manifest-v2-",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(
                canonical_json_bytes(manifest.model_dump(mode="json", exclude_none=False)) + b"\n"
            )
            temporary.flush()
            os.fsync(temporary.fileno())
        os.link(temporary_name, output)
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)
    return output


def validate_aggregate_v2(
    manifest_path: Path,
    *,
    deterministic_oracle_path: Path,
    heldout_oracle_path: Path,
    repository_root: Path,
    execute_property_gates: bool = True,
    require_secure_hard_gate: bool = True,
) -> ValidatedAggregateV2:
    """Revalidate every component and the current code tree before release."""

    deterministic_oracle_path, heldout_oracle_path = _require_canonical_oracle_paths_v2(
        repository_root,
        deterministic_oracle_path,
        heldout_oracle_path,
    )

    raw = load_strict_json_object(manifest_path, maximum_bytes=_MAX_MANIFEST_BYTES)
    try:
        manifest = ReleaseManifestV2.model_validate_json(
            json.dumps(raw, sort_keys=True, separators=(",", ":"))
        )
    except Exception as exc:
        raise AggregateV2Error("V2 release manifest is invalid") from exc
    entries: dict[str, ArtifactEntryV2] = {
        cast(str, item.kind): item for item in manifest.artifacts
    }
    if len(entries) != 3 or any(
        entries[kind].path != expected for kind, expected in _EXPECTED_ARTIFACTS.items()
    ):
        raise AggregateV2Error("V2 release manifest does not bind the exact three artifacts")
    evidence_root = manifest_path.resolve().parent
    artifact_paths: dict[str, Path] = {}
    for kind, entry in entries.items():
        target = (evidence_root / entry.path).resolve()
        if target.parent != evidence_root or not target.is_file():
            raise AggregateV2Error("V2 release artifact is missing or escapes its directory")
        if hashlib.sha256(target.read_bytes()).hexdigest() != entry.sha256:
            raise AggregateV2Error("V2 release artifact hash differs from the manifest")
        artifact_paths[kind] = target

    deterministic = validate_deterministic_release_v2(
        artifact_paths["deterministic"], deterministic_oracle_path
    )
    secure = validate_secure_semantics_v2(
        artifact_paths["secure"],
        deterministic_release=deterministic,
        heldout_oracle_path=heldout_oracle_path,
    )
    if require_secure_hard_gate and not secure.hard_gate_passed:
        raise AggregateV2Error("secure release hard gate did not pass")
    naive = validate_naive_semantics_v2(artifact_paths["naive"])
    _validate_named_fixture_bindings(deterministic, secure, naive)
    if manifest.deterministic_oracle_sha256 != deterministic.oracle_sha256:
        raise AggregateV2Error("manifest deterministic oracle commitment differs")
    if manifest.heldout_oracle_sha256 != secure.heldout_oracle_sha256:
        raise AggregateV2Error("manifest held-out oracle commitment differs")
    observed_arm_configurations = {item.arm: item for item in secure.arm_configurations}
    if any(
        arm.model_dump(mode="json")
        != {
            "arm": observed_arm_configurations[arm.arm].arm,
            "model_identifier": observed_arm_configurations[arm.arm].model_identifier,
            "sdk_version": observed_arm_configurations[arm.arm].sdk_version,
            "prompt_sha256": observed_arm_configurations[arm.arm].prompt_sha256,
            "source_timeout_seconds": observed_arm_configurations[arm.arm].source_timeout_seconds,
            "source_max_attempts": observed_arm_configurations[arm.arm].source_max_attempts,
            "mapper_timeout_seconds": observed_arm_configurations[arm.arm].mapper_timeout_seconds,
            "mapper_max_retries": observed_arm_configurations[arm.arm].mapper_max_retries,
        }
        for arm in manifest.secure_arm_configurations
    ):
        raise AggregateV2Error("manifest secure-arm configuration differs from evidence")
    component_hashes = {
        deterministic.implementation_tree_sha256,
        secure.implementation_tree_sha256,
        naive.implementation_tree_sha256,
        manifest.implementation_tree_sha256,
    }
    if len(component_hashes) != 1:
        raise AggregateV2Error("V2 release components use different implementation trees")
    current_hash = implementation_tree_sha256_v2(
        release_implementation_paths_v2(repository_root),
        repository_root=repository_root,
    )
    if current_hash != manifest.implementation_tree_sha256:
        raise AggregateV2Error("V2 evidence is stale relative to the current implementation")
    property_report = (
        execute_property_gate_families_v2(repository_root)
        if execute_property_gates
        else PropertyGateReportV2(
            names=(),
            artifact_invariant_count=RELEASE_ARTIFACT_INVARIANT_COUNT_V2,
            property_gate_count=0,
            total_release_gate_count=RELEASE_ARTIFACT_INVARIANT_COUNT_V2,
        )
    )
    property_gate_names = property_report.names
    property_gates_complete = (
        execute_property_gates
        and property_gate_names == _PROPERTY_GATE_NAMES_V2
        and len(property_gate_names) == RELEASE_PROPERTY_GATE_COUNT_V2
    )
    if execute_property_gates and not property_gates_complete:
        raise AggregateV2Error("V2 property-gate families were not completely executed")
    if execute_property_gates:
        post_property_hash = implementation_tree_sha256_v2(
            release_implementation_paths_v2(repository_root),
            repository_root=repository_root,
        )
        if (
            post_property_hash != current_hash
            or post_property_hash != manifest.implementation_tree_sha256
        ):
            raise AggregateV2Error("V2 implementation tree changed during property-gate execution")
    if deterministic.artifact_invariant_count != RELEASE_ARTIFACT_INVARIANT_COUNT_V2:
        raise AggregateV2Error("V2 deterministic artifact invariant count is incomplete")
    return ValidatedAggregateV2(
        manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        implementation_tree_sha256=current_hash,
        deterministic=deterministic,
        secure=secure,
        naive=naive,
        artifact_invariant_count=deterministic.artifact_invariant_count,
        property_gate_count=len(property_gate_names),
        total_release_gate_count=(
            deterministic.artifact_invariant_count + len(property_gate_names)
        ),
        property_gate_names=property_gate_names,
    )


def execute_property_gate_families_v2(repository_root: Path) -> PropertyGateReportV2:
    """Run and report the two independently executed V2 property families."""

    names = _execute_property_gate_families(repository_root)
    return PropertyGateReportV2(
        names=names,
        artifact_invariant_count=RELEASE_ARTIFACT_INVARIANT_COUNT_V2,
        property_gate_count=len(names),
        total_release_gate_count=RELEASE_ARTIFACT_INVARIANT_COUNT_V2 + len(names),
    )


def validate_property_gate_families_v2(repository_root: Path) -> tuple[str, ...]:
    """Stable CLI seam returning the two successfully executed family names."""

    return execute_property_gate_families_v2(repository_root).names


def _execute_property_gate_families(repository_root: Path) -> tuple[str, ...]:
    """Execute two named metamorphic families; accept no producer verdicts."""

    completed_names: list[str] = []
    for family_name, node_ids in _PROPERTY_GATE_FAMILIES_V2:
        try:
            execute_property_gate_nodes(repository_root, node_ids)
        except PropertyGateRunnerError as exc:
            raise AggregateV2Error(f"V2 property-gate family failed: {family_name}") from exc
        completed_names.append(family_name)
    if len(completed_names) != RELEASE_PROPERTY_GATE_COUNT_V2 or (
        len(completed_names) + RELEASE_ARTIFACT_INVARIANT_COUNT_V2 != RELEASE_TOTAL_GATE_COUNT_V2
    ):
        raise AggregateV2Error("V2 composite release-gate accounting is invalid")
    return tuple(completed_names)
