"""Transitive V2.2 release-bundle validation over semantic validators only.

Integrity and release are deliberately separate: the manifest writer commits a
red run's evidence with full integrity binding, while public validation and
rendering require ``release_green`` (every secure and naïve hard gate).
"""

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

from evaluation.deterministic_release_v22 import (
    RELEASE_ARTIFACT_INVARIANT_COUNT_V22,
    RELEASE_PROPERTY_GATE_COUNT_V22,
    RELEASE_TOTAL_GATE_COUNT_V22,
    ValidatedDeterministicReleaseV22,
    validate_deterministic_release_v22,
)
from evaluation.naive_release_v22 import (
    ValidatedNaiveReleaseV22,
    validate_naive_semantics_v22,
)
from evaluation.property_gate_runner import (
    PropertyGateRunnerError,
    execute_property_gate_nodes,
)
from evaluation.protocol_v22 import (
    FROZEN_RUN_ID_V22,
    NAIVE_LEDGER_FILENAME_V22,
    SECURE_LEDGER_FILENAME_V22,
    SECURE_SLOT_COUNT_V22,
    TOTAL_PROVIDER_SLOT_COUNT_V22,
)
from evaluation.release_spec_v2 import (
    Digest,
    SafeMetadataLabel,
    canonical_json_bytes,
    implementation_tree_sha256_v2,
    load_strict_json_object,
    release_implementation_paths_v2,
)
from evaluation.secure_release_v22 import (
    ValidatedSecureReleaseV22,
    validate_secure_semantics_v22,
)
from evaluation.slot_ledger_v22 import (
    ValidatedSlotLedgerV22,
    validate_slot_ledger_v22,
)

_MAX_MANIFEST_BYTES = 256 * 1024
_EXPECTED_ARTIFACTS = {
    "deterministic": "deterministic-v22.json",
    "secure": "secure-v22.jsonl",
    "naive": "naive-v22.jsonl",
    "secure_ledger": SECURE_LEDGER_FILENAME_V22,
    "naive_ledger": NAIVE_LEDGER_FILENAME_V22,
}
_CANONICAL_DETERMINISTIC_ORACLE = Path("evaluation/oracle_v22.json")
_CANONICAL_HELDOUT_ORACLE = Path("evaluation/heldout_release_oracle_v22.json")
_PROPERTY_GATE_FAMILIES_V22 = (
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
_PROPERTY_GATE_NAMES_V22 = tuple(name for name, _node_ids in _PROPERTY_GATE_FAMILIES_V22)


class AggregateV22Error(ValueError):
    """A V2.2 release manifest or one of its transitive inputs is invalid."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ArtifactEntryV22(_StrictModel):
    kind: Literal["deterministic", "secure", "naive", "secure_ledger", "naive_ledger"]
    path: Literal[
        "deterministic-v22.json",
        "secure-v22.jsonl",
        "naive-v22.jsonl",
        "secure-slots-v22.jsonl",
        "naive-slots-v22.jsonl",
    ]
    sha256: Digest
    final_chain_sha256: Digest | None = None
    slot_count: int | None = Field(default=None, ge=1, le=116)

    @model_validator(mode="after")
    def ledger_metadata_is_atomic(self) -> ArtifactEntryV22:
        is_ledger = self.kind in {"secure_ledger", "naive_ledger"}
        if is_ledger != (self.final_chain_sha256 is not None and self.slot_count is not None):
            raise ValueError("only ledger artifacts carry final chain metadata")
        return self


class SecureArmEntryV22(_StrictModel):
    arm: Literal["canonical", "heldout"]
    model_identifier: SafeMetadataLabel
    sdk_version: SafeMetadataLabel
    prompt_sha256: Digest
    source_timeout_seconds: float | None = Field(default=None, gt=0, le=60)
    source_max_attempts: Literal[1] | None = None
    mapper_timeout_seconds: float = Field(gt=0, le=600)
    mapper_max_retries: Literal[0]

    @model_validator(mode="after")
    def source_policy_matches_arm(self) -> SecureArmEntryV22:
        if self.arm == "canonical":
            if self.source_timeout_seconds != 0.5 or self.source_max_attempts != 1:
                raise ValueError("canonical manifest arm requires the frozen source policy")
        elif self.source_timeout_seconds is not None or self.source_max_attempts is not None:
            raise ValueError("held-out manifest arm cannot carry a source policy")
        return self


class ReleaseManifestV22(_StrictModel):
    schema_version: Literal[3]
    protocol_version: Literal["2.2"]
    artifact_kind: Literal["release_manifest_v22"]
    run_id: Literal["v24-20260817-r1"]
    generated_at: AwareDatetime
    implementation_tree_sha256: Digest
    deterministic_oracle_sha256: Digest
    heldout_oracle_sha256: Digest
    artifacts: tuple[ArtifactEntryV22, ...] = Field(min_length=5, max_length=5)
    secure_arm_configurations: tuple[SecureArmEntryV22, ...] = Field(min_length=2, max_length=2)

    @model_validator(mode="after")
    def arms_are_complete(self) -> ReleaseManifestV22:
        if {item.arm for item in self.secure_arm_configurations} != {
            "canonical",
            "heldout",
        }:
            raise ValueError("release manifest must commit both secure arms")
        return self


@dataclass(frozen=True, slots=True)
class ValidatedAggregateV22:
    manifest_sha256: str
    run_id: str
    implementation_tree_sha256: str
    deterministic: ValidatedDeterministicReleaseV22
    secure: ValidatedSecureReleaseV22
    naive: ValidatedNaiveReleaseV22
    secure_ledger: ValidatedSlotLedgerV22
    naive_ledger: ValidatedSlotLedgerV22
    provider_slot_count: int
    artifact_invariant_count: int
    property_gate_count: int
    total_release_gate_count: int
    property_gate_names: tuple[str, ...]
    integrity_valid: bool
    release_green: bool


@dataclass(frozen=True, slots=True)
class PropertyGateReportV22:
    """Observed execution of the two evaluator-owned metamorphic families."""

    names: tuple[str, ...]
    artifact_invariant_count: int
    property_gate_count: int
    total_release_gate_count: int


def canonical_oracle_paths_v22(repository_root: Path) -> tuple[Path, Path]:
    """Return the only oracle paths admissible at the public release boundary."""

    root = repository_root.resolve()
    return (
        (root / _CANONICAL_DETERMINISTIC_ORACLE).resolve(),
        (root / _CANONICAL_HELDOUT_ORACLE).resolve(),
    )


def _require_canonical_oracle_paths_v22(
    repository_root: Path,
    deterministic_oracle_path: Path,
    heldout_oracle_path: Path,
) -> tuple[Path, Path]:
    expected_deterministic, expected_heldout = canonical_oracle_paths_v22(repository_root)
    if (
        deterministic_oracle_path.resolve() != expected_deterministic
        or heldout_oracle_path.resolve() != expected_heldout
    ):
        raise AggregateV22Error("V2.2 release requires the canonical repository oracles")
    return expected_deterministic, expected_heldout


def _validate_named_fixture_bindings(
    deterministic: ValidatedDeterministicReleaseV22,
    secure: ValidatedSecureReleaseV22,
    naive: ValidatedNaiveReleaseV22,
) -> None:
    """Cross-bind experimental arms to independently named fixture commitments."""

    expected_clean_fixture = deterministic.fixture_tree_sha256("clean")
    expected_directive_fixture = deterministic.fixture_tree_sha256("structured_note_directive")
    # The two arms are bound to *independent* named deterministic cases: the
    # secure canonical directive arm keeps the structured_note_directive case,
    # while the V2.4 naive arm registers the structured_note_poisoned case
    # (fabricated typed ap_years 8.0 plus a note directive, one channel).
    expected_naive_attack_fixture = deterministic.fixture_tree_sha256("structured_note_poisoned")
    expected_secure = tuple(
        sorted(
            {
                "clean": expected_clean_fixture,
                "directive": expected_directive_fixture,
            }.items()
        )
    )
    if secure.canonical_fixture_commitments != expected_secure:
        raise AggregateV22Error("secure canonical fixtures are not deterministic-case bound")
    if (
        naive.clean_fixture_tree_sha256 != expected_clean_fixture
        or naive.attack_fixture_tree_sha256 != expected_naive_attack_fixture
    ):
        raise AggregateV22Error("naïve fixtures are not bound to named deterministic cases")


def write_release_manifest_v22(
    evidence_directory: Path,
    *,
    run_id: str,
    deterministic_oracle_path: Path,
    heldout_oracle_path: Path,
    repository_root: Path,
    generated_at: datetime | None = None,
) -> Path:
    """Validate five bound artifacts, then atomically commit their manifest."""

    if run_id != FROZEN_RUN_ID_V22:
        raise AggregateV22Error("alternate V2.2 run IDs are not admissible")
    if evidence_directory.resolve().name != FROZEN_RUN_ID_V22:
        raise AggregateV22Error("V2.2 evidence directory must use the frozen run ID")

    deterministic_oracle_path, heldout_oracle_path = _require_canonical_oracle_paths_v22(
        repository_root,
        deterministic_oracle_path,
        heldout_oracle_path,
    )

    artifact_paths = {
        kind: evidence_directory / filename for kind, filename in _EXPECTED_ARTIFACTS.items()
    }
    if any(not path.is_file() for path in artifact_paths.values()):
        raise AggregateV22Error("V2.2 manifest writer requires the exact five artifacts")
    deterministic = validate_deterministic_release_v22(
        artifact_paths["deterministic"], deterministic_oracle_path
    )
    secure = validate_secure_semantics_v22(
        artifact_paths["secure"],
        deterministic_release=deterministic,
        heldout_oracle_path=heldout_oracle_path,
    )
    naive = validate_naive_semantics_v22(artifact_paths["naive"])
    secure_ledger = validate_slot_ledger_v22(
        artifact_paths["secure_ledger"],
        artifact_path=artifact_paths["secure"],
        ledger_kind="secure",
    )
    naive_ledger = validate_slot_ledger_v22(
        artifact_paths["naive_ledger"],
        artifact_path=artifact_paths["naive"],
        ledger_kind="naive",
    )
    if {
        deterministic.run_id,
        secure.run_id,
        naive.run_id,
        secure_ledger.run_id,
        naive_ledger.run_id,
    } != {FROZEN_RUN_ID_V22}:
        raise AggregateV22Error("V2.2 artifacts use a missing, mixed, or alternate run ID")
    current_hash = implementation_tree_sha256_v2(
        release_implementation_paths_v2(repository_root),
        repository_root=repository_root,
    )
    if {
        deterministic.implementation_tree_sha256,
        secure.implementation_tree_sha256,
        naive.implementation_tree_sha256,
    } != {current_hash}:
        raise AggregateV22Error("V2.2 captures are stale or use mixed implementation trees")
    _validate_named_fixture_bindings(deterministic, secure, naive)
    timestamp = generated_at or datetime.now(UTC)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise AggregateV22Error("V2.2 manifest timestamp must be timezone aware")
    manifest = ReleaseManifestV22(
        schema_version=3,
        protocol_version="2.2",
        artifact_kind="release_manifest_v22",
        run_id=FROZEN_RUN_ID_V22,
        generated_at=timestamp,
        implementation_tree_sha256=current_hash,
        deterministic_oracle_sha256=deterministic.oracle_sha256,
        heldout_oracle_sha256=secure.heldout_oracle_sha256,
        artifacts=tuple(
            ArtifactEntryV22(
                kind=cast(
                    Literal[
                        "deterministic",
                        "secure",
                        "naive",
                        "secure_ledger",
                        "naive_ledger",
                    ],
                    kind,
                ),
                path=cast(
                    Literal[
                        "deterministic-v22.json",
                        "secure-v22.jsonl",
                        "naive-v22.jsonl",
                        "secure-slots-v22.jsonl",
                        "naive-slots-v22.jsonl",
                    ],
                    _EXPECTED_ARTIFACTS[kind],
                ),
                sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                final_chain_sha256=(
                    secure_ledger.final_chain_sha256
                    if kind == "secure_ledger"
                    else naive_ledger.final_chain_sha256
                    if kind == "naive_ledger"
                    else None
                ),
                slot_count=(
                    secure_ledger.slot_count
                    if kind == "secure_ledger"
                    else naive_ledger.slot_count
                    if kind == "naive_ledger"
                    else None
                ),
            )
            for kind, path in artifact_paths.items()
        ),
        secure_arm_configurations=tuple(
            SecureArmEntryV22(
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
    output = evidence_directory / "manifest-v22.json"
    if output.exists():
        raise FileExistsError("V2.2 release manifest already exists")
    evidence_directory.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with NamedTemporaryFile(
            mode="wb",
            dir=evidence_directory,
            prefix=".manifest-v22-",
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(
                canonical_json_bytes(manifest.model_dump(mode="json", exclude_none=False)) + b"\n"
            )
            temporary.flush()
            os.fsync(temporary.fileno())
        os.link(temporary_name, output)
        _fsync_directory_v22(evidence_directory)
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)
    return output


def validate_aggregate_v22(
    manifest_path: Path,
    *,
    deterministic_oracle_path: Path,
    heldout_oracle_path: Path,
    repository_root: Path,
    execute_property_gates: bool = True,
    require_release_green: bool = True,
) -> ValidatedAggregateV22:
    """Revalidate every component and the current code tree before release."""

    deterministic_oracle_path, heldout_oracle_path = _require_canonical_oracle_paths_v22(
        repository_root,
        deterministic_oracle_path,
        heldout_oracle_path,
    )

    raw = load_strict_json_object(manifest_path, maximum_bytes=_MAX_MANIFEST_BYTES)
    try:
        manifest = ReleaseManifestV22.model_validate_json(
            json.dumps(raw, sort_keys=True, separators=(",", ":"))
        )
    except Exception as exc:
        raise AggregateV22Error("V2.2 release manifest is invalid") from exc
    evidence_root = manifest_path.resolve().parent
    if (
        manifest_path.name != "manifest-v22.json"
        or manifest.run_id != FROZEN_RUN_ID_V22
        or evidence_root.name != FROZEN_RUN_ID_V22
    ):
        raise AggregateV22Error("V2.2 manifest is outside the exact frozen evidence directory")
    entries: dict[str, ArtifactEntryV22] = {
        cast(str, item.kind): item for item in manifest.artifacts
    }
    if len(entries) != 5 or any(
        entries[kind].path != expected for kind, expected in _EXPECTED_ARTIFACTS.items()
    ):
        raise AggregateV22Error("V2.2 release manifest does not bind the exact five artifacts")
    artifact_paths: dict[str, Path] = {}
    for kind, entry in entries.items():
        target = (evidence_root / entry.path).resolve()
        if target.parent != evidence_root or not target.is_file():
            raise AggregateV22Error("V2.2 release artifact is missing or escapes its directory")
        if hashlib.sha256(target.read_bytes()).hexdigest() != entry.sha256:
            raise AggregateV22Error("V2.2 release artifact hash differs from the manifest")
        artifact_paths[kind] = target

    deterministic = validate_deterministic_release_v22(
        artifact_paths["deterministic"], deterministic_oracle_path
    )
    secure = validate_secure_semantics_v22(
        artifact_paths["secure"],
        deterministic_release=deterministic,
        heldout_oracle_path=heldout_oracle_path,
    )
    naive = validate_naive_semantics_v22(artifact_paths["naive"])
    secure_ledger = validate_slot_ledger_v22(
        artifact_paths["secure_ledger"],
        artifact_path=artifact_paths["secure"],
        ledger_kind="secure",
    )
    naive_ledger = validate_slot_ledger_v22(
        artifact_paths["naive_ledger"],
        artifact_path=artifact_paths["naive"],
        ledger_kind="naive",
    )
    for kind, ledger in (
        ("secure_ledger", secure_ledger),
        ("naive_ledger", naive_ledger),
    ):
        entry = entries[kind]
        if (
            entry.final_chain_sha256 != ledger.final_chain_sha256
            or entry.slot_count != ledger.slot_count
        ):
            raise AggregateV22Error("manifest ledger closure differs from independent validation")
    if secure_ledger.slot_count + naive_ledger.slot_count != TOTAL_PROVIDER_SLOT_COUNT_V22:
        raise AggregateV22Error("V2.2 provider ledger does not contain exactly 116 call slots")
    if {
        deterministic.run_id,
        secure.run_id,
        naive.run_id,
        secure_ledger.run_id,
        naive_ledger.run_id,
        manifest.run_id,
    } != {FROZEN_RUN_ID_V22}:
        raise AggregateV22Error("V2.2 release components use mixed or alternate run IDs")
    secure_ledger_green = (
        secure_ledger.completed_count == secure_ledger.slot_count == SECURE_SLOT_COUNT_V22
        and secure_ledger.failed_count == 0
        and secure_ledger.unobserved_count == 0
    )
    artifact_release_green = (
        secure.hard_gate_passed and naive.hard_gate_passed and secure_ledger_green
    )
    _validate_named_fixture_bindings(deterministic, secure, naive)
    if manifest.deterministic_oracle_sha256 != deterministic.oracle_sha256:
        raise AggregateV22Error("manifest deterministic oracle commitment differs")
    if manifest.heldout_oracle_sha256 != secure.heldout_oracle_sha256:
        raise AggregateV22Error("manifest held-out oracle commitment differs")
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
        raise AggregateV22Error("manifest secure-arm configuration differs from evidence")
    component_hashes = {
        deterministic.implementation_tree_sha256,
        secure.implementation_tree_sha256,
        naive.implementation_tree_sha256,
        manifest.implementation_tree_sha256,
    }
    if len(component_hashes) != 1:
        raise AggregateV22Error("V2.2 release components use different implementation trees")
    current_hash = implementation_tree_sha256_v2(
        release_implementation_paths_v2(repository_root),
        repository_root=repository_root,
    )
    if current_hash != manifest.implementation_tree_sha256:
        raise AggregateV22Error("V2.2 evidence is stale relative to the current implementation")
    property_report = (
        execute_property_gate_families_v22(repository_root)
        if execute_property_gates
        else PropertyGateReportV22(
            names=(),
            artifact_invariant_count=RELEASE_ARTIFACT_INVARIANT_COUNT_V22,
            property_gate_count=0,
            total_release_gate_count=RELEASE_ARTIFACT_INVARIANT_COUNT_V22,
        )
    )
    property_gate_names = property_report.names
    property_gates_complete = (
        execute_property_gates
        and property_gate_names == _PROPERTY_GATE_NAMES_V22
        and len(property_gate_names) == RELEASE_PROPERTY_GATE_COUNT_V22
    )
    if execute_property_gates and not property_gates_complete:
        raise AggregateV22Error("V2.2 property-gate families were not completely executed")
    if execute_property_gates:
        post_property_hash = implementation_tree_sha256_v2(
            release_implementation_paths_v2(repository_root),
            repository_root=repository_root,
        )
        if (
            post_property_hash != current_hash
            or post_property_hash != manifest.implementation_tree_sha256
        ):
            raise AggregateV22Error(
                "V2.2 implementation tree changed during property-gate execution"
            )
    if deterministic.artifact_invariant_count != RELEASE_ARTIFACT_INVARIANT_COUNT_V22:
        raise AggregateV22Error("V2.2 deterministic artifact invariant count is incomplete")
    release_green = artifact_release_green and property_gates_complete
    if require_release_green and not release_green:
        raise AggregateV22Error("V2.2 release gates did not pass")
    return ValidatedAggregateV22(
        manifest_sha256=hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        run_id=manifest.run_id,
        implementation_tree_sha256=current_hash,
        deterministic=deterministic,
        secure=secure,
        naive=naive,
        secure_ledger=secure_ledger,
        naive_ledger=naive_ledger,
        provider_slot_count=secure_ledger.slot_count + naive_ledger.slot_count,
        artifact_invariant_count=deterministic.artifact_invariant_count,
        property_gate_count=len(property_gate_names),
        total_release_gate_count=(
            deterministic.artifact_invariant_count + len(property_gate_names)
        ),
        property_gate_names=property_gate_names,
        integrity_valid=True,
        release_green=release_green,
    )


def execute_property_gate_families_v22(repository_root: Path) -> PropertyGateReportV22:
    """Run and report the two independently executed V2.2 property families."""

    names = _execute_property_gate_families(repository_root)
    return PropertyGateReportV22(
        names=names,
        artifact_invariant_count=RELEASE_ARTIFACT_INVARIANT_COUNT_V22,
        property_gate_count=len(names),
        total_release_gate_count=RELEASE_ARTIFACT_INVARIANT_COUNT_V22 + len(names),
    )


def validate_property_gate_families_v22(repository_root: Path) -> tuple[str, ...]:
    """Stable CLI seam returning the two successfully executed family names."""

    return execute_property_gate_families_v22(repository_root).names


def _execute_property_gate_families(repository_root: Path) -> tuple[str, ...]:
    """Execute two named metamorphic families; accept no producer verdicts."""

    completed_names: list[str] = []
    for family_name, node_ids in _PROPERTY_GATE_FAMILIES_V22:
        try:
            execute_property_gate_nodes(repository_root, node_ids)
        except PropertyGateRunnerError as exc:
            raise AggregateV22Error(f"V22 property-gate family failed: {family_name}") from exc
        completed_names.append(family_name)
    if len(completed_names) != RELEASE_PROPERTY_GATE_COUNT_V22 or (
        len(completed_names) + RELEASE_ARTIFACT_INVARIANT_COUNT_V22 != RELEASE_TOTAL_GATE_COUNT_V22
    ):
        raise AggregateV22Error("V2.2 composite release-gate accounting is invalid")
    return tuple(completed_names)


def _fsync_directory_v22(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
