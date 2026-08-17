"""Capture-only helpers for V2.2 evaluation artifacts.

Capture records bounded observations and never decides whether they pass; the
V2.2 semantic release validators intentionally do not import this module.
Beyond the V2 design, the secure capture durably retains every attempt before
the next provider call and maintains a hash-chained slot ledger: a ``started``
slot is fsynced before each request and terminalized before advancing, so an
interrupted capture leaves a permanently failed slot that is never reissued.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import re
import subprocess
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import IO, TypeAlias, cast

from cv_trust_agent.dataset import materialize_fixture_root, read_application_index
from cv_trust_agent.mappers import (
    DEFAULT_OPENAI_MODEL,
    OPENAI_MAPPER_INSTRUCTIONS,
    MapperCallDiagnostic,
    MapperError,
    MapperFailureCode,
    OpenAIResponsesMapper,
)
from cv_trust_agent.models import ClaimKind
from evaluation.capture_v2 import (
    CaseInputV2,
    HeldoutCitationV2Error,
    _atomic_write_no_overwrite_v2,
    _contains_capture_verdict_v2,
    _ephemeral_port,
    _resolve_executable,
    _stop_process,
    _wait_for_source,
    capture_typed_claims_v2,
)
from evaluation.fixture_commitment import normalized_fixture_tree_hash
from evaluation.heldout_mapper import (
    HeldoutInstructionClient,
    build_heldout_mapper_requests,
    heldout_prompt_sha256,
)
from evaluation.heldout_oracle_spec_v22 import (
    heldout_oracle_sha256_v22,
    load_heldout_release_oracle_v22,
)
from evaluation.oracle_spec_v22 import (
    DETERMINISTIC_ARTIFACT_KIND_V22,
    DeterministicOracleV22,
    oracle_sha256_v22,
)
from evaluation.protocol_v22 import (
    CANONICAL_MAPPER_NAME_V22,
    CANONICAL_PROVIDER_CANDIDATE_IDS_V22,
    CANONICAL_PROVIDER_SNAPSHOT_ID_V22,
    FROZEN_RUN_ID_V22,
    HELDOUT_CLEAN_SNAPSHOT_ID_V22,
    HELDOUT_DIRECTIVE_SNAPSHOT_ID_V22,
    HELDOUT_PROVIDER_CANDIDATE_IDS_V22,
    PROTOCOL_VERSION_V22,
    SCHEMA_VERSION_V22,
    SECURE_SLOT_COUNT_V22,
)
from evaluation.release_spec_v2 import (
    JsonObject,
    canonical_json_bytes,
    implementation_tree_sha256_v2,
    release_implementation_paths_v2,
)
from evaluation.release_spec_v22 import DecisionProjectionV22

FixtureMaterializerV22: TypeAlias = Callable[[Path, str], None]
_SECURE_PAIR_ORDERS_V22 = (
    ("clean", "directive"),
    ("directive", "clean"),
    ("clean", "directive"),
)
_SECURE_ATTEMPT_COUNT_V22 = 12
_MAX_PUBLIC_OUTPUT_BYTES = 16 * 1024 * 1024
_SLOT_CHAIN_DOMAIN_V22 = b"cv-trust-agent/provider-slot-chain/v3\0"
_SLOT_ABSENCE_DOMAIN_V22 = b"cv-trust-agent/provider-slot-unobserved/v3\0"
_SAFE_SOURCE_ID_V22 = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_METADATA_V22 = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+-]{0,79}$")

# Closed diagnostic vocabularies.  Every stage and failure code below is a
# code-owned constant; no provider-controlled string is ever recorded.
MAPPER_STAGES_V22 = (
    "provider_call",
    "response_parse",
    "structured_validation",
    "wire_conversion",
    "identity_validation",
    "citation_capture",
    "value_normalization",
)
MAPPER_STAGE_FAILURE_CODES_V22: Mapping[MapperFailureCode, tuple[str, str]] = {
    MapperFailureCode.PROVIDER_FAILURE: ("provider_call", "provider_failure"),
    MapperFailureCode.PROVIDER_TIMEOUT: ("provider_call", "provider_timeout"),
    MapperFailureCode.PROVIDER_CONNECTION: ("provider_call", "provider_connection"),
    MapperFailureCode.PROVIDER_STATUS: ("provider_call", "provider_status"),
    MapperFailureCode.PROVIDER_RESPONSE_INVALID: ("response_parse", "provider_response_invalid"),
    MapperFailureCode.NO_PARSED_OUTPUT: ("response_parse", "no_parsed_output"),
    MapperFailureCode.STRUCTURED_OUTPUT_INVALID: (
        "structured_validation",
        "structured_output_invalid",
    ),
    MapperFailureCode.WIRE_DATE_INVALID: ("wire_conversion", "wire_date_invalid"),
    MapperFailureCode.WIRE_INTERVAL_ORDER_INVALID: (
        "wire_conversion",
        "wire_interval_order_invalid",
    ),
    MapperFailureCode.CANDIDATE_IDENTITY_MISMATCH: (
        "identity_validation",
        "candidate_identity_mismatch",
    ),
    MapperFailureCode.SNAPSHOT_IDENTITY_MISMATCH: (
        "identity_validation",
        "snapshot_identity_mismatch",
    ),
}
CLAIM_KIND_COUNTER_KEYS_V22 = (
    *(kind.value for kind in ClaimKind),
    "unknown_kind",
)


class CaptureV22Error(ValueError):
    """A V2.2 capture invariant was violated."""


@dataclass(frozen=True, slots=True)
class CapturedCaseV22:
    case_name: str
    fixture_id: str
    fixture_tree_sha256: str
    projection: DecisionProjectionV22

    def artifact_object(self) -> JsonObject:
        return {
            "case_name": self.case_name,
            "fixture_id": self.fixture_id,
            "fixture_tree_sha256": self.fixture_tree_sha256,
            "projection": self.projection.canonical_object(),
        }


class PublicCommandCaptureV22:
    """Capture one case through ordinary public ``serve`` and ``run`` commands."""

    def __init__(
        self,
        *,
        executable: str = "cv-trust",
        source_timeout_seconds: float = 0.5,
        process_timeout_seconds: float = 60.0,
    ) -> None:
        self._executable = _resolve_executable(executable)
        self._source_timeout_seconds = source_timeout_seconds
        self._process_timeout_seconds = process_timeout_seconds

    def __call__(self, case: CaseInputV2) -> CapturedCaseV22:
        port = _ephemeral_port()
        source_url = f"http://127.0.0.1:{port}"
        with TemporaryDirectory(prefix="cv-trust-v22-case-") as temporary:
            fixture_root = Path(temporary) / "source"
            case.materialize(fixture_root, source_url)
            fixture_digest = normalized_fixture_tree_hash(fixture_root)
            process = subprocess.Popen(
                (
                    self._executable,
                    "serve",
                    "--scenario",
                    case.source_scenario,
                    "--fixture-root",
                    fixture_root.as_posix(),
                    "--port",
                    str(port),
                ),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                _wait_for_source(process, source_url)
                command = [
                    self._executable,
                    "run",
                    "--source-url",
                    source_url,
                    "--mapper",
                    "deterministic",
                    "--source-timeout",
                    str(self._source_timeout_seconds),
                ]
                if case.mapper_fault is not None:
                    command.extend(("--mapper-fault", case.mapper_fault))
                if case.fault_candidate is not None:
                    command.extend(("--fault-candidate", case.fault_candidate))
                if case.fault_claim is not None:
                    command.extend(("--fault-claim", case.fault_claim))
                completed = subprocess.run(
                    command,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    check=False,
                    timeout=self._process_timeout_seconds,
                )
            finally:
                _stop_process(process)
        if completed.returncode != 0:
            raise RuntimeError("public V2.2 case execution failed")
        if len(completed.stdout) > _MAX_PUBLIC_OUTPUT_BYTES:
            raise RuntimeError("public V2.2 case output exceeded its bound")
        try:
            raw = json.loads(completed.stdout)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("public V2.2 case output was not JSON") from exc
        if not isinstance(raw, dict) or any(not isinstance(key, str) for key in raw):
            raise RuntimeError("public V2.2 case output was not an object")
        projection = DecisionProjectionV22.from_observation(cast(Mapping[str, object], raw))
        return CapturedCaseV22(
            case_name=case.name,
            fixture_id=case.fixture_id,
            fixture_tree_sha256=fixture_digest,
            projection=projection,
        )


def capture_deterministic_cases_v22(
    cases: Sequence[CaseInputV2],
    runner: Callable[[CaseInputV2], CapturedCaseV22],
) -> tuple[CapturedCaseV22, ...]:
    names = [case.name for case in cases]
    if not names or len(names) != len(set(names)):
        raise ValueError("V2.2 case registrations must be non-empty and unique")
    captured = tuple(runner(case) for case in cases)
    if [item.case_name for item in captured] != names:
        raise ValueError("capture runner changed the registered case order")
    return captured


def write_deterministic_observations_v22(
    output_path: Path,
    *,
    observations: Sequence[CapturedCaseV22],
    oracle: DeterministicOracleV22,
    implementation_tree_sha256: str,
) -> Path:
    """Write observations only; semantic verdicts are intentionally absent."""

    if output_path.exists():
        raise FileExistsError("V2.2 deterministic capture target already exists")
    if len(implementation_tree_sha256) != 64:
        raise ValueError("implementation tree digest is invalid")
    artifact: JsonObject = {
        "schema_version": SCHEMA_VERSION_V22,
        "protocol_version": PROTOCOL_VERSION_V22,
        "run_id": FROZEN_RUN_ID_V22,
        "artifact_kind": DETERMINISTIC_ARTIFACT_KIND_V22,
        "oracle_sha256": oracle_sha256_v22(oracle),
        "implementation_tree_sha256": implementation_tree_sha256,
        "observations": [item.artifact_object() for item in observations],
    }
    target = _atomic_write_no_overwrite_v2(
        output_path,
        canonical_json_bytes(artifact) + b"\n",
        prefix=".deterministic-v22-",
    )
    _fsync_directory_v22(target.parent)
    return target


@dataclass(frozen=True, slots=True)
class SecureAttemptCoordinateV22:
    """One preregistered arm/condition coordinate in the twelve-call protocol."""

    arm: str
    repetition: int
    condition: str
    condition_order: tuple[str, str]
    condition_order_index: int


@dataclass(frozen=True, slots=True)
class SecureLiveCaptureV22:
    """Capture receipt only; it deliberately contains no release verdict."""

    artifact_path: Path
    slot_ledger_path: Path
    attempt_count: int
    implementation_tree_sha256: str
    final_chain_sha256: str


def secure_attempt_schedule_v22() -> tuple[SecureAttemptCoordinateV22, ...]:
    """Return the exact canonical-then-held-out twelve-attempt schedule."""

    coordinates: list[SecureAttemptCoordinateV22] = []
    for arm in ("canonical", "heldout"):
        for repetition, condition_order in enumerate(_SECURE_PAIR_ORDERS_V22, start=1):
            for order_index, condition in enumerate(condition_order, start=1):
                coordinates.append(
                    SecureAttemptCoordinateV22(
                        arm=arm,
                        repetition=repetition,
                        condition=condition,
                        condition_order=condition_order,
                        condition_order_index=order_index,
                    )
                )
    if len(coordinates) != _SECURE_ATTEMPT_COUNT_V22:
        raise RuntimeError("secure V2.2 schedule is incomplete")
    return tuple(coordinates)


class SecureSlotLedgerV22:
    """Hash-chained, fsynced provider-slot writer for the paid protocols.

    Every slot is appended as ``started`` and fsynced before its provider work
    begins, then terminalized (``completed`` or ``failed``) before the capture
    advances.  The ledger never reissues a slot: an existing ledger file is a
    hard error, so an interrupted capture cannot be resumed silently.
    """

    def __init__(
        self,
        path: Path,
        *,
        ledger_kind: str,
        run_id: str = FROZEN_RUN_ID_V22,
    ) -> None:
        if path.exists():
            raise FileExistsError("secure V2.2 slot ledger already exists; slots never reissue")
        if ledger_kind not in {"secure", "naive"}:
            raise CaptureV22Error("V2.2 ledger kind is outside the closed vocabulary")
        if run_id != FROZEN_RUN_ID_V22:
            raise CaptureV22Error("alternate V2.2 run IDs are not admissible")
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._handle: IO[bytes] = path.open("xb")
        _fsync_directory_v22(path.parent)
        self._ledger_kind = ledger_kind
        self._run_id = run_id
        self._chain = hashlib.sha256(
            _SLOT_CHAIN_DOMAIN_V22 + ledger_kind.encode("ascii") + b"\0" + run_id.encode("ascii")
        ).hexdigest()
        self._open_slots: dict[int, JsonObject] = {}
        self._next_index = 1
        self._terminal_counts = {"completed": 0, "failed": 0, "unobserved": 0}
        expected = 84 if ledger_kind == "secure" else 32
        self._append(
            {
                **self._base_record("ledger_genesis_v22"),
                "expected_slot_count": expected,
                "canonical_slot_count": 60 if ledger_kind == "secure" else 0,
                "heldout_slot_count": 24 if ledger_kind == "secure" else 0,
                "naive_slot_count": 32 if ledger_kind == "naive" else 0,
            }
        )

    @property
    def path(self) -> Path:
        return self._path

    @property
    def final_chain_sha256(self) -> str:
        if not self._handle.closed:
            raise CaptureV22Error("V2.2 slot ledger has not been closed")
        return self._chain

    def _base_record(self, event: str) -> JsonObject:
        return {
            "schema_version": SCHEMA_VERSION_V22,
            "protocol_version": PROTOCOL_VERSION_V22,
            "run_id": self._run_id,
            "ledger_kind": self._ledger_kind,
            "event": event,
        }

    def _append(self, record: JsonObject) -> None:
        record["prev_chain_sha256"] = self._chain
        payload = canonical_json_bytes(record)
        self._chain = hashlib.sha256(
            _SLOT_CHAIN_DOMAIN_V22 + bytes.fromhex(self._chain) + payload
        ).hexdigest()
        record_with_chain = dict(record)
        record_with_chain["chain_sha256"] = self._chain
        self._handle.write(canonical_json_bytes(record_with_chain) + b"\n")
        self._handle.flush()
        os.fsync(self._handle.fileno())

    def start_slot(
        self,
        descriptor: Mapping[str, object],
    ) -> int:
        if self._handle.closed:
            raise CaptureV22Error("V2.2 slot ledger is closed")
        allowed = {
            "arm",
            "repetition",
            "condition",
            "condition_order_index",
            "call_index",
            "block_id",
            "call_role",
            "call_position",
            "candidate_id",
            "snapshot_id",
        }
        if (
            not descriptor
            or not set(descriptor).issubset(allowed)
            or "arm" not in descriptor
            or "call_index" not in descriptor
            or len(descriptor) > len(allowed)
            or any(
                not isinstance(key, str)
                or not isinstance(value, str | int)
                or isinstance(value, bool)
                or (isinstance(value, str) and len(value) > 64)
                for key, value in descriptor.items()
            )
        ):
            raise CaptureV22Error("secure V2.2 slot descriptor is outside its bounds")
        arm = descriptor.get("arm")
        has_identity = "candidate_id" in descriptor and "snapshot_id" in descriptor
        if (arm in {"canonical", "heldout"}) != has_identity or (
            arm == "naive" and ("candidate_id" in descriptor or "snapshot_id" in descriptor)
        ):
            raise CaptureV22Error("secure V2.2 slot descriptor identity is invalid")
        index = self._next_index
        self._next_index += 1
        canonical = cast(JsonObject, dict(descriptor))
        self._open_slots[index] = canonical
        record: JsonObject = {
            **self._base_record("slot_started_v22"),
            "slot_index": index,
            **canonical,
        }
        self._append(record)
        return index

    def terminalize_slot(self, index: int, *, state: str, row_sha256: str) -> None:
        if state not in {"completed", "failed", "unobserved"}:
            raise CaptureV22Error("secure V2.2 slot terminal state is invalid")
        if index not in self._open_slots:
            raise CaptureV22Error("secure V2.2 slot terminalization is unmatched")
        if re.fullmatch(r"[0-9a-f]{64}", row_sha256) is None:
            raise CaptureV22Error("secure V2.2 slot row hash is invalid")
        del self._open_slots[index]
        self._terminal_counts[state] += 1
        self._append(
            {
                **self._base_record("slot_terminal_v22"),
                "slot_index": index,
                "state": state,
                "row_sha256": row_sha256,
            }
        )

    def close(self, *, expected_slot_count: int) -> None:
        if self._open_slots:
            raise CaptureV22Error("secure V2.2 capture ended with an open slot")
        slot_count = self._next_index - 1
        if slot_count != expected_slot_count:
            raise CaptureV22Error("secure V2.2 slot count does not match the frozen schedule")
        self._append(
            {
                **self._base_record("ledger_final_v22"),
                "slot_count": slot_count,
                "completed_count": self._terminal_counts["completed"],
                "failed_count": self._terminal_counts["failed"],
                "unobserved_count": self._terminal_counts["unobserved"],
            }
        )
        self._handle.flush()
        os.fsync(self._handle.fileno())
        self._handle.close()
        _fsync_directory_v22(self._path.parent)


def _slot_descriptor_v22(
    coordinate: SecureAttemptCoordinateV22,
    *,
    call_index: int,
    candidate_id: str,
    snapshot_id: str,
) -> JsonObject:
    return {
        "arm": coordinate.arm,
        "repetition": coordinate.repetition,
        "condition": coordinate.condition,
        "condition_order_index": coordinate.condition_order_index,
        "call_index": call_index,
        "candidate_id": candidate_id,
        "snapshot_id": snapshot_id,
    }


def _unobserved_slot_sha256_v22(
    *,
    ledger_kind: str,
    run_id: str,
    slot_index: int,
    descriptor: Mapping[str, object],
) -> str:
    return hashlib.sha256(
        _SLOT_ABSENCE_DOMAIN_V22
        + canonical_json_bytes(
            {
                "kind": "unobserved",
                "ledger_kind": ledger_kind,
                "run_id": run_id,
                "slot_index": slot_index,
                "descriptor": dict(descriptor),
            }
        )
    ).hexdigest()


def _terminalize_unobserved_v22(
    ledger: SecureSlotLedgerV22,
    *,
    slot: int,
    descriptor: Mapping[str, object],
) -> None:
    ledger.terminalize_slot(
        slot,
        state="unobserved",
        row_sha256=_unobserved_slot_sha256_v22(
            ledger_kind=ledger._ledger_kind,
            run_id=ledger._run_id,
            slot_index=slot,
            descriptor=descriptor,
        ),
    )


def capture_secure_live_v22(
    output_path: Path,
    *,
    execute_live_api: bool,
    repository_root: Path,
    slot_ledger_path: Path,
    executable: str = "cv-trust",
    canonical_model: str = DEFAULT_OPENAI_MODEL,
    heldout_model: str = DEFAULT_OPENAI_MODEL,
    heldout_oracle_path: Path | None = None,
    mapper_timeout_seconds: float = 30.0,
    process_timeout_seconds: float = 360.0,
) -> SecureLiveCaptureV22:
    """Capture twelve raw secure attempts after explicit paid-API authorization.

    Capture only: no semantic validator is imported and no utility, safety,
    pair-status, or pass boolean is ever written.  Each attempt row is staged
    durably before the next call, and each provider slot is chained through
    :class:`SecureSlotLedgerV22`.
    """

    if not execute_live_api:
        raise PermissionError("secure V2.2 live capture requires explicit paid-API authorization")
    if mapper_timeout_seconds != 30.0:
        raise ValueError("secure V2.2 capture uses the frozen 30-second mapper deadline")
    if output_path.exists():
        raise FileExistsError("secure V2.2 capture target already exists")
    if (
        output_path.name != "secure-v22.jsonl"
        or slot_ledger_path.name != "secure-slots-v22.jsonl"
        or output_path.resolve().parent != slot_ledger_path.resolve().parent
        or output_path.resolve().parent.name != FROZEN_RUN_ID_V22
    ):
        raise ValueError("secure V2.2 capture requires the exact frozen evidence directory")
    root = repository_root.resolve()
    selected_oracle = heldout_oracle_path or root / "evaluation" / "heldout_release_oracle_v22.json"
    heldout_oracle = load_heldout_release_oracle_v22(selected_oracle)
    implementation_hash = implementation_tree_sha256_v2(
        release_implementation_paths_v2(root),
        repository_root=root,
    )
    resolved_executable = _resolve_executable(executable)
    sdk_version = _distribution_version_v22("openai")
    ledger = SecureSlotLedgerV22(slot_ledger_path, ledger_kind="secure")
    staging_path = slot_ledger_path.with_suffix(".staged.jsonl")
    if staging_path.exists():
        raise FileExistsError("secure V2.2 staging path already exists")
    rows: list[JsonObject] = []
    canonical_coordinates = tuple(
        item for item in secure_attempt_schedule_v22() if item.arm == "canonical"
    )
    heldout_coordinates = tuple(
        item for item in secure_attempt_schedule_v22() if item.arm == "heldout"
    )
    canonical_scenarios = {
        "clean": "clean",
        "directive": "structured_note_directive",
    }

    def stage_bytes(payload: bytes) -> None:
        with staging_path.open("ab") as handle:
            handle.write(payload + b"\n")
            handle.flush()
            os.fsync(handle.fileno())

    def retain(row: JsonObject) -> None:
        payload = canonical_json_bytes(row)
        stage_bytes(payload)
        rows.append(row)

    with TemporaryDirectory(prefix="cv-trust-secure-v22-") as temporary:
        fixture_hashes: dict[str, str] = {}
        sources: dict[str, tuple[str, subprocess.Popen[bytes]]] = {}
        try:
            for condition, scenario in canonical_scenarios.items():
                port = _ephemeral_port()
                source_url = f"http://127.0.0.1:{port}"
                fixture_root = Path(temporary) / condition
                materialize_fixture_root(
                    fixture_root,
                    scenario,
                    source_base_url=source_url,
                )
                _validate_canonical_fixture_identity_v22(fixture_root)
                fixture_hashes[condition] = normalized_fixture_tree_hash(fixture_root)
                process = subprocess.Popen(
                    (
                        resolved_executable,
                        "serve",
                        "--scenario",
                        scenario,
                        "--fixture-root",
                        fixture_root.as_posix(),
                        "--port",
                        str(port),
                    ),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                sources[condition] = (source_url, process)
                _wait_for_source(process, source_url)
            for coordinate in canonical_coordinates:
                source_url, _ = sources[coordinate.condition]
                descriptors = tuple(
                    _slot_descriptor_v22(
                        coordinate,
                        call_index=call_index,
                        candidate_id=candidate_id,
                        snapshot_id=CANONICAL_PROVIDER_SNAPSHOT_ID_V22,
                    )
                    for call_index, candidate_id in enumerate(
                        CANONICAL_PROVIDER_CANDIDATE_IDS_V22,
                        start=1,
                    )
                )
                slots = tuple(ledger.start_slot(descriptor) for descriptor in descriptors)
                try:
                    row = _capture_canonical_live_attempt_v22(
                        coordinate,
                        executable=resolved_executable,
                        source_url=source_url,
                        model_identifier=canonical_model,
                        sdk_version=sdk_version,
                        implementation_tree_sha256=implementation_hash,
                        fixture_tree_sha256=fixture_hashes[coordinate.condition],
                        mapper_timeout_seconds=mapper_timeout_seconds,
                        process_timeout_seconds=process_timeout_seconds,
                    )
                except Exception:
                    for slot, descriptor in zip(slots, descriptors, strict=True):
                        _terminalize_unobserved_v22(
                            ledger,
                            slot=slot,
                            descriptor=descriptor,
                        )
                    raise
                retain(row)
                observed = row.get("provider_calls")
                provider_calls = (
                    cast(list[JsonObject], observed) if isinstance(observed, list) else []
                )
                calls_by_identity = {
                    (item["candidate_id"], item["snapshot_id"]): item for item in provider_calls
                }
                for slot, descriptor in zip(slots, descriptors, strict=True):
                    identity = (descriptor["candidate_id"], descriptor["snapshot_id"])
                    provider_call = calls_by_identity.get(identity)
                    if provider_call is None:
                        _terminalize_unobserved_v22(
                            ledger,
                            slot=slot,
                            descriptor=descriptor,
                        )
                        continue
                    ledger.terminalize_slot(
                        slot,
                        state=(
                            "completed" if provider_call.get("outcome") == "success" else "failed"
                        ),
                        row_sha256=hashlib.sha256(canonical_json_bytes(provider_call)).hexdigest(),
                    )
        finally:
            for _, process in sources.values():
                _stop_process(process)

    heldout_requests = {
        condition: build_heldout_mapper_requests(
            root,
            condition=condition,
            oracle_path=root / "evaluation" / "heldout_oracle.json",
        )
        for condition in ("clean", "directive")
    }
    heldout_fixture_hashes = {
        condition: normalized_fixture_tree_hash(root / "evaluation" / "heldout" / condition)
        for condition in ("clean", "directive")
    }
    oracle_digest = heldout_oracle_sha256_v22(heldout_oracle)
    for coordinate in heldout_coordinates:
        retain(
            _capture_heldout_live_attempt_v22(
                coordinate,
                mapper_requests=heldout_requests[coordinate.condition],
                model_identifier=heldout_model,
                sdk_version=sdk_version,
                implementation_tree_sha256=implementation_hash,
                fixture_tree_sha256=heldout_fixture_hashes[coordinate.condition],
                heldout_oracle_sha256=oracle_digest,
                mapper_timeout_seconds=mapper_timeout_seconds,
                ledger=ledger,
                stage=stage_bytes,
            )
        )

    ledger.close(expected_slot_count=SECURE_SLOT_COUNT_V22)
    implementation_hash_after = implementation_tree_sha256_v2(
        release_implementation_paths_v2(root),
        repository_root=root,
    )
    if implementation_hash_after != implementation_hash:
        raise RuntimeError("implementation tree changed during secure V2.2 capture")
    target = write_secure_attempts_v22(output_path, attempts=rows)
    staging_path.unlink(missing_ok=True)
    _fsync_directory_v22(staging_path.parent)
    return SecureLiveCaptureV22(
        artifact_path=target,
        slot_ledger_path=ledger.path,
        attempt_count=len(rows),
        implementation_tree_sha256=implementation_hash,
        final_chain_sha256=ledger.final_chain_sha256,
    )


def write_secure_attempts_v22(
    output_path: Path,
    *,
    attempts: Sequence[Mapping[str, object]],
) -> Path:
    """Atomically write exactly twelve bounded raw attempts, with no overwrite."""

    if output_path.exists():
        raise FileExistsError("secure V2.2 capture target already exists")
    if len(attempts) != _SECURE_ATTEMPT_COUNT_V22:
        raise ValueError("secure V2.2 capture must contain exactly twelve attempts")
    rows: list[bytes] = []
    for attempt in attempts:
        if attempt.get("run_id") != FROZEN_RUN_ID_V22:
            raise ValueError("secure V2.2 capture row has a missing or alternate run ID")
        if _contains_capture_verdict_v2(attempt):
            raise ValueError("secure V2.2 capture cannot contain producer verdicts")
        row = canonical_json_bytes(dict(attempt))
        if not row or len(row) > _MAX_PUBLIC_OUTPUT_BYTES:
            raise ValueError("secure V2.2 capture row exceeds its bound")
        rows.append(row + b"\n")
    payload = b"".join(rows)
    if len(payload) > _MAX_PUBLIC_OUTPUT_BYTES:
        raise ValueError("secure V2.2 capture artifact exceeds its bound")
    target = _atomic_write_no_overwrite_v2(
        output_path,
        payload,
        prefix=".secure-v22-",
    )
    _fsync_directory_v22(target.parent)
    return target


def _capture_canonical_live_attempt_v22(
    coordinate: SecureAttemptCoordinateV22,
    *,
    executable: str,
    source_url: str,
    model_identifier: str,
    sdk_version: str,
    implementation_tree_sha256: str,
    fixture_tree_sha256: str,
    mapper_timeout_seconds: float,
    process_timeout_seconds: float,
) -> JsonObject:
    started_at = datetime.now(UTC)
    started = time.monotonic()
    environment = os.environ.copy()
    environment["CV_TRUST_OPENAI_MODEL"] = model_identifier
    result: JsonObject
    usage = _empty_usage_v22()
    provider_calls: list[JsonObject] = []
    try:
        completed = subprocess.run(
            (
                executable,
                "run",
                "--source-url",
                source_url,
                "--mapper",
                "openai",
                "--source-timeout",
                "0.5",
            ),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=process_timeout_seconds,
            env=environment,
        )
    except subprocess.TimeoutExpired:
        result = {"kind": "failure", "failure_code": "process_timeout"}
    except OSError:
        result = {"kind": "failure", "failure_code": "process_failure"}
    else:
        if completed.returncode != 0:
            result = {"kind": "failure", "failure_code": "process_failure"}
        elif not completed.stdout or len(completed.stdout) > _MAX_PUBLIC_OUTPUT_BYTES:
            result = {"kind": "failure", "failure_code": "invalid_sanitized_output"}
        else:
            try:
                raw = json.loads(completed.stdout)
                if not isinstance(raw, dict) or any(not isinstance(key, str) for key in raw):
                    raise ValueError("canonical output is not an object")
                payload = cast(Mapping[str, object], raw)
                provider_calls = _sanitize_canonical_provider_calls_v22(payload.get("mapper_calls"))
                usage = _usage_from_raw_mapper_calls_v22(provider_calls)
                if len(provider_calls) != 10:
                    raise ValueError("canonical output lacks ten unique provider diagnostics")
                projection = DecisionProjectionV22.from_observation(payload)
            except (UnicodeError, json.JSONDecodeError, ValueError):
                result = {"kind": "failure", "failure_code": "invalid_sanitized_output"}
            else:
                result = {
                    "kind": "decision",
                    "projection": projection.canonical_object(),
                }
    row = _secure_attempt_row_v22(
        coordinate,
        event="secure_canonical_attempt_v22",
        model_identifier=model_identifier,
        sdk_version=sdk_version,
        prompt_sha256=hashlib.sha256(OPENAI_MAPPER_INSTRUCTIONS.encode("utf-8")).hexdigest(),
        implementation_tree_sha256=implementation_tree_sha256,
        fixture_tree_sha256=fixture_tree_sha256,
        mapper_timeout_seconds=mapper_timeout_seconds,
        started_at=started_at,
        latency_ms=_elapsed_ms_v22(started),
        usage=usage,
        result=result,
    )
    row["provider_calls"] = provider_calls
    return row


def _sanitize_canonical_provider_calls_v22(value: object) -> list[JsonObject]:
    """Retain only the exact bounded diagnostic vocabulary emitted by the CLI."""

    if not isinstance(value, list) or len(value) > 10:
        return []
    expected_keys = {
        "mapper_name",
        "model",
        "candidate_id",
        "snapshot_id",
        "outcome",
        "failure_code",
        "latency_ms",
        "claim_count",
        "citation_count",
        "response_id_hash",
        "input_tokens",
        "output_tokens",
        "total_tokens",
    }
    allowed_failures = {item.value for item in MapperFailureCode}
    sanitized: list[JsonObject] = []
    identities: set[tuple[str, str]] = set()
    for raw in value:
        if not isinstance(raw, dict) or set(raw) != expected_keys:
            return []
        mapper_name = raw.get("mapper_name")
        model = raw.get("model")
        candidate_id = raw.get("candidate_id")
        snapshot_id = raw.get("snapshot_id")
        outcome = raw.get("outcome")
        failure_code = raw.get("failure_code")
        if (
            not isinstance(mapper_name, str)
            or mapper_name != CANONICAL_MAPPER_NAME_V22
            or not isinstance(model, str)
            or _SAFE_METADATA_V22.fullmatch(model) is None
            or not isinstance(candidate_id, str)
            or _SAFE_SOURCE_ID_V22.fullmatch(candidate_id) is None
            or not isinstance(snapshot_id, str)
            or _SAFE_SOURCE_ID_V22.fullmatch(snapshot_id) is None
            or outcome not in {"success", "failure"}
            or (
                outcome == "success"
                and (failure_code is not None or raw.get("response_id_hash") is None)
            )
            or (
                outcome == "failure"
                and (not isinstance(failure_code, str) or failure_code not in allowed_failures)
            )
        ):
            return []
        identity = (candidate_id, snapshot_id)
        if identity in identities:
            return []
        identities.add(identity)
        for field, maximum in (
            ("latency_ms", 3_600_000),
            ("claim_count", 64),
            ("citation_count", 1_024),
        ):
            observed = raw.get(field)
            if (
                not isinstance(observed, int)
                or isinstance(observed, bool)
                or observed < 0
                or observed > maximum
            ):
                return []
        response_hash = raw.get("response_id_hash")
        if response_hash is not None and (
            not isinstance(response_hash, str)
            or re.fullmatch(r"[0-9a-f]{64}", response_hash) is None
        ):
            return []
        for field in ("input_tokens", "output_tokens", "total_tokens"):
            observed = raw.get(field)
            if observed is not None and (
                not isinstance(observed, int)
                or isinstance(observed, bool)
                or observed < 0
                or observed > 100_000_000
            ):
                return []
        sanitized.append(cast(JsonObject, {key: raw[key] for key in sorted(expected_keys)}))
    expected_order = {
        (candidate_id, CANONICAL_PROVIDER_SNAPSHOT_ID_V22): index
        for index, candidate_id in enumerate(CANONICAL_PROVIDER_CANDIDATE_IDS_V22)
    }
    if not set(identities).issubset(expected_order):
        return []

    def call_order(item: JsonObject) -> int:
        candidate_id = item.get("candidate_id")
        snapshot_id = item.get("snapshot_id")
        assert isinstance(candidate_id, str) and isinstance(snapshot_id, str)
        return expected_order[(candidate_id, snapshot_id)]

    return sorted(sanitized, key=call_order)


def _capture_heldout_live_attempt_v22(
    coordinate: SecureAttemptCoordinateV22,
    *,
    mapper_requests: Sequence[object],
    model_identifier: str,
    sdk_version: str,
    implementation_tree_sha256: str,
    fixture_tree_sha256: str,
    heldout_oracle_sha256: str,
    mapper_timeout_seconds: float,
    ledger: SecureSlotLedgerV22 | None = None,
    stage: Callable[[bytes], None] | None = None,
) -> JsonObject:
    from openai import OpenAI, OpenAIError

    from cv_trust_agent.models import MapperRequest

    if len(mapper_requests) != 4 or any(
        not isinstance(item, MapperRequest) for item in mapper_requests
    ):
        raise ValueError("held-out capture requires exactly four mapper requests")
    requests = tuple(item for item in mapper_requests if isinstance(item, MapperRequest))
    expected_snapshot = (
        HELDOUT_CLEAN_SNAPSHOT_ID_V22
        if coordinate.condition == "clean"
        else HELDOUT_DIRECTIVE_SNAPSHOT_ID_V22
    )
    if tuple(item.candidate_id for item in requests) != HELDOUT_PROVIDER_CANDIDATE_IDS_V22 or any(
        item.snapshot_id != expected_snapshot for item in requests
    ):
        raise ValueError("held-out mapper requests differ from the frozen cohort identities")
    descriptors = tuple(
        _slot_descriptor_v22(
            coordinate,
            call_index=ordinal,
            candidate_id=request.candidate_id,
            snapshot_id=request.snapshot_id,
        )
        for ordinal, request in enumerate(requests, start=1)
    )

    started_at = datetime.now(UTC)
    started = time.monotonic()
    diagnostics: list[MapperCallDiagnostic] = []

    def record_diagnostic(diagnostic: MapperCallDiagnostic) -> None:
        diagnostics.append(diagnostic)

    def observe_candidate(mapper: OpenAIResponsesMapper, raw_request: MapperRequest) -> JsonObject:
        try:
            output = mapper.map_claims(raw_request)
        except MapperError as exc:
            failure_stage, code = MAPPER_STAGE_FAILURE_CODES_V22[exc.code]
            return _heldout_failure_candidate_v22(raw_request, stage=failure_stage, code=code)
        try:
            captured = capture_typed_claims_v2(
                candidate_id=raw_request.candidate_id,
                snapshot_id=raw_request.snapshot_id,
                claims=cast(
                    Sequence[Mapping[str, object]],
                    output.model_dump(mode="json", exclude_none=False)["claims"],
                ),
                tagged_visible_text=raw_request.tagged_visible_text,
            )
        except HeldoutCitationV2Error:
            return _heldout_failure_candidate_v22(
                raw_request,
                stage="citation_capture",
                code="citation_failure",
            )
        except (ValueError, KeyError, TypeError):
            return _heldout_failure_candidate_v22(
                raw_request,
                stage="value_normalization",
                code="claim_value_invalid",
            )
        return {
            "candidate_id": captured["candidate_id"],
            "snapshot_id": captured["snapshot_id"],
            "outcome": "mapped",
            "failure_stage": None,
            "failure_code": None,
            "claim_kind_counts": _claim_kind_counts_v22(
                cast(Sequence[Mapping[str, object]], captured["claims"])
            ),
            "claims": captured["claims"],
        }

    result: JsonObject
    candidates: list[JsonObject] = []
    started_slots: list[tuple[int, JsonObject]] = []
    try:
        mapper = OpenAIResponsesMapper(
            client=HeldoutInstructionClient(OpenAI(timeout=mapper_timeout_seconds, max_retries=0)),
            model=model_identifier,
            diagnostics=record_diagnostic,
        )
        for raw_request, descriptor in zip(requests, descriptors, strict=True):
            slot: int | None = None
            if ledger is not None:
                slot = ledger.start_slot(descriptor)
                started_slots.append((slot, descriptor))
            try:
                candidate = observe_candidate(mapper, raw_request)
            except Exception:
                if ledger is not None and slot is not None:
                    _terminalize_unobserved_v22(
                        ledger,
                        slot=slot,
                        descriptor=descriptor,
                    )
                raise
            payload = canonical_json_bytes(candidate)
            if stage is not None:
                stage(payload)
            if ledger is not None and slot is not None:
                ledger.terminalize_slot(
                    slot,
                    state=(
                        "failed" if candidate.get("outcome") == "mapper_failure" else "completed"
                    ),
                    row_sha256=hashlib.sha256(payload).hexdigest(),
                )
            candidates.append(candidate)
        if len(candidates) != 4:
            raise ValueError("held-out capture did not produce four candidate observations")
        result = {"kind": "claims", "candidates": candidates}
    except (KeyError, TypeError, ValueError):
        result = {"kind": "failure", "failure_code": "invalid_sanitized_output"}
    except (OSError, OpenAIError, RuntimeError):
        result = {"kind": "failure", "failure_code": "provider_failure"}
    finally:
        if ledger is not None:
            for descriptor in descriptors[len(started_slots) :]:
                slot = ledger.start_slot(descriptor)
                _terminalize_unobserved_v22(
                    ledger,
                    slot=slot,
                    descriptor=descriptor,
                )
    row = _secure_attempt_row_v22(
        coordinate,
        event="secure_heldout_attempt_v22",
        model_identifier=model_identifier,
        sdk_version=sdk_version,
        prompt_sha256=heldout_prompt_sha256(),
        implementation_tree_sha256=implementation_tree_sha256,
        fixture_tree_sha256=fixture_tree_sha256,
        mapper_timeout_seconds=mapper_timeout_seconds,
        started_at=started_at,
        latency_ms=_elapsed_ms_v22(started),
        usage=_usage_from_diagnostics_v22(diagnostics),
        result=result,
    )
    row["heldout_oracle_sha256"] = heldout_oracle_sha256
    row["provider_candidates"] = candidates
    return row


def _heldout_failure_candidate_v22(
    request: object,
    *,
    stage: str,
    code: str,
) -> JsonObject:
    from cv_trust_agent.models import MapperRequest

    if not isinstance(request, MapperRequest):
        raise ValueError("held-out mapper request has an invalid type")
    if stage not in MAPPER_STAGES_V22:
        raise CaptureV22Error("held-out failure stage is outside the closed vocabulary")
    return {
        "candidate_id": request.candidate_id,
        "snapshot_id": request.snapshot_id,
        "outcome": "mapper_failure",
        "failure_stage": stage,
        "failure_code": code,
        "claim_kind_counts": _claim_kind_counts_v22(()),
        "claims": [],
    }


def _validate_canonical_fixture_identity_v22(fixture_root: Path) -> None:
    """Ensure preauthorized slots name the exact source-controlled cohort."""

    index = read_application_index(fixture_root)
    candidates = index.get("candidates")
    if not isinstance(candidates, list) or any(not isinstance(item, dict) for item in candidates):
        raise CaptureV22Error("canonical fixture index has invalid candidate identities")
    candidate_ids = tuple(item.get("candidate_id") for item in candidates)
    if (
        index.get("index_id") != CANONICAL_PROVIDER_SNAPSHOT_ID_V22
        or candidate_ids != CANONICAL_PROVIDER_CANDIDATE_IDS_V22
    ):
        raise CaptureV22Error("canonical fixture differs from the frozen provider identities")


def _claim_kind_counts_v22(claims: Sequence[Mapping[str, object]]) -> JsonObject:
    counts = dict.fromkeys(CLAIM_KIND_COUNTER_KEYS_V22, 0)
    for claim in claims:
        kind = claim.get("kind")
        key = kind if isinstance(kind, str) and kind in counts else "unknown_kind"
        counts[key] += 1
    return cast(JsonObject, counts)


def _secure_attempt_row_v22(
    coordinate: SecureAttemptCoordinateV22,
    *,
    event: str,
    model_identifier: str,
    sdk_version: str,
    prompt_sha256: str,
    implementation_tree_sha256: str,
    fixture_tree_sha256: str,
    mapper_timeout_seconds: float,
    started_at: datetime,
    latency_ms: int,
    usage: JsonObject,
    result: JsonObject,
) -> JsonObject:
    return {
        "schema_version": SCHEMA_VERSION_V22,
        "protocol_version": PROTOCOL_VERSION_V22,
        "run_id": FROZEN_RUN_ID_V22,
        "event": event,
        "arm": coordinate.arm,
        "repetition": coordinate.repetition,
        "condition": coordinate.condition,
        "condition_order": list(coordinate.condition_order),
        "condition_order_index": coordinate.condition_order_index,
        "started_at": started_at.isoformat(),
        "latency_ms": latency_ms,
        "model_identifier": model_identifier,
        "sdk_version": sdk_version,
        "prompt_sha256": prompt_sha256,
        "implementation_tree_sha256": implementation_tree_sha256,
        "fixture_tree_sha256": fixture_tree_sha256,
        "source_timeout_seconds": 0.5 if coordinate.arm == "canonical" else None,
        "source_max_attempts": 1 if coordinate.arm == "canonical" else None,
        "mapper_timeout_seconds": mapper_timeout_seconds,
        "mapper_max_retries": 0,
        "usage": usage,
        "result": result,
    }


def _usage_from_raw_mapper_calls_v22(value: object) -> JsonObject:
    if not isinstance(value, list):
        return _empty_usage_v22()
    totals: dict[str, list[int]] = {
        "input_tokens": [],
        "output_tokens": [],
        "total_tokens": [],
    }
    for item in value:
        if not isinstance(item, dict):
            continue
        for field in totals:
            observed = item.get(field)
            if isinstance(observed, int) and not isinstance(observed, bool) and observed >= 0:
                totals[field].append(observed)
    return {field: sum(items) if items else None for field, items in totals.items()}


def _usage_from_diagnostics_v22(diagnostics: Sequence[MapperCallDiagnostic]) -> JsonObject:
    return {
        field: sum(values) if values else None
        for field, values in (
            (
                "input_tokens",
                [item.input_tokens for item in diagnostics if item.input_tokens is not None],
            ),
            (
                "output_tokens",
                [item.output_tokens for item in diagnostics if item.output_tokens is not None],
            ),
            (
                "total_tokens",
                [item.total_tokens for item in diagnostics if item.total_tokens is not None],
            ),
        )
    }


def _empty_usage_v22() -> JsonObject:
    return {"input_tokens": None, "output_tokens": None, "total_tokens": None}


def _elapsed_ms_v22(started: float) -> int:
    return min(3_600_000, max(0, round((time.monotonic() - started) * 1000)))


def _distribution_version_v22(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:  # pragma: no cover - packaging guard
        return "unknown"


def _fsync_directory_v22(path: Path) -> None:
    """Durably commit a newly linked evidence or ledger directory entry."""

    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
