"""Capture-only helpers for V2 evaluation artifacts.

Capture records bounded observations and never decides whether they pass.  The
semantic release validators intentionally do not import this module.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import TypeAlias, cast

from cv_trust_agent.dataset import materialize_fixture_root
from cv_trust_agent.mappers import (
    DEFAULT_OPENAI_MODEL,
    OPENAI_MAPPER_INSTRUCTIONS,
    MapperCallDiagnostic,
    MapperError,
    MapperFailureCode,
    OpenAIResponsesMapper,
)
from evaluation.fixture_commitment import normalized_fixture_tree_hash
from evaluation.heldout_mapper import (
    HeldoutInstructionClient,
    build_heldout_mapper_requests,
    heldout_prompt_sha256,
)
from evaluation.heldout_oracle_spec_v2 import (
    heldout_oracle_sha256_v2,
    load_heldout_release_oracle_v2,
    validate_claim_value_v2,
)
from evaluation.oracle_spec_v2 import (
    DETERMINISTIC_ARTIFACT_KIND_V2,
    DeterministicOracleV2,
    oracle_sha256_v2,
)
from evaluation.release_spec_v2 import (
    DecisionProjectionV2,
    JsonObject,
    canonical_json_bytes,
    implementation_tree_sha256_v2,
    release_implementation_paths_v2,
)

FixtureMaterializerV2: TypeAlias = Callable[[Path, str], None]
_SECURE_PAIR_ORDERS_V2 = (
    ("clean", "directive"),
    ("directive", "clean"),
    ("clean", "directive"),
)
_SECURE_ATTEMPT_COUNT_V2 = 12
_MAX_PUBLIC_OUTPUT_BYTES = 16 * 1024 * 1024
_FORBIDDEN_CAPTURE_VERDICT_KEYS = frozenset(
    {
        "acceptance_checks",
        "accepted",
        "evaluable",
        "hard_gate_passed",
        "noninterference_passed",
        "pair_status",
        "passed",
        "protocol_complete",
        "safety_gate_passed",
        "safety_passed",
        "utility_observation_met",
        "utility_passed",
    }
)


class HeldoutClaimSchemaV2Error(ValueError):
    """A held-out mapper claim is outside the closed typed protocol."""


class HeldoutCitationV2Error(ValueError):
    """A held-out mapper citation is empty or outside its visible request."""


@dataclass(frozen=True, slots=True)
class CaseInputV2:
    """Evaluator-owned input registration; no runtime scenario enum is needed."""

    name: str
    fixture_id: str
    materialize: FixtureMaterializerV2
    source_scenario: str = "clean"
    mapper_fault: str | None = None
    fault_candidate: str | None = None
    fault_claim: str | None = None


@dataclass(frozen=True, slots=True)
class CapturedCaseV2:
    case_name: str
    fixture_id: str
    fixture_tree_sha256: str
    projection: DecisionProjectionV2

    def artifact_object(self) -> JsonObject:
        return {
            "case_name": self.case_name,
            "fixture_id": self.fixture_id,
            "fixture_tree_sha256": self.fixture_tree_sha256,
            "projection": self.projection.canonical_object(),
        }


class PublicCommandCaptureV2:
    """Capture one case through ordinary public ``serve`` and ``run`` commands."""

    def __init__(
        self,
        *,
        executable: str = "cv-trust",
        source_timeout_seconds: float = 0.5,
        process_timeout_seconds: float = 60.0,
    ) -> None:
        resolved = shutil.which(executable)
        if resolved is None:
            raise RuntimeError("cv-trust executable is unavailable")
        self._executable = resolved
        self._source_timeout_seconds = source_timeout_seconds
        self._process_timeout_seconds = process_timeout_seconds

    def __call__(self, case: CaseInputV2) -> CapturedCaseV2:
        port = _ephemeral_port()
        source_url = f"http://127.0.0.1:{port}"
        with TemporaryDirectory(prefix="cv-trust-v2-case-") as temporary:
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
            raise RuntimeError("public V2 case execution failed")
        if len(completed.stdout) > 16 * 1024 * 1024:
            raise RuntimeError("public V2 case output exceeded its bound")
        try:
            raw = json.loads(completed.stdout)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("public V2 case output was not JSON") from exc
        if not isinstance(raw, dict) or any(not isinstance(key, str) for key in raw):
            raise RuntimeError("public V2 case output was not an object")
        projection = DecisionProjectionV2.from_observation(cast(Mapping[str, object], raw))
        return CapturedCaseV2(
            case_name=case.name,
            fixture_id=case.fixture_id,
            fixture_tree_sha256=fixture_digest,
            projection=projection,
        )


def capture_deterministic_cases_v2(
    cases: Sequence[CaseInputV2],
    runner: Callable[[CaseInputV2], CapturedCaseV2],
) -> tuple[CapturedCaseV2, ...]:
    names = [case.name for case in cases]
    if not names or len(names) != len(set(names)):
        raise ValueError("V2 case registrations must be non-empty and unique")
    captured = tuple(runner(case) for case in cases)
    if [item.case_name for item in captured] != names:
        raise ValueError("capture runner changed the registered case order")
    return captured


def write_deterministic_observations_v2(
    output_path: Path,
    *,
    observations: Sequence[CapturedCaseV2],
    oracle: DeterministicOracleV2,
    implementation_tree_sha256: str,
) -> Path:
    """Write observations only; semantic verdicts are intentionally absent."""

    if output_path.exists():
        raise FileExistsError("V2 deterministic capture target already exists")
    if len(implementation_tree_sha256) != 64:
        raise ValueError("implementation tree digest is invalid")
    artifact: JsonObject = {
        "schema_version": 2,
        "artifact_kind": DETERMINISTIC_ARTIFACT_KIND_V2,
        "oracle_sha256": oracle_sha256_v2(oracle),
        "implementation_tree_sha256": implementation_tree_sha256,
        "observations": [item.artifact_object() for item in observations],
    }
    return _atomic_write_no_overwrite_v2(
        output_path,
        canonical_json_bytes(artifact) + b"\n",
        prefix=".deterministic-v2-",
    )


@dataclass(frozen=True, slots=True)
class SecureAttemptCoordinateV2:
    """One preregistered arm/condition coordinate in the twelve-call protocol."""

    arm: str
    repetition: int
    condition: str
    condition_order: tuple[str, str]
    condition_order_index: int


@dataclass(frozen=True, slots=True)
class SecureLiveCaptureV2:
    """Capture receipt only; it deliberately contains no release verdict."""

    artifact_path: Path
    attempt_count: int
    implementation_tree_sha256: str


def secure_attempt_schedule_v2() -> tuple[SecureAttemptCoordinateV2, ...]:
    """Return the exact canonical-then-held-out twelve-attempt schedule."""

    coordinates: list[SecureAttemptCoordinateV2] = []
    for arm in ("canonical", "heldout"):
        for repetition, condition_order in enumerate(_SECURE_PAIR_ORDERS_V2, start=1):
            for order_index, condition in enumerate(condition_order, start=1):
                coordinates.append(
                    SecureAttemptCoordinateV2(
                        arm=arm,
                        repetition=repetition,
                        condition=condition,
                        condition_order=condition_order,
                        condition_order_index=order_index,
                    )
                )
    if len(coordinates) != _SECURE_ATTEMPT_COUNT_V2:
        raise RuntimeError("secure V2 schedule is incomplete")
    return tuple(coordinates)


def capture_secure_live_v2(
    output_path: Path,
    *,
    execute_live_api: bool,
    repository_root: Path,
    executable: str = "cv-trust",
    canonical_model: str = DEFAULT_OPENAI_MODEL,
    heldout_model: str = DEFAULT_OPENAI_MODEL,
    heldout_oracle_path: Path | None = None,
    mapper_timeout_seconds: float = 30.0,
    process_timeout_seconds: float = 360.0,
) -> SecureLiveCaptureV2:
    """Capture twelve raw secure attempts after explicit paid-API authorization.

    This function performs capture only.  It never imports a semantic release
    validator and never writes utility, safety, pair-status, or pass booleans.
    """

    if not execute_live_api:
        raise PermissionError("secure V2 live capture requires explicit paid-API authorization")
    if mapper_timeout_seconds != 30.0:
        raise ValueError("secure V2 capture uses the frozen 30-second mapper deadline")
    root = repository_root.resolve()
    selected_oracle = heldout_oracle_path or root / "evaluation" / "heldout_release_oracle_v2.json"
    heldout_oracle = load_heldout_release_oracle_v2(selected_oracle)
    implementation_hash = implementation_tree_sha256_v2(
        release_implementation_paths_v2(root),
        repository_root=root,
    )
    resolved_executable = _resolve_executable(executable)
    sdk_version = _distribution_version("openai")
    rows: list[JsonObject] = []
    canonical_coordinates = tuple(
        item for item in secure_attempt_schedule_v2() if item.arm == "canonical"
    )
    heldout_coordinates = tuple(
        item for item in secure_attempt_schedule_v2() if item.arm == "heldout"
    )

    canonical_scenarios = {
        "clean": "clean",
        "directive": "structured_note_directive",
    }
    with TemporaryDirectory(prefix="cv-trust-secure-v2-") as temporary:
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
                rows.append(
                    _capture_canonical_live_attempt_v2(
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
                )
        finally:
            for _, process in sources.values():
                _stop_process(process)

    heldout_requests = {
        condition: build_heldout_mapper_requests(root, condition=condition)
        for condition in ("clean", "directive")
    }
    heldout_fixture_hashes = {
        condition: normalized_fixture_tree_hash(root / "evaluation" / "heldout" / condition)
        for condition in ("clean", "directive")
    }
    oracle_digest = heldout_oracle_sha256_v2(heldout_oracle)
    for coordinate in heldout_coordinates:
        rows.append(
            _capture_heldout_live_attempt_v2(
                coordinate,
                mapper_requests=heldout_requests[coordinate.condition],
                model_identifier=heldout_model,
                sdk_version=sdk_version,
                implementation_tree_sha256=implementation_hash,
                fixture_tree_sha256=heldout_fixture_hashes[coordinate.condition],
                heldout_oracle_sha256=oracle_digest,
                mapper_timeout_seconds=mapper_timeout_seconds,
            )
        )

    implementation_hash_after = implementation_tree_sha256_v2(
        release_implementation_paths_v2(root),
        repository_root=root,
    )
    if implementation_hash_after != implementation_hash:
        raise RuntimeError("implementation tree changed during secure V2 capture")
    target = write_secure_attempts_v2(output_path, attempts=rows)
    return SecureLiveCaptureV2(
        artifact_path=target,
        attempt_count=len(rows),
        implementation_tree_sha256=implementation_hash,
    )


def write_secure_attempts_v2(
    output_path: Path,
    *,
    attempts: Sequence[Mapping[str, object]],
) -> Path:
    """Atomically write exactly twelve bounded raw attempts, with no overwrite."""

    if output_path.exists():
        raise FileExistsError("secure V2 capture target already exists")
    if len(attempts) != _SECURE_ATTEMPT_COUNT_V2:
        raise ValueError("secure V2 capture must contain exactly twelve attempts")
    rows: list[bytes] = []
    for attempt in attempts:
        if _contains_capture_verdict_v2(attempt):
            raise ValueError("secure V2 capture cannot contain producer verdicts")
        row = canonical_json_bytes(dict(attempt))
        if not row or len(row) > _MAX_PUBLIC_OUTPUT_BYTES:
            raise ValueError("secure V2 capture row exceeds its bound")
        rows.append(row + b"\n")
    payload = b"".join(rows)
    if len(payload) > _MAX_PUBLIC_OUTPUT_BYTES:
        raise ValueError("secure V2 capture artifact exceeds its bound")
    return _atomic_write_no_overwrite_v2(
        output_path,
        payload,
        prefix=".secure-v2-",
    )


def _atomic_write_no_overwrite_v2(
    output_path: Path,
    payload: bytes,
    *,
    prefix: str,
) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with NamedTemporaryFile(
            mode="wb",
            dir=output_path.parent,
            prefix=prefix,
            delete=False,
        ) as temporary:
            temporary_name = temporary.name
            temporary.write(payload)
            temporary.flush()
            os.fsync(temporary.fileno())
        os.link(temporary_name, output_path)
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)
    return output_path


def _contains_capture_verdict_v2(value: object) -> bool:
    if isinstance(value, Mapping):
        return any(
            key in _FORBIDDEN_CAPTURE_VERDICT_KEYS or _contains_capture_verdict_v2(item)
            for key, item in value.items()
        )
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return any(_contains_capture_verdict_v2(item) for item in value)
    return False


def heldout_span_sha256(text: str) -> str:
    return hashlib.sha256(b"cv-trust-agent/heldout-span/v2\0" + text.encode("utf-8")).hexdigest()


def capture_typed_claims_v2(
    *,
    candidate_id: str,
    snapshot_id: str,
    claims: Sequence[Mapping[str, object]],
    tagged_visible_text: str,
) -> JsonObject:
    """Sanitize mapper claims while retaining independently checkable span hashes."""

    evidence_text: dict[str, str] = {}
    for line in tagged_visible_text.splitlines():
        if not line.startswith('<evidence id="') or '">' not in line:
            continue
        prefix, suffix = line.split('">', 1)
        if not suffix.endswith("</evidence>"):
            continue
        evidence_id = prefix.removeprefix('<evidence id="')
        evidence_text[evidence_id] = suffix.removesuffix("</evidence>")
    sanitized: list[JsonObject] = []
    for claim in claims:
        raw_ids = claim.get("evidence_ids")
        if not isinstance(raw_ids, list | tuple) or any(
            not isinstance(item, str) for item in raw_ids
        ):
            raise HeldoutCitationV2Error("held-out claim citations are invalid")
        evidence_ids = cast(Sequence[str], raw_ids)
        if not evidence_ids or any(item not in evidence_text for item in evidence_ids):
            raise HeldoutCitationV2Error("held-out claim cites text outside the mapper request")
        kind = claim.get("kind")
        if not isinstance(kind, str):
            raise HeldoutClaimSchemaV2Error("held-out claim kind is invalid")
        bool_value = claim.get("bool_value")
        number_value = claim.get("number_value")
        text_value = claim.get("text_value")
        start_date = claim.get("start_date")
        end_date = claim.get("end_date")
        if bool_value is not None and not isinstance(bool_value, bool):
            raise HeldoutClaimSchemaV2Error("held-out boolean claim value is invalid")
        if number_value is not None and (
            isinstance(number_value, bool) or not isinstance(number_value, int | float)
        ):
            raise HeldoutClaimSchemaV2Error("held-out numeric claim value is invalid")
        if text_value is not None and not isinstance(text_value, str):
            raise HeldoutClaimSchemaV2Error("held-out text claim value is invalid")
        if any(
            value is not None and not isinstance(value, str) for value in (start_date, end_date)
        ):
            raise HeldoutClaimSchemaV2Error("held-out claim date is invalid")
        try:
            validate_claim_value_v2(
                kind=kind,
                bool_value=bool_value,
                number_value=cast(float | None, number_value),
                text_value=text_value,
                start_date=cast(str | None, start_date),
                end_date=cast(str | None, end_date),
            )
        except ValueError as exc:
            raise HeldoutClaimSchemaV2Error(str(exc)) from exc
        sanitized.append(
            {
                "kind": kind,
                "bool_value": bool_value,
                "number_value": number_value,
                "text_value": text_value,
                "start_date": start_date,
                "end_date": end_date,
                "citation_span_sha256": [
                    heldout_span_sha256(evidence_text[item]) for item in evidence_ids
                ],
            }
        )
    return {
        "candidate_id": candidate_id,
        "snapshot_id": snapshot_id,
        "claims": sanitized,
    }


def _capture_canonical_live_attempt_v2(
    coordinate: SecureAttemptCoordinateV2,
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
    usage = _empty_usage_v2()
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
                projection = DecisionProjectionV2.from_observation(payload)
                usage = _usage_from_raw_mapper_calls_v2(payload.get("mapper_calls"))
            except (UnicodeError, json.JSONDecodeError, ValueError):
                result = {"kind": "failure", "failure_code": "invalid_sanitized_output"}
            else:
                result = {
                    "kind": "decision",
                    "projection": projection.canonical_object(),
                }
    return _secure_attempt_row_v2(
        coordinate,
        event="secure_canonical_attempt_v2",
        model_identifier=model_identifier,
        sdk_version=sdk_version,
        prompt_sha256=hashlib.sha256(OPENAI_MAPPER_INSTRUCTIONS.encode("utf-8")).hexdigest(),
        implementation_tree_sha256=implementation_tree_sha256,
        fixture_tree_sha256=fixture_tree_sha256,
        mapper_timeout_seconds=mapper_timeout_seconds,
        started_at=started_at,
        latency_ms=_elapsed_ms_v2(started),
        usage=usage,
        result=result,
    )


def _capture_heldout_live_attempt_v2(
    coordinate: SecureAttemptCoordinateV2,
    *,
    mapper_requests: Sequence[object],
    model_identifier: str,
    sdk_version: str,
    implementation_tree_sha256: str,
    fixture_tree_sha256: str,
    heldout_oracle_sha256: str,
    mapper_timeout_seconds: float,
) -> JsonObject:
    from openai import OpenAI, OpenAIError

    from cv_trust_agent.models import MapperRequest

    started_at = datetime.now(UTC)
    started = time.monotonic()
    diagnostics: list[MapperCallDiagnostic] = []

    def record_diagnostic(diagnostic: MapperCallDiagnostic) -> None:
        diagnostics.append(diagnostic)

    result: JsonObject
    try:
        mapper = OpenAIResponsesMapper(
            client=HeldoutInstructionClient(OpenAI(timeout=mapper_timeout_seconds, max_retries=0)),
            model=model_identifier,
            diagnostics=record_diagnostic,
        )
        candidates: list[JsonObject] = []
        for raw_request in mapper_requests:
            if not isinstance(raw_request, MapperRequest):
                raise ValueError("held-out mapper request has an invalid type")
            try:
                output = mapper.map_claims(raw_request)
            except MapperError as exc:
                candidates.append(
                    {
                        "candidate_id": raw_request.candidate_id,
                        "snapshot_id": raw_request.snapshot_id,
                        "outcome": "mapper_failure",
                        "failure_code": _heldout_mapper_failure_code_v2(exc.code),
                        "claims": [],
                    }
                )
                continue
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
                candidates.append(
                    {
                        "candidate_id": raw_request.candidate_id,
                        "snapshot_id": raw_request.snapshot_id,
                        "outcome": "mapper_failure",
                        "failure_code": "citation_failure",
                        "claims": [],
                    }
                )
                continue
            except (HeldoutClaimSchemaV2Error, KeyError, TypeError):
                candidates.append(
                    {
                        "candidate_id": raw_request.candidate_id,
                        "snapshot_id": raw_request.snapshot_id,
                        "outcome": "mapper_failure",
                        "failure_code": "schema_failure",
                        "claims": [],
                    }
                )
                continue
            candidates.append(
                {
                    "candidate_id": captured["candidate_id"],
                    "snapshot_id": captured["snapshot_id"],
                    "outcome": "mapped",
                    "failure_code": None,
                    "claims": captured["claims"],
                }
            )
        if len(candidates) != 4:
            raise ValueError("held-out capture did not produce four candidate observations")
        result = {"kind": "claims", "candidates": candidates}
    except (OSError, OpenAIError, RuntimeError):
        result = {"kind": "failure", "failure_code": "provider_failure"}
    except (KeyError, TypeError, ValueError):
        result = {"kind": "failure", "failure_code": "invalid_sanitized_output"}
    row = _secure_attempt_row_v2(
        coordinate,
        event="secure_heldout_attempt_v2",
        model_identifier=model_identifier,
        sdk_version=sdk_version,
        prompt_sha256=heldout_prompt_sha256(),
        implementation_tree_sha256=implementation_tree_sha256,
        fixture_tree_sha256=fixture_tree_sha256,
        mapper_timeout_seconds=mapper_timeout_seconds,
        started_at=started_at,
        latency_ms=_elapsed_ms_v2(started),
        usage=_usage_from_diagnostics_v2(diagnostics),
        result=result,
    )
    row["heldout_oracle_sha256"] = heldout_oracle_sha256
    return row


def _secure_attempt_row_v2(
    coordinate: SecureAttemptCoordinateV2,
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
        "schema_version": 2,
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


def _usage_from_raw_mapper_calls_v2(value: object) -> JsonObject:
    if not isinstance(value, list):
        return _empty_usage_v2()
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


def _usage_from_diagnostics_v2(diagnostics: Sequence[MapperCallDiagnostic]) -> JsonObject:
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


def _empty_usage_v2() -> JsonObject:
    return {"input_tokens": None, "output_tokens": None, "total_tokens": None}


def _heldout_mapper_failure_code_v2(code: MapperFailureCode) -> str:
    if code in {
        MapperFailureCode.STRUCTURED_OUTPUT_INVALID,
        MapperFailureCode.NO_PARSED_OUTPUT,
        MapperFailureCode.CANDIDATE_IDENTITY_MISMATCH,
        MapperFailureCode.SNAPSHOT_IDENTITY_MISMATCH,
    }:
        return "schema_failure"
    return "provider_failure"


def _elapsed_ms_v2(started: float) -> int:
    return min(3_600_000, max(0, round((time.monotonic() - started) * 1000)))


def _resolve_executable(value: str) -> str:
    if not value or Path(value).is_absolute() or "/" in value or "\\" in value:
        raise ValueError("secure V2 executable must be a PATH command name")
    resolved = shutil.which(value)
    if resolved is None:
        raise RuntimeError("secure V2 executable is unavailable")
    return resolved


def _distribution_version(name: str) -> str:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return "unavailable"


def _wait_for_source(process: subprocess.Popen[bytes], source_url: str) -> None:
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("source process exited during startup")
        try:
            with urllib.request.urlopen(f"{source_url}/health", timeout=0.2) as response:
                if response.status == 200:
                    return
        except (OSError, urllib.error.URLError):
            time.sleep(0.05)
    raise RuntimeError("source process did not become healthy")


def _stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def _ephemeral_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])
