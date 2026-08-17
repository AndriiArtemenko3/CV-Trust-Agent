"""Typer command line interface for the CV-Trust demonstration."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any
from uuid import uuid4

import typer
import uvicorn
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from cv_trust_agent.dataset import Scenario
from cv_trust_agent.engine import (
    DetailFetchMaterial,
    DetailValidationMaterial,
    ExecutionMaterial,
    ResumeFetchMaterial,
    StartFailure,
    TrustedAgentEngine,
)
from cv_trust_agent.intake import (
    CatalogDeterministicMapper,
    IntakeError,
    prepare_candidate_detail,
    prepare_candidate_resume,
)
from cv_trust_agent.mappers import (
    DEFAULT_OPENAI_MODEL,
    ClaimMapper,
    FaultMapper,
    MapperCallDiagnostic,
    MapperFault,
    OpenAIResponsesMapper,
)
from cv_trust_agent.models import (
    BatchIndex,
    ReasonCode,
    RunDecision,
    TrustStage,
    UnavailableCandidate,
    UnavailableComponent,
)
from cv_trust_agent.pdf_evidence import PdfBatchBudget
from cv_trust_agent.retrieval import (
    HttpSourceClient,
    RequestRecord,
    RetrievalError,
    RetrievalParsingError,
    RetrievalSchemaError,
    RetrievalTimeout,
    RetrievedCandidateDetail,
    RetrievedResume,
)
from cv_trust_agent.telemetry import JsonlTelemetrySink, TelemetrySink

DEFAULT_FIXTURE_ROOT = Path("fixtures/generated")
SOURCE_REQUEST_TIMEOUT_SECONDS = 0.5
SOURCE_STARTUP_TIMEOUT_SECONDS = 8.0
MAPPER_REQUEST_TIMEOUT_SECONDS = 30.0
SOURCE_MAX_ATTEMPTS = 1
MAPPER_MAX_RETRIES = 0

app = typer.Typer(
    name="cv-trust",
    help="Evidence-gated ranking over an untrusted applicant source.",
    no_args_is_help=True,
    pretty_exceptions_show_locals=False,
)
fixtures_app = typer.Typer(help="Build and validate deterministic source fixtures.")
app.add_typer(fixtures_app, name="fixtures")
console = Console()


class MapperChoice(StrEnum):
    DETERMINISTIC = "deterministic"
    OPENAI = "openai"


class MapperFaultChoice(StrEnum):
    NONE = "none"
    DISAGREEMENT = "disagreement"


class FaultClaimChoice(StrEnum):
    AP_YEARS = "ap_years"


class DemoCase(StrEnum):
    CLEAN = "clean"
    STRUCTURED_NOTE_DIRECTIVE = "structured_note_directive"
    SEMANTIC_CONFLICT_NO_DIRECTIVE = "semantic_conflict_no_directive"
    COMPOUND = "compound"


@dataclass(frozen=True)
class AgentRun:
    """A sanitized decision plus observable retrieval counters."""

    decision: RunDecision
    source_timeout_seconds: float
    index_fetched: bool
    candidate_details_parsed: int
    resumes_parsed: int
    unavailable_candidate_count: int
    http_request_count: int
    requests: tuple[RequestRecord, ...]


class _HttpCandidateEvidenceProvider:
    """HTTP/intake adapter invoked only by the closed workflow executor."""

    def __init__(self, client: HttpSourceClient, request_ledger: list[RequestRecord]) -> None:
        self._client = client
        self._request_ledger = request_ledger
        self.candidate_details_parsed = 0
        self.resumes_parsed = 0
        self.unavailable_candidate_count = 0

    def fetch_candidate_details(self, index: BatchIndex) -> DetailFetchMaterial:
        details: list[RetrievedCandidateDetail] = []
        unavailable: list[UnavailableCandidate] = []
        for entry in index.candidates:
            try:
                retrieved = self._client.fetch_candidate_detail(
                    candidate_id=entry.candidate_id,
                    detail_url=entry.detail_url,
                )
            except RetrievalError as exc:
                self._request_ledger.extend(exc.requests)
                unavailable.append(
                    _unavailable_candidate(
                        entry.candidate_id,
                        UnavailableComponent.DETAIL,
                        exc,
                    )
                )
            else:
                self._request_ledger.extend(retrieved.requests)
                details.append(retrieved)
        self._record_unavailable(unavailable)
        return DetailFetchMaterial(tuple(details), tuple(unavailable))

    def validate_candidate_details(
        self,
        index: BatchIndex,
        fetched: DetailFetchMaterial,
    ) -> DetailValidationMaterial:
        entries = {entry.candidate_id: entry for entry in index.candidates}
        prepared = []
        unavailable = list(fetched.unavailable_candidates)
        for detail in fetched.retrieved_details:
            entry = entries.get(detail.candidate_id)
            if entry is None:
                unavailable.append(
                    UnavailableCandidate(
                        candidate_id=detail.candidate_id,
                        component=UnavailableComponent.DETAIL,
                        reason=ReasonCode.SCHEMA_INVALID,
                    )
                )
                continue
            try:
                candidate = prepare_candidate_detail(entry, detail)
            except IntakeError as exc:
                unavailable.append(
                    UnavailableCandidate(
                        candidate_id=entry.candidate_id,
                        component=UnavailableComponent.DETAIL,
                        reason=exc.reason,
                    )
                )
            else:
                prepared.append(candidate)
                self.candidate_details_parsed += 1
        self._record_unavailable(unavailable)
        return DetailValidationMaterial(tuple(prepared), tuple(unavailable))

    def fetch_candidate_resumes(
        self,
        index: BatchIndex,
        validated: DetailValidationMaterial,
    ) -> ResumeFetchMaterial:
        entries = {entry.candidate_id: entry for entry in index.candidates}
        resumes: list[RetrievedResume] = []
        unavailable = list(validated.unavailable_candidates)
        for detail in validated.prepared_details:
            entry = entries[detail.record.candidate_id]
            try:
                retrieved = self._client.fetch_resume(
                    candidate_id=entry.candidate_id,
                    resume_url=entry.resume_url,
                )
            except RetrievalError as exc:
                self._request_ledger.extend(exc.requests)
                unavailable.append(
                    _unavailable_candidate(
                        entry.candidate_id,
                        UnavailableComponent.RESUME,
                        exc,
                    )
                )
            else:
                self._request_ledger.extend(retrieved.requests)
                resumes.append(retrieved)
        self._record_unavailable(unavailable)
        return ResumeFetchMaterial(
            tuple(resumes),
            validated.prepared_details,
            tuple(unavailable),
        )

    def parse_candidate_resumes(
        self,
        index: BatchIndex,
        fetched: ResumeFetchMaterial,
    ) -> ExecutionMaterial:
        entries = {entry.candidate_id: entry for entry in index.candidates}
        details = {detail.record.candidate_id: detail for detail in fetched.prepared_details}
        records = []
        mapper_requests = []
        unavailable = list(fetched.unavailable_candidates)
        pdf_budget = PdfBatchBudget()
        for resume in fetched.retrieved_resumes:
            entry = entries.get(resume.candidate_id)
            detail = details.get(resume.candidate_id)
            if entry is None or detail is None:
                unavailable.append(
                    UnavailableCandidate(
                        candidate_id=resume.candidate_id,
                        component=UnavailableComponent.INTAKE,
                        reason=ReasonCode.SCHEMA_INVALID,
                    )
                )
                continue
            try:
                candidate = prepare_candidate_resume(
                    index,
                    entry,
                    detail,
                    resume,
                    batch_budget=pdf_budget,
                )
            except IntakeError as exc:
                unavailable.append(
                    UnavailableCandidate(
                        candidate_id=entry.candidate_id,
                        component=UnavailableComponent.INTAKE,
                        reason=exc.reason,
                    )
                )
            else:
                records.append(candidate.record)
                mapper_requests.append(candidate.mapper_request)
                self.resumes_parsed += 1
        self._record_unavailable(unavailable)
        return ExecutionMaterial(
            candidate_records=tuple(records),
            mapper_requests=tuple(mapper_requests),
            unavailable_candidates=tuple(unavailable),
        )

    def _record_unavailable(self, unavailable: list[UnavailableCandidate]) -> None:
        self.unavailable_candidate_count = len(
            {candidate.candidate_id for candidate in unavailable}
        )


@fixtures_app.command("build")
def fixtures_build(
    root: Annotated[
        Path,
        typer.Option("--root", help="Destination for generated clean fixtures."),
    ] = DEFAULT_FIXTURE_ROOT,
) -> None:
    """Build the deterministic clean index, details, and resumes."""

    from cv_trust_agent.dataset import Scenario, materialize_fixture_root

    try:
        materialize_fixture_root(root, Scenario.CLEAN)
    except Exception:
        _abort("fixture build failed")
    console.print("[green]Fixtures built:[/] 1 index, 10 details, 10 resumes")


@fixtures_app.command("validate")
def fixtures_validate(
    root: Annotated[
        Path,
        typer.Option("--root", help="Fixture root; generated temporarily when absent."),
    ] = DEFAULT_FIXTURE_ROOT,
) -> None:
    """Validate schema, hashes, PDFs, labels, and byte determinism."""

    try:
        stats = _validate_fixtures(root)
    except Exception:
        _abort("fixture validation failed")
    console.print(
        "[green]Fixtures valid:[/] "
        f"{stats['index_count']} index, "
        f"{stats['candidate_count']} candidates, "
        f"{stats['detail_count']} details, "
        f"{stats['resume_count']} resumes, deterministic bytes"
    )


@app.command("serve")
def serve(
    scenario: Annotated[
        Scenario,
        typer.Option("--scenario", case_sensitive=False),
    ] = Scenario.CLEAN,
    port: Annotated[int, typer.Option("--port", min=1, max=65535)] = 8000,
    fixture_root: Annotated[
        Path | None,
        typer.Option(
            "--fixture-root",
            help="Optional deterministic fixture root used by evidence-bound evaluations.",
        ),
    ] = None,
) -> None:
    """Serve one untrusted scenario over HTTP."""

    from cv_trust_agent.source import create_app

    source_app = create_app(
        scenario=scenario.value,
        fixture_root=fixture_root,
        public_base_url=f"http://127.0.0.1:{port}",
    )
    uvicorn.run(source_app, host="127.0.0.1", port=port, log_level="info")


@app.command("run")
def run_command(
    source_url: Annotated[
        str,
        typer.Option("--source-url", help="Base URL of the separate source process."),
    ],
    mapper: Annotated[
        MapperChoice,
        typer.Option("--mapper", case_sensitive=False),
    ] = MapperChoice.DETERMINISTIC,
    source_timeout: Annotated[
        float,
        typer.Option(
            "--source-timeout",
            min=0.05,
            max=60.0,
            help="One-attempt HTTP deadline in seconds.",
        ),
    ] = SOURCE_REQUEST_TIMEOUT_SECONDS,
    mapper_fault: Annotated[
        MapperFaultChoice,
        typer.Option("--mapper-fault", case_sensitive=False),
    ] = MapperFaultChoice.NONE,
    fault_candidate: Annotated[
        str,
        typer.Option("--fault-candidate", help="Validated candidate ID for a controlled fault."),
    ] = "AP-005",
    fault_claim: Annotated[
        FaultClaimChoice,
        typer.Option("--fault-claim", case_sensitive=False),
    ] = FaultClaimChoice.AP_YEARS,
) -> None:
    """Fetch one indexed cohort and emit a sanitized JSON ranking decision."""

    run_id = f"cli-{uuid4().hex[:12]}"
    trace_path = Path("run-traces") / f"{run_id}.jsonl"
    diagnostics: list[MapperCallDiagnostic] = []
    try:
        selected_mapper = _make_mapper(
            mapper,
            mapper_fault=mapper_fault,
            fault_candidate=_validated_fault_candidate(fault_candidate),
            fault_claim=fault_claim,
            diagnostics=diagnostics.append,
        )
        result = execute_agent_run(
            source_url,
            selected_mapper,
            telemetry=JsonlTelemetrySink(trace_path),
            run_id=run_id,
            timeout_seconds=source_timeout,
        )
    except Exception as exc:
        _abort_run(exc)
    payload = _run_payload(result, mapper_diagnostics=diagnostics)
    payload["trace_file"] = trace_path.as_posix()
    typer.echo(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False))


@app.command("demo")
def demo(
    case: Annotated[
        DemoCase,
        typer.Option("--case", case_sensitive=False),
    ] = DemoCase.CLEAN,
    mapper: Annotated[
        MapperChoice,
        typer.Option("--mapper", case_sensitive=False),
    ] = MapperChoice.DETERMINISTIC,
) -> None:
    """Start a separate source process, run once, and clean it up."""

    try:
        scenario, mapper_fault = _demo_configuration(case)
        result = _run_demo_scenario(
            scenario,
            mapper,
            mapper_fault=mapper_fault,
            fault_candidate="AP-005",
        )
    except Exception as exc:
        _abort_run(exc)
    _render_run_summary("CV-Trust demo", case.value, result)
    _render_demo_details(result.decision)


def execute_agent_run(
    source_url: str,
    mapper: ClaimMapper,
    *,
    telemetry: TelemetrySink | None = None,
    run_id: str | None = None,
    timeout_seconds: float = SOURCE_REQUEST_TIMEOUT_SECONDS,
) -> AgentRun:
    """Fetch an index, then let the trusted plan execute candidate materialization."""

    selected_run_id = run_id or f"run-{uuid4().hex[:12]}"
    engine = TrustedAgentEngine(mapper, telemetry=telemetry)
    request_ledger: list[RequestRecord] = []
    client = HttpSourceClient(source_url, timeout_seconds=timeout_seconds)
    try:
        try:
            retrieved_index = client.fetch_index()
        except RetrievalError as exc:
            stage, reason = _retrieval_failure_trust(exc)
            decision = engine.fail_closed(
                run_id=selected_run_id,
                stage=stage,
                reason=reason,
            )
            return AgentRun(
                decision=decision,
                source_timeout_seconds=timeout_seconds,
                index_fetched=False,
                candidate_details_parsed=0,
                resumes_parsed=0,
                unavailable_candidate_count=0,
                http_request_count=len(exc.requests),
                requests=exc.requests,
            )
        request_ledger.extend(retrieved_index.requests)
        try:
            checkpoint = engine.start(retrieved_index.payload, run_id=selected_run_id)
        except StartFailure as exc:
            return AgentRun(
                decision=exc.decision,
                source_timeout_seconds=timeout_seconds,
                index_fetched=True,
                candidate_details_parsed=0,
                resumes_parsed=0,
                unavailable_candidate_count=0,
                http_request_count=len(request_ledger),
                requests=tuple(request_ledger),
            )
        provider = _HttpCandidateEvidenceProvider(client, request_ledger)
        decision = engine.execute(checkpoint, provider)
        return AgentRun(
            decision=decision,
            source_timeout_seconds=timeout_seconds,
            index_fetched=True,
            candidate_details_parsed=provider.candidate_details_parsed,
            resumes_parsed=provider.resumes_parsed,
            unavailable_candidate_count=provider.unavailable_candidate_count,
            http_request_count=len(request_ledger),
            requests=tuple(request_ledger),
        )
    finally:
        client.close()


def _unavailable_candidate(
    candidate_id: str,
    component: UnavailableComponent,
    exc: RetrievalError,
) -> UnavailableCandidate:
    _, reason = _retrieval_failure_trust(exc)
    return UnavailableCandidate(candidate_id=candidate_id, component=component, reason=reason)


def _make_mapper(
    choice: MapperChoice,
    *,
    mapper_fault: MapperFaultChoice = MapperFaultChoice.NONE,
    fault_candidate: str = "AP-005",
    fault_claim: FaultClaimChoice = FaultClaimChoice.AP_YEARS,
    diagnostics: Any | None = None,
) -> ClaimMapper:
    base: ClaimMapper
    if choice is MapperChoice.DETERMINISTIC:
        base = CatalogDeterministicMapper()
    else:
        configured_model = os.getenv("CV_TRUST_OPENAI_MODEL", DEFAULT_OPENAI_MODEL).strip()
        base = OpenAIResponsesMapper(
            model=configured_model or DEFAULT_OPENAI_MODEL,
            timeout_seconds=MAPPER_REQUEST_TIMEOUT_SECONDS,
            diagnostics=diagnostics,
        )
    if mapper_fault is MapperFaultChoice.NONE:
        return base
    if fault_claim is not FaultClaimChoice.AP_YEARS:
        raise ValueError("unsupported controlled fault claim")
    return FaultMapper(
        base,
        {("*", fault_candidate): MapperFault.AP_YEARS_DISAGREEMENT},
    )


def _validated_fault_candidate(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", value) is None:
        raise ValueError("fault candidate violates the safe identifier contract")
    return value


def _demo_configuration(case: DemoCase) -> tuple[Scenario, MapperFaultChoice]:
    if case is DemoCase.COMPOUND:
        return Scenario.DETAIL_TIMEOUT, MapperFaultChoice.DISAGREEMENT
    return Scenario(case.value), MapperFaultChoice.NONE


def _run_demo_scenario(
    scenario: Scenario,
    mapper: MapperChoice,
    *,
    mapper_fault: MapperFaultChoice = MapperFaultChoice.NONE,
    fault_candidate: str = "AP-005",
) -> AgentRun:
    port = _ephemeral_port()
    source_url = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory(prefix="cv-trust-demo-") as fixture_root:
        command = (
            sys.executable,
            "-m",
            "cv_trust_agent.source",
            "--scenario",
            scenario.value,
            "--fixture-root",
            fixture_root,
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        )
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            _wait_for_source(process, source_url)
            selected_mapper = _make_mapper(
                mapper,
                mapper_fault=mapper_fault,
                fault_candidate=fault_candidate,
            )
            return execute_agent_run(source_url, selected_mapper)
        finally:
            _stop_process(process)


def _wait_for_source(process: subprocess.Popen[bytes], source_url: str) -> None:
    deadline = time.monotonic() + SOURCE_STARTUP_TIMEOUT_SECONDS
    with HttpSourceClient(source_url, timeout_seconds=0.2) as client:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("source process exited during startup")
            if client.health():
                return
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


def _run_payload(
    result: AgentRun,
    *,
    mapper_diagnostics: list[MapperCallDiagnostic] | None = None,
) -> dict[str, Any]:
    payload = result.decision.model_dump(mode="json", exclude_none=True)
    payload.update(
        {
            "index_fetched": result.index_fetched,
            "candidate_details_parsed": result.candidate_details_parsed,
            "resumes_parsed": result.resumes_parsed,
            "unavailable_candidate_count": result.unavailable_candidate_count,
            "http_request_count": result.http_request_count,
            "runtime_policy": {
                "source_max_attempts": SOURCE_MAX_ATTEMPTS,
                "source_timeout_seconds": result.source_timeout_seconds,
                "mapper_max_retries": MAPPER_MAX_RETRIES,
                "mapper_timeout_seconds": MAPPER_REQUEST_TIMEOUT_SECONDS,
            },
            "decision_fingerprint": _decision_fingerprint(result.decision),
            "support_graph_hash": result.decision.support_graph_hash,
            "http_requests": [
                {
                    "method": request.method,
                    "path": request.path,
                    "status_code": request.status_code,
                    "elapsed_ms": request.elapsed_ms,
                }
                for request in result.requests
            ],
            "mapper_calls": [
                {
                    "mapper_name": diagnostic.mapper_name,
                    "model": diagnostic.model,
                    "candidate_id": diagnostic.candidate_id,
                    "snapshot_id": diagnostic.snapshot_id,
                    "outcome": diagnostic.outcome.value,
                    "failure_code": (
                        diagnostic.failure_code.value if diagnostic.failure_code else None
                    ),
                    "latency_ms": diagnostic.latency_ms,
                    "claim_count": diagnostic.claim_count,
                    "citation_count": diagnostic.citation_count,
                    "response_id_hash": diagnostic.response_id_hash,
                    "input_tokens": diagnostic.input_tokens,
                    "output_tokens": diagnostic.output_tokens,
                    "total_tokens": diagnostic.total_tokens,
                }
                for diagnostic in (mapper_diagnostics or [])
            ],
        }
    )
    return payload


def _render_run_summary(title: str, name: str, result: AgentRun) -> None:
    table = Table(title=title)
    table.add_column("Case", overflow="fold")
    table.add_column("Evidence", overflow="fold")
    table.add_column("Trusted decision", overflow="fold")
    table.add_column("Ranking / exclusions", overflow="fold")
    ap005_route = next(
        (route for route in result.decision.routes if route.candidate_id == "AP-005"),
        None,
    )
    ap005 = (
        "absent"
        if ap005_route is None
        else (
            f"evidence-rank {ap005_route.evidence_rank}, "
            f"display {ap005_route.display_position} {ap005_route.band.value}"
            if ap005_route.evidence_rank is not None
            else f"excluded {ap005_route.band.value}"
        )
    )
    ranked = sorted(
        (route for route in result.decision.routes if route.display_position is not None),
        key=lambda route: route.display_position or 0,
    )
    excluded = [
        route.candidate_id for route in result.decision.routes if route.display_position is None
    ]
    ranking = " > ".join(route.candidate_id for route in ranked) or "—"
    excluded_text = ", ".join(excluded) or "—"
    table.add_row(
        name,
        "\n".join(
            (
                f"Index: {'yes' if result.index_fetched else 'no'}",
                f"Detail/CV: {result.candidate_details_parsed}/{result.resumes_parsed}",
                f"HTTP: {result.http_request_count}",
            )
        ),
        "\n".join(
            (
                result.decision.strategy.value,
                f"AP-005: {ap005}",
                f"Fingerprint: {_decision_fingerprint(result.decision)[:12]}",
            )
        ),
        "\n".join(
            (
                f"Ranked: {len(ranked)} / excluded: {len(excluded)}",
                f"Order: {ranking}",
                f"Excluded IDs: {excluded_text}",
            )
        ),
    )
    console.print(table)


def _render_demo_details(decision: RunDecision) -> None:
    console.print("\n[bold]Evidence ranking[/bold]")
    ranking_table = Table(show_header=True)
    ranking_table.add_column("Evidence rank", justify="right")
    ranking_table.add_column("Display", justify="right")
    ranking_table.add_column("Candidate")
    ranking_table.add_column("Band")
    ranking_table.add_column("Queue")
    for route in sorted(
        decision.routes,
        key=lambda item: (
            item.display_position is None,
            item.display_position or 0,
            item.candidate_id,
        ),
    ):
        ranking_table.add_row(
            str(route.evidence_rank) if route.evidence_rank is not None else "—",
            str(route.display_position) if route.display_position is not None else "—",
            route.candidate_id,
            route.band.value,
            route.queue.value,
        )
    console.print(ranking_table)

    diff = decision.plan_diff
    console.print("\n[bold]Plan[/bold]")
    if diff is None:
        console.print(f"Retained: {decision.plan.strategy.value} (version {decision.plan.version})")
    else:
        console.print(f"Before → after: {diff.strategy_before.value} → {diff.strategy_after.value}")
        console.print("Triggers: " + ", ".join(reason.value for reason in diff.trigger_codes))
        console.print("Removed commands: " + (", ".join(diff.removed_command_ids) or "none"))
        console.print(
            "Added commands: "
            + (", ".join(command.command_id for command in diff.added_commands) or "none")
        )
        console.print(
            "Evidence: "
            f"revoked={len(diff.revoked_evidence_ids)}, "
            f"granted={len(diff.granted_evidence_ids)}, "
            f"allowed={len(decision.plan.allowed_evidence_ids)}"
        )

    console.print("\n[bold]Executed command receipts[/bold]")
    receipt_table = Table(show_header=True)
    receipt_table.add_column("Plan")
    receipt_table.add_column("Command")
    receipt_table.add_column("State")
    for receipt in decision.step_receipts:
        receipt_table.add_row(
            f"v{receipt.plan_version}",
            receipt.command_kind.value,
            receipt.status.value,
        )
    console.print(receipt_table)

    console.print("\n[bold]Explanations[/bold]")
    explanation_table = Table(show_header=True)
    explanation_table.add_column("Candidate")
    explanation_table.add_column("Template")
    explanation_table.add_column("Sanitized explanation")
    for explanation in decision.explanations:
        explanation_table.add_row(
            explanation.candidate_id or "batch",
            explanation.template.value,
            explanation.message,
        )
    console.print(explanation_table)


def _decision_fingerprint(decision: RunDecision) -> str:
    trusted_semantics = {
        "strategy": decision.strategy.value,
        "ranking_scope": decision.ranking_scope.value,
        "routes": [
            {
                "candidate_id": route.candidate_id,
                "band": route.band.value,
                "queue": route.queue.value,
                "evidence_rank": route.evidence_rank,
                "display_position": route.display_position,
                "rank_key": route.rank_key.model_dump(mode="json") if route.rank_key else None,
                "support_graph_present": route.support_graph is not None,
            }
            for route in sorted(decision.routes, key=lambda item: item.candidate_id)
        ],
        "plans": [
            {
                "version": plan.version,
                "objective": plan.objective.value,
                "strategy": plan.strategy.value,
                "commands": [
                    {
                        "command_id": command.command_id,
                        "kind": command.kind.value,
                        "scope": command.scope.value,
                        "candidate_id": command.candidate_id,
                        "dependency_ids": list(command.dependency_ids),
                    }
                    for command in plan.commands
                ],
                "prohibited_actions": [action.value for action in plan.prohibited_actions],
            }
            for plan in decision.plans
        ],
        "step_receipts": [
            {
                "plan_version": receipt.plan_version,
                "command_id": receipt.command_id,
                "kind": receipt.command_kind.value,
                "status": receipt.status.value,
            }
            for receipt in decision.step_receipts
        ],
        "corroboration_requests": [
            request.model_dump(mode="json") for request in decision.corroboration_requests
        ],
        "support_graph_hash": decision.support_graph_hash,
    }
    encoded = json.dumps(
        trusted_semantics,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_fixtures(root: Path) -> dict[str, int]:
    from cv_trust_agent.dataset import (
        Scenario,
        application_index_path,
        candidate_detail_path,
        compute_index_manifest_hash,
        compute_semantic_hash,
        materialize_fixture_root,
        read_application_index,
        read_candidate_detail,
        resume_path,
    )
    from cv_trust_agent.pdf_evidence import extract_pdf_evidence

    with tempfile.TemporaryDirectory(prefix="cv-trust-validation-") as temporary:
        selected_root = root
        if not selected_root.is_dir():
            selected_root = Path(temporary) / "fixtures"
            materialize_fixture_root(selected_root, Scenario.CLEAN)

        file_bytes: dict[str, bytes] = {}
        raw_index = read_application_index(selected_root)
        index = _strict_index(raw_index)
        if len(index.candidates) != 10:
            raise ValueError("fixture candidate count is not ten")
        raw_candidates = raw_index.get("candidates")
        if not isinstance(raw_candidates, list):
            raise ValueError("fixture index candidates are missing")
        if compute_index_manifest_hash(raw_candidates) != index.manifest_hash:
            raise ValueError("fixture index manifest hash is invalid")
        _assert_no_gold_labels(raw_index)

        for entry in index.candidates:
            raw_detail = read_candidate_detail(selected_root, entry.candidate_id)
            detail = _strict_candidate_detail(raw_detail)
            if (
                detail.candidate_id != entry.candidate_id
                or detail.record_revision != entry.record_revision
                or detail.semantic_hash != entry.semantic_hash
                or detail.resume_url != entry.resume_url
                or compute_semantic_hash(raw_detail) != detail.semantic_hash
            ):
                raise ValueError("fixture candidate detail commitment is invalid")
            _assert_no_gold_labels(raw_detail)
            detail_path = candidate_detail_path(selected_root, entry.candidate_id)
            file_bytes[detail_path.relative_to(selected_root).as_posix()] = detail_path.read_bytes()

            pdf_path = resume_path(selected_root, entry.candidate_id)
            pdf_bytes = pdf_path.read_bytes()
            extraction = extract_pdf_evidence(pdf_bytes)
            if extraction.page_count != 1:
                raise ValueError("fixture resume is not one page")
            if f"Candidate ID: {entry.candidate_id}" not in extraction.visible_text:
                raise ValueError("fixture resume identity is not visibly supported")
            if hashlib.sha256(pdf_bytes).hexdigest() != entry.resume_sha256:
                raise ValueError("fixture resume commitment is invalid")
            file_bytes[pdf_path.relative_to(selected_root).as_posix()] = pdf_bytes

        index_path = application_index_path(selected_root)
        file_bytes[index_path.relative_to(selected_root).as_posix()] = index_path.read_bytes()

        reference_root = Path(temporary) / "reference"
        materialize_fixture_root(reference_root, Scenario.CLEAN)
        for relative, expected_bytes in file_bytes.items():
            if (reference_root / relative).read_bytes() != expected_bytes:
                raise ValueError("fixture bytes are not deterministic")

    return {
        "index_count": 1,
        "candidate_count": len(index.candidates),
        "detail_count": len(index.candidates),
        "resume_count": len(index.candidates),
    }


def _strict_index(raw: Mapping[str, Any]) -> BatchIndex:
    try:
        return BatchIndex.model_validate(raw)
    except ValidationError as exc:
        raise ValueError("fixture index failed strict validation") from exc


def _strict_candidate_detail(raw: Mapping[str, Any]) -> Any:
    from cv_trust_agent.models import CandidateRecord

    try:
        return CandidateRecord.model_validate(raw)
    except ValidationError as exc:
        raise ValueError("fixture candidate detail failed strict validation") from exc


def _assert_no_gold_labels(value: object) -> None:
    banned = {
        "expected_band",
        "expected_queue",
        "expected_strategy",
        "gold_label",
        "scenario",
    }
    if isinstance(value, Mapping):
        if any(str(key).casefold() in banned for key in value):
            raise ValueError("fixture payload contains private evaluation labels")
        for item in value.values():
            _assert_no_gold_labels(item)
    elif isinstance(value, list | tuple):
        for item in value:
            _assert_no_gold_labels(item)


def _abort_run(exc: Exception) -> None:
    if isinstance(exc, RetrievalTimeout):
        _abort("source evidence retrieval timed out")
    if isinstance(exc, RetrievalError):
        _abort("source retrieval failed")
    if isinstance(exc, IntakeError):
        _abort("source evidence failed strict intake")
    _abort("trusted run could not be completed")


def _retrieval_failure_trust(exc: RetrievalError) -> tuple[TrustStage, ReasonCode]:
    if isinstance(exc, RetrievalSchemaError):
        return TrustStage.SCHEMA, ReasonCode.SCHEMA_INVALID
    if isinstance(exc, RetrievalParsingError):
        return TrustStage.PARSING, ReasonCode.PARSING_FAILED
    return TrustStage.RETRIEVAL, ReasonCode.RETRIEVAL_FAILED


def _abort(message: str) -> None:
    Console(stderr=True).print(f"[red]Error:[/] {message}")
    raise typer.Exit(code=1)


if __name__ == "__main__":  # pragma: no cover - exercised by process tests
    app()
