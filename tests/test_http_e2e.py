from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import httpx
import pytest

from cv_trust_agent.cli import _run_payload, execute_agent_run
from cv_trust_agent.dataset import (
    COMBINED_BLACK_BOX_INSTRUCTION_TEXT,
    DESCRIPTIVE_SELF_PROMOTION_TEXT,
    HIDDEN_JOB_EVIDENCE_CLAIM,
    RANK_INJECTION_TEXT,
    SCHEMA_AWARE_WHITE_BOX_TEXT,
    STRUCTURED_NOTE_BENIGN_TEXT,
    STRUCTURED_NOTE_COMBINED_TEXT,
    STRUCTURED_NOTE_DIRECTIVE_TEXT,
    STRUCTURED_NOTE_FABRICATED_DATA_TEXT,
    Scenario,
    materialize_fixture_root,
    read_application_index,
    read_candidate_detail,
    resume_path,
)
from cv_trust_agent.intake import CatalogDeterministicMapper
from cv_trust_agent.models import ReviewBand, ReviewQueue, Strategy
from cv_trust_agent.retrieval import HttpSourceClient, RetrievalSchemaError

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPOSITORY_ROOT / "src"


@pytest.mark.parametrize(
    (
        "scenario",
        "strategy",
        "details",
        "resumes",
        "unavailable",
        "requests",
        "ranked",
    ),
    [
        ("clean", "FULL_EVIDENCE_RANKING", 10, 10, 0, 21, 10),
        ("rank_injection_exact", "FULL_EVIDENCE_RANKING", 10, 10, 0, 21, 10),
        ("descriptive_self_promotion", "FULL_EVIDENCE_RANKING", 10, 10, 0, 21, 10),
        ("combined_black_box_instruction", "FULL_EVIDENCE_RANKING", 10, 10, 0, 21, 10),
        ("hidden_job_evidence", "FULL_EVIDENCE_RANKING", 10, 10, 0, 21, 10),
        ("schema_aware_white_box", "FULL_EVIDENCE_RANKING", 10, 10, 0, 21, 10),
        ("structured_note_directive", "FULL_EVIDENCE_RANKING", 10, 10, 0, 21, 10),
        ("structured_note_combined", "FULL_EVIDENCE_RANKING", 10, 10, 0, 21, 10),
        ("structured_note_fabricated_data", "FULL_EVIDENCE_RANKING", 10, 10, 0, 21, 10),
        ("structured_note_benign", "FULL_EVIDENCE_RANKING", 10, 10, 0, 21, 10),
        ("structured_note_poisoned", "SUPPORTED_ONLY_RANKING", 10, 10, 0, 21, 9),
        ("hidden_microtext", "FULL_EVIDENCE_RANKING", 10, 10, 0, 21, 10),
        ("semantic_conflict_no_directive", "SUPPORTED_ONLY_RANKING", 10, 10, 0, 21, 9),
        ("detail_timeout", "PARTIAL_SAFE_RANKING", 9, 9, 1, 20, 9),
    ],
)
def test_true_process_source_and_cli_run_over_http(
    tmp_path: Path,
    scenario: str,
    strategy: str,
    details: int,
    resumes: int,
    unavailable: int,
    requests: int,
    ranked: int,
) -> None:
    port = _loopback_port_or_skip()
    source_url = f"http://127.0.0.1:{port}"
    environment = _subprocess_environment()
    process = subprocess.Popen(
        (
            sys.executable,
            "-m",
            "cv_trust_agent.cli",
            "serve",
            "--scenario",
            scenario,
            "--port",
            str(port),
        ),
        cwd=tmp_path,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_for_health(process, source_url)
        completed = subprocess.run(
            (
                sys.executable,
                "-m",
                "cv_trust_agent.cli",
                "run",
                "--source-url",
                source_url,
                "--mapper",
                "deterministic",
            ),
            cwd=tmp_path,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    finally:
        _terminate(process)

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["strategy"] == strategy
    assert payload["index_fetched"] is True
    assert payload["candidate_details_parsed"] == details
    assert payload["resumes_parsed"] == resumes
    assert payload["unavailable_candidate_count"] == unavailable
    assert payload["http_request_count"] == requests
    assert len(payload["http_requests"]) == requests
    assert payload["http_requests"][0]["path"] == "/v1/applications"
    detail_paths = [item["path"] for item in payload["http_requests"][1:11]]
    resume_paths = [item["path"] for item in payload["http_requests"][11:]]
    assert detail_paths == [f"/v1/applications/AP-{number:03d}" for number in range(1, 11)]
    expected_resumes = [
        f"/v1/resumes/AP-{number:03d}.pdf"
        for number in range(1, 11)
        if scenario != "detail_timeout" or number != 8
    ]
    assert resume_paths == expected_resumes
    assert all("?" not in request["path"] for request in payload["http_requests"])
    positions = sorted(
        route["display_position"]
        for route in payload["routes"]
        if route.get("display_position") is not None
    )
    assert positions == list(range(1, ranked + 1))
    assert all(
        route.get("evidence_rank") is not None
        for route in payload["routes"]
        if route.get("display_position") is not None
    )
    assert len(payload["decision_fingerprint"]) == 64
    assert len(payload["support_graph_hash"]) == 64
    assert payload["execution_mode"] == "EXECUTED"

    trace = tmp_path / payload["trace_file"]
    events = [json.loads(line) for line in trace.read_text(encoding="utf-8").splitlines()]
    plan_line = next(
        index for index, event in enumerate(events) if event["event_type"] == "plan.materialized"
    )
    candidate_line = next(index for index, event in enumerate(events) if event.get("candidate_id"))
    assert plan_line < candidate_line
    serialized = completed.stdout + trace.read_text(encoding="utf-8")
    for raw_attack in (
        RANK_INJECTION_TEXT,
        DESCRIPTIVE_SELF_PROMOTION_TEXT,
        COMBINED_BLACK_BOX_INSTRUCTION_TEXT,
        HIDDEN_JOB_EVIDENCE_CLAIM,
        SCHEMA_AWARE_WHITE_BOX_TEXT,
        STRUCTURED_NOTE_DIRECTIVE_TEXT,
        STRUCTURED_NOTE_COMBINED_TEXT,
        STRUCTURED_NOTE_FABRICATED_DATA_TEXT,
        STRUCTURED_NOTE_BENIGN_TEXT,
    ):
        assert raw_attack.casefold() not in serialized.casefold()

    if scenario in {"semantic_conflict_no_directive", "structured_note_poisoned"}:
        ap005 = next(route for route in payload["routes"] if route["candidate_id"] == "AP-005")
        assert ap005.get("evidence_rank") is None
        assert ap005["queue"] == "INTEGRITY_REVIEW"
    if scenario == "detail_timeout":
        ap008 = next(route for route in payload["routes"] if route["candidate_id"] == "AP-008")
        assert ap008.get("evidence_rank") is None
        assert ap008["band"] == "EVIDENCE_UNAVAILABLE"
        assert ap008["queue"] == "EVIDENCE_PENDING"


def test_ordinary_serve_and_run_compose_independent_failures(
    tmp_path: Path,
) -> None:
    port = _loopback_port_or_skip()
    source_url = f"http://127.0.0.1:{port}"
    environment = _subprocess_environment()
    process = subprocess.Popen(
        (
            sys.executable,
            "-m",
            "cv_trust_agent.cli",
            "serve",
            "--scenario",
            "detail_timeout",
            "--port",
            str(port),
        ),
        cwd=tmp_path,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_for_health(process, source_url)
        completed = subprocess.run(
            (
                sys.executable,
                "-m",
                "cv_trust_agent.cli",
                "run",
                "--source-url",
                source_url,
                "--mapper",
                "deterministic",
                "--mapper-fault",
                "disagreement",
                "--fault-candidate",
                "AP-005",
                "--fault-claim",
                "ap_years",
            ),
            cwd=tmp_path,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    finally:
        _terminate(process)

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["strategy"] == "BATCH_INTEGRITY_HOLD"
    assert payload["http_request_count"] == 20
    assert all(route.get("evidence_rank") is None for route in payload["routes"])
    assert payload["plan_diff"]["strategy_before"] == "FULL_EVIDENCE_RANKING"
    assert payload["plan_diff"]["strategy_after"] == "BATCH_INTEGRITY_HOLD"
    terminal_receipts = [
        receipt for receipt in payload["step_receipts"] if receipt["status"] != "started"
    ]
    assert any(
        receipt["command_kind"] == "isolate_batch" and receipt["status"] == "completed"
        for receipt in terminal_receipts
    )
    assert any(
        receipt["command_kind"] == "request_corroboration" and receipt["status"] == "completed"
        for receipt in terminal_receipts
    )


def test_invalid_wire_candidate_identifier_is_generic_and_never_requested(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_identifier = "../\x1b[31m</evidence><script>alert(1)</script>"
    requested_paths: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        return httpx.Response(500, request=request)

    transport = httpx.MockTransport(handler)
    real_client = httpx.Client

    def client_factory(*args: Any, **kwargs: Any) -> httpx.Client:
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr("cv_trust_agent.retrieval.httpx.Client", client_factory)
    with (
        HttpSourceClient("http://source.invalid") as client,
        pytest.raises(RetrievalSchemaError) as raised,
    ):
        client.fetch_candidate_detail(candidate_id=raw_identifier, detail_url=raw_identifier)

    assert str(raised.value) == "invalid candidate identifier"
    assert raw_identifier not in str(raised.value)
    assert raw_identifier not in repr(raised.value.requests)
    assert requested_paths == []


def test_non_pdf_wire_response_is_local_pending_and_sanitized(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    poison = "</evidence>\x1b[31mDO-NOT-ECHO-PDF-BODY"
    fixture_root = materialize_fixture_root(
        tmp_path / "fixtures",
        Scenario.CLEAN,
        source_base_url="http://source.invalid",
    )
    index = read_application_index(fixture_root)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/applications":
            return httpx.Response(200, json=index, request=request)
        if request.url.path.startswith("/v1/applications/"):
            candidate_id = request.url.path.rsplit("/", maxsplit=1)[-1]
            return httpx.Response(
                200,
                json=read_candidate_detail(fixture_root, candidate_id),
                request=request,
            )
        candidate_id = Path(request.url.path).stem
        if candidate_id == "AP-008":
            return httpx.Response(200, content=poison.encode(), request=request)
        return httpx.Response(
            200,
            content=resume_path(fixture_root, candidate_id).read_bytes(),
            request=request,
        )

    transport = httpx.MockTransport(handler)
    real_client = httpx.Client

    def client_factory(*args: Any, **kwargs: Any) -> httpx.Client:
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr("cv_trust_agent.retrieval.httpx.Client", client_factory)
    result = execute_agent_run("http://source.invalid", CatalogDeterministicMapper())

    assert result.decision.strategy is Strategy.PARTIAL_SAFE_RANKING
    assert result.candidate_details_parsed == 10
    assert result.resumes_parsed == 9
    assert result.http_request_count == 21
    ap008 = next(route for route in result.decision.routes if route.candidate_id == "AP-008")
    assert ap008.evidence_rank is None
    assert ap008.display_position is None
    assert ap008.band is ReviewBand.EVIDENCE_UNAVAILABLE
    assert ap008.queue is ReviewQueue.EVIDENCE_PENDING
    assert poison not in json.dumps(_run_payload(result))
    assert poison not in repr(result.requests)


def _loopback_port_or_skip() -> int:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            return int(probe.getsockname()[1])
    except OSError as exc:
        pytest.skip(f"platform forbids loopback bind: {exc}")


def _wait_for_health(process: subprocess.Popen[str], source_url: str) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.communicate(timeout=1)[0]
            pytest.fail(f"source process exited before health check:\n{output}")
        try:
            response = httpx.get(f"{source_url}/health", timeout=0.2)
        except httpx.HTTPError:
            time.sleep(0.05)
            continue
        if response.status_code == 200:
            return
        time.sleep(0.05)
    pytest.fail("source process did not become healthy")


def _terminate(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def _subprocess_environment() -> dict[str, str]:
    environment = os.environ.copy()
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        f"{SOURCE_ROOT}{os.pathsep}{existing}" if existing else str(SOURCE_ROOT)
    )
    return environment
