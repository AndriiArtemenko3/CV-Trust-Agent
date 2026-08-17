from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import httpx
import pytest
from reportlab.lib.pagesizes import A4  # type: ignore[import-untyped]
from reportlab.pdfgen import canvas  # type: ignore[import-untyped]

import cv_trust_agent.pdf_evidence as pdf_module
from cv_trust_agent.dataset import HIDDEN_CLAIM, Scenario, materialize_fixture_root, resume_path
from cv_trust_agent.pdf_evidence import (
    EvidenceVisibility,
    PdfEvidenceLimitError,
    extract_pdf_evidence,
)
from cv_trust_agent.retrieval import (
    MAX_BATCH_INDEX_BYTES,
    MAX_CANDIDATE_DETAIL_BYTES,
    MAX_CANDIDATES_PER_BATCH,
    MAX_RESUME_BYTES,
    HttpSourceClient,
    RetrievalProtocolError,
    RetrievalResourceLimitError,
)


def test_declared_index_length_is_rejected_before_body_is_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body_was_read = False

    class GuardedStream(httpx.SyncByteStream):
        def __iter__(self) -> Any:
            nonlocal body_was_read
            body_was_read = True
            yield b"{}"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-length": str(MAX_BATCH_INDEX_BYTES + 1)},
            stream=GuardedStream(),
            request=request,
        )

    _install_transport(monkeypatch, handler)
    with (
        HttpSourceClient("http://source.invalid") as client,
        pytest.raises(RetrievalResourceLimitError) as raised,
    ):
        client.fetch_index()

    assert str(raised.value) == "batch index exceeds byte limit"
    assert body_was_read is False
    assert raised.value.requests[0].path == "/v1/applications"


def test_actual_streamed_resume_length_is_bounded_without_content_length(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    oversized = b"%PDF" + (b"x" * (MAX_RESUME_BYTES - 3))

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            stream=httpx.ByteStream(oversized),
            request=request,
        )

    _install_transport(monkeypatch, handler)
    with (
        HttpSourceClient("http://source.invalid") as client,
        pytest.raises(RetrievalResourceLimitError) as raised,
    ):
        client.fetch_resume(
            candidate_id="AP-005",
            resume_url="http://source.invalid/v1/resumes/AP-005.pdf",
        )

    assert str(raised.value) == "resume exceeds byte limit"
    assert raised.value.requests[0].status_code == 200


def test_declared_candidate_detail_length_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-length": str(MAX_CANDIDATE_DETAIL_BYTES + 1)},
            stream=httpx.ByteStream(b"{}"),
            request=request,
        )

    _install_transport(monkeypatch, handler)
    with (
        HttpSourceClient("http://source.invalid") as client,
        pytest.raises(RetrievalResourceLimitError) as raised,
    ):
        client.fetch_candidate_detail(
            candidate_id="AP-005",
            detail_url="http://source.invalid/v1/applications/AP-005",
        )

    assert str(raised.value) == "candidate detail exceeds byte limit"
    assert raised.value.requests[0].path == "/v1/applications/AP-005"


def test_batch_candidate_count_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = {"candidates": [{"candidate_id": f"AP-{index:03d}"} for index in range(51)]}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=json.dumps(payload).encode(), request=request)

    _install_transport(monkeypatch, handler)
    with (
        HttpSourceClient("http://source.invalid") as client,
        pytest.raises(RetrievalResourceLimitError) as raised,
    ):
        client.fetch_index()

    assert MAX_CANDIDATES_PER_BATCH == 50
    assert str(raised.value) == "batch index exceeds candidate limit"


def test_invalid_content_length_is_a_sanitized_protocol_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-length": "not-a-length"},
            stream=httpx.ByteStream(b"{}"),
            request=request,
        )

    _install_transport(monkeypatch, handler)
    with (
        HttpSourceClient("http://source.invalid") as client,
        pytest.raises(RetrievalProtocolError) as raised,
    ):
        client.fetch_index()

    assert str(raised.value) == "batch index response has invalid content length"
    assert raised.value.requests[0].path == "/v1/applications"


def test_pdf_byte_and_page_limits_fail_closed(tmp_path: Path) -> None:
    with pytest.raises(PdfEvidenceLimitError, match="byte limit"):
        extract_pdf_evidence(b"%PDF" + (b"x" * pdf_module.MAX_PDF_BYTES))

    eleven_pages = tmp_path / "eleven-pages.pdf"
    _write_pdf(eleven_pages, page_count=11, text="bounded page")
    with pytest.raises(PdfEvidenceLimitError, match="page limit"):
        extract_pdf_evidence(eleven_pages)


def test_extracted_character_limit_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "text-limit.pdf"
    _write_pdf(target, page_count=1, text="more than ten characters")
    monkeypatch.setattr(pdf_module, "MAX_EXTRACTED_CHARACTERS", 10)

    with pytest.raises(PdfEvidenceLimitError, match="extracted text limit"):
        extract_pdf_evidence(target)


def test_microtext_preserves_font_size_and_is_not_visible(tmp_path: Path) -> None:
    root = materialize_fixture_root(tmp_path, Scenario.HIDDEN_MICROTEXT)
    extraction = extract_pdf_evidence(resume_path(root, "AP-005"))
    microtext = tuple(
        character
        for character in extraction.characters
        if character.visibility is EvidenceVisibility.MICROTEXT
    )

    assert "".join(character.text for character in microtext) == HIDDEN_CLAIM
    assert microtext
    assert all(character.font_size == pytest.approx(3.0) for character in microtext)
    assert all(character.contrast_ratio >= 3.0 for character in microtext)
    assert HIDDEN_CLAIM not in extraction.visible_text


def _install_transport(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
    transport = httpx.MockTransport(handler)
    real_client = httpx.Client

    def client_factory(*args: Any, **kwargs: Any) -> httpx.Client:
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr("cv_trust_agent.retrieval.httpx.Client", client_factory)


def _write_pdf(path: Path, *, page_count: int, text: str) -> None:
    output = io.BytesIO()
    document = canvas.Canvas(output, pagesize=A4, invariant=1, pageCompression=0)
    for _ in range(page_count):
        document.drawString(54, 700, text)
        document.showPage()
    document.save()
    path.write_bytes(output.getvalue())
