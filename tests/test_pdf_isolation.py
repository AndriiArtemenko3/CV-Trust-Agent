from __future__ import annotations

import copy
import json
import multiprocessing
import tempfile
from pathlib import Path
from typing import Any

import pytest

import cv_trust_agent.pdf_evidence as pdf_module
from cv_trust_agent.pdf_evidence import (
    PdfBatchBudget,
    PdfEvidenceLimitError,
    PdfEvidenceTimeoutError,
    PdfEvidenceWorkerError,
    extract_pdf_evidence,
)

_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_VALID_RESUME = _REPOSITORY_ROOT / "data/corpus/resumes/AP-001.pdf"


@pytest.fixture(scope="module")
def valid_worker_envelope() -> dict[str, Any]:
    extraction = extract_pdf_evidence(_VALID_RESUME)
    return {
        "status": "ok",
        "extraction": pdf_module._extraction_to_wire(extraction),
    }


def _install_worker_envelope(
    monkeypatch: pytest.MonkeyPatch,
    envelope: dict[str, Any],
) -> None:
    payload = json.dumps(envelope, allow_nan=True, separators=(",", ":")).encode("utf-8")
    monkeypatch.setattr(pdf_module, "_run_worker", lambda **_kwargs: payload)


def test_pdf_is_parsed_in_an_explicit_spawn_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected_methods: list[str] = []
    real_get_context = multiprocessing.get_context

    def tracked_get_context(method: str) -> Any:
        selected_methods.append(method)
        return real_get_context(method)

    monkeypatch.setattr(multiprocessing, "get_context", tracked_get_context)

    extraction = extract_pdf_evidence(_VALID_RESUME)

    assert selected_methods == ["spawn"]
    assert extraction.page_count == 1
    assert "Candidate ID: AP-001" in extraction.visible_text
    assert extraction.characters
    assert all(
        character.document_page_count == extraction.page_count
        and 1 <= character.page_number <= character.document_page_count
        and character.page_width > 0
        and character.page_height > 0
        for character in extraction.characters
    )


def test_worker_metadata_evidence_id_hashes_the_untrusted_key() -> None:
    raw_key = "/HIRE_ME"

    evidence_id = pdf_module._metadata_evidence_id("a" * 64, raw_key)

    assert raw_key not in evidence_id
    assert raw_key.removeprefix("/") not in evidence_id
    assert evidence_id.endswith("53d0a335e6fc184a60529f04ae9020901d465e2d4c0fc4208a1f60c80896e684")


def test_parent_timeout_terminates_worker_cleans_spool_and_does_not_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class HangingProcess:
        def __init__(self) -> None:
            self.exitcode: int | None = None
            self.alive = True
            self.start_count = 0
            self.join_timeouts: list[float | None] = []
            self.terminate_count = 0
            self.kill_count = 0
            self.close_count = 0

        def start(self) -> None:
            self.start_count += 1

        def join(self, timeout: float | None = None) -> None:
            self.join_timeouts.append(timeout)

        def is_alive(self) -> bool:
            return self.alive

        def terminate(self) -> None:
            self.terminate_count += 1
            self.alive = False
            self.exitcode = -15

        def kill(self) -> None:
            self.kill_count += 1
            self.alive = False
            self.exitcode = -9

        def close(self) -> None:
            self.close_count += 1

    process = HangingProcess()
    process_constructions: list[dict[str, object]] = []
    selected_methods: list[str] = []

    def tracked_get_context(method: str) -> Any:
        selected_methods.append(method)

        class Context:
            @staticmethod
            def Process(**kwargs: object) -> HangingProcess:
                process_constructions.append(kwargs)
                return process

        return Context()

    with monkeypatch.context() as isolated:
        isolated.setattr(tempfile, "tempdir", str(tmp_path))
        isolated.setattr(multiprocessing, "get_context", tracked_get_context)
        with pytest.raises(PdfEvidenceTimeoutError) as raised:
            extract_pdf_evidence(_VALID_RESUME)

    assert str(raised.value) == "resume PDF parsing timed out"
    assert selected_methods == ["spawn"]
    assert len(process_constructions) == 1
    assert process_constructions[0]["target"] is pdf_module._pdf_worker_main
    assert process_constructions[0]["name"] == "cv-trust-pdf-parser"
    assert process_constructions[0]["daemon"] is False
    assert process.start_count == 1
    assert len(process.join_timeouts) == 2
    assert process.join_timeouts[0] is not None
    assert 0 < process.join_timeouts[0] <= pdf_module.PDF_DOCUMENT_TIMEOUT_SECONDS
    assert process.join_timeouts[1] == 0.25
    assert process.terminate_count == 1
    assert process.kill_count == 0
    assert process.close_count == 1
    assert tuple(tmp_path.iterdir()) == ()
    assert "Candidate ID" in extract_pdf_evidence(_VALID_RESUME).visible_text


def test_expired_batch_budget_fails_before_starting_a_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current_time = [100.0]
    budget = PdfBatchBudget(20.0, clock=lambda: current_time[0])
    current_time[0] = 121.0

    def unexpected_context(_method: str) -> Any:
        raise AssertionError("an expired batch must not start a worker")

    monkeypatch.setattr(multiprocessing, "get_context", unexpected_context)

    with pytest.raises(PdfEvidenceTimeoutError) as raised:
        extract_pdf_evidence(_VALID_RESUME, batch_budget=budget)

    assert str(raised.value) == "resume PDF batch deadline exceeded"


def test_malformed_pdf_failure_is_sanitized_and_candidate_local() -> None:
    poison = "DO-NOT-ECHO-UNTRUSTED-PDF-CONTENT"

    with pytest.raises(PdfEvidenceWorkerError) as raised:
        extract_pdf_evidence(f"%PDF-1.7\n{poison}".encode())

    assert str(raised.value) == "resume PDF parsing failed"
    assert poison not in str(raised.value)
    # A failed worker has no persistent parser state and cannot poison the next candidate.
    assert "Candidate ID: AP-001" in extract_pdf_evidence(_VALID_RESUME).visible_text


@pytest.mark.parametrize(
    ("constant", "value", "message"),
    (
        ("MAX_PDF_LINES", 1, "resume PDF exceeds line limit"),
        ("MAX_PDF_METADATA_ITEMS", 1, "resume PDF exceeds metadata item limit"),
        ("MAX_PDF_RESULT_BYTES", 64, "resume PDF exceeds isolated result limit"),
    ),
)
def test_worker_enforces_line_metadata_and_result_bounds(
    constant: str,
    value: int,
    message: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(pdf_module, constant, value)

    with pytest.raises(PdfEvidenceLimitError) as raised:
        extract_pdf_evidence(_VALID_RESUME)

    assert str(raised.value) == message


def test_parent_rejects_malformed_worker_result_without_echoing_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    poison = "DO-NOT-ECHO-WORKER-PAYLOAD"

    def malformed_result(**_kwargs: object) -> bytes:
        return f'{{"status":"{poison}"}}'.encode()

    monkeypatch.setattr(pdf_module, "_run_worker", malformed_result)

    with pytest.raises(PdfEvidenceWorkerError) as raised:
        extract_pdf_evidence(_VALID_RESUME)

    assert str(raised.value) == "resume PDF parser returned an invalid result"
    assert poison not in str(raised.value)


@pytest.mark.parametrize(
    "mutation",
    (
        "off_page_labelled_visible",
        "low_contrast_labelled_visible",
        "microtext_labelled_visible",
        "inverted_horizontal_geometry",
        "inverted_vertical_geometry",
        "negative_font_size",
        "nonfinite_color",
        "nonfinite_contrast",
        "mismatched_contrast",
    ),
)
def test_parent_rejects_forged_character_geometry_and_classification(
    mutation: str,
    valid_worker_envelope: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = copy.deepcopy(valid_worker_envelope)
    extraction = envelope["extraction"]
    assert isinstance(extraction, dict)
    characters = extraction["characters"]
    assert isinstance(characters, list) and characters
    character = characters[0]
    assert isinstance(character, dict)

    if mutation == "off_page_labelled_visible":
        character.update({"x0": -1.0, "visibility": "visible"})
    elif mutation == "low_contrast_labelled_visible":
        color = (0.97, 0.97, 0.97)
        character.update(
            {
                "fill_color": list(color),
                "contrast_ratio": pdf_module._contrast_against_white(color),
                "visibility": "visible",
            }
        )
    elif mutation == "microtext_labelled_visible":
        character.update({"font_size": 3.0, "visibility": "visible"})
    elif mutation == "inverted_horizontal_geometry":
        character["x0"] = float(character["x1"]) + 1.0
    elif mutation == "inverted_vertical_geometry":
        character["top"] = float(character["bottom"]) + 1.0
    elif mutation == "negative_font_size":
        character["font_size"] = -1.0
    elif mutation == "nonfinite_color":
        character["fill_color"] = [float("nan")]
    elif mutation == "nonfinite_contrast":
        character["contrast_ratio"] = float("inf")
    else:
        character["contrast_ratio"] = float(character["contrast_ratio"]) + 1.0

    _install_worker_envelope(monkeypatch, envelope)

    with pytest.raises(PdfEvidenceWorkerError) as raised:
        extract_pdf_evidence(_VALID_RESUME)

    assert str(raised.value) == "resume PDF parser returned an invalid result"


def test_parent_accepts_off_page_character_only_with_recomputed_classification(
    valid_worker_envelope: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    envelope = copy.deepcopy(valid_worker_envelope)
    extraction = envelope["extraction"]
    assert isinstance(extraction, dict)
    characters = extraction["characters"]
    assert isinstance(characters, list) and characters
    character = characters[0]
    assert isinstance(character, dict)
    character.update({"x0": -1.0, "visibility": "off_page"})
    _install_worker_envelope(monkeypatch, envelope)

    parsed = extract_pdf_evidence(_VALID_RESUME)

    assert parsed.characters[0].x0 == -1.0
    assert parsed.characters[0].visibility is pdf_module.EvidenceVisibility.OFF_PAGE
