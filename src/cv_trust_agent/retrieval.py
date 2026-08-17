"""HTTP-only boundary for the untrusted applicant source.

The public workflow fetches one batch index, then one structured detail and one
resume for every indexed candidate. Index-provided URLs are treated as
commitments, not navigation authority: each must resolve to the canonical path
for its already-validated candidate identifier. There are no automatic
retries, and exceptions expose only fixed messages plus a bounded request
ledger.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

import httpx

_WIRE_CANDIDATE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
MAX_BATCH_INDEX_BYTES = 256 * 1024
MAX_CANDIDATE_DETAIL_BYTES = 64 * 1024
MAX_RESUME_BYTES = 5 * 1024 * 1024
MAX_CANDIDATES_PER_BATCH = 50
_MAX_HEALTH_BYTES = 16 * 1024


class RetrievalError(RuntimeError):
    """Base class for source-boundary failures."""

    def __init__(
        self,
        message: str,
        *,
        requests: tuple[RequestRecord, ...] = (),
    ) -> None:
        super().__init__(message)
        self.requests = requests


class RetrievalTimeout(RetrievalError):
    """Raised when one source component misses its deadline."""


class RetrievalProtocolError(RetrievalError):
    """Raised when the external source violates the minimal wire contract."""


class RetrievalSchemaError(RetrievalProtocolError):
    """An index or candidate-detail response cannot cross the strict schema boundary."""


class RetrievalParsingError(RetrievalProtocolError):
    """A resume response cannot cross the PDF parsing boundary."""


class RetrievalResourceLimitError(RetrievalProtocolError):
    """The external source exceeded a bounded input-resource contract."""


@dataclass(frozen=True)
class RequestRecord:
    """Sanitized request evidence safe to expose in a decision result."""

    method: str
    path: str
    status_code: int | None
    elapsed_ms: int


@dataclass(frozen=True)
class RetrievedBatchIndex:
    """The untrusted batch-index object and its single request record."""

    payload: dict[str, Any]
    requests: tuple[RequestRecord, ...]


@dataclass(frozen=True)
class RetrievedCandidateDetail:
    """One untrusted structured candidate detail."""

    candidate_id: str
    payload: dict[str, Any]
    requests: tuple[RequestRecord, ...]


@dataclass(frozen=True)
class RetrievedResume:
    """One untrusted candidate resume."""

    candidate_id: str
    content: bytes
    requests: tuple[RequestRecord, ...]


class HttpSourceClient:
    """Fetch an index and each indexed candidate component exactly once."""

    def __init__(self, base_url: str, *, timeout_seconds: float = 2.0) -> None:
        normalized_base = base_url.rstrip("/") + "/"
        self._base_url = httpx.URL(normalized_base)
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            timeout=httpx.Timeout(timeout_seconds),
            follow_redirects=False,
        )

    def __enter__(self) -> HttpSourceClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def health(self) -> bool:
        try:
            response, _ = self._get(
                "/health",
                component="health check",
                max_bytes=_MAX_HEALTH_BYTES,
            )
        except httpx.HTTPError:
            return False
        except RetrievalError:
            return False
        return response.status_code == 200

    def fetch_index(self) -> RetrievedBatchIndex:
        """Fetch the batch index exactly once."""

        path = "/v1/applications"
        response, request = self._get(
            path,
            component="batch index",
            max_bytes=MAX_BATCH_INDEX_BYTES,
        )
        try:
            payload = response.json()
        except ValueError as exc:
            raise RetrievalSchemaError(
                "batch index did not return valid JSON",
                requests=(request,),
            ) from exc
        if not isinstance(payload, dict):
            raise RetrievalSchemaError(
                "batch index must be a JSON object",
                requests=(request,),
            )
        candidates = payload.get("candidates")
        if isinstance(candidates, list) and len(candidates) > MAX_CANDIDATES_PER_BATCH:
            raise RetrievalResourceLimitError(
                "batch index exceeds candidate limit",
                requests=(request,),
            )
        return RetrievedBatchIndex(payload=payload, requests=(request,))

    def fetch_candidate_detail(
        self,
        *,
        candidate_id: str,
        detail_url: str,
    ) -> RetrievedCandidateDetail:
        """Fetch one indexed structured record exactly once."""

        encoded_id = _encoded_candidate_id(candidate_id)
        path = f"/v1/applications/{encoded_id}"
        self._require_canonical_url(detail_url, path, component="candidate detail")
        response, request = self._get(
            path,
            component="candidate detail",
            max_bytes=MAX_CANDIDATE_DETAIL_BYTES,
        )
        try:
            payload = response.json()
        except ValueError as exc:
            raise RetrievalSchemaError(
                "candidate detail did not return valid JSON",
                requests=(request,),
            ) from exc
        if not isinstance(payload, dict):
            raise RetrievalSchemaError(
                "candidate detail must be a JSON object",
                requests=(request,),
            )
        returned_id = payload.get("candidate_id")
        if returned_id != candidate_id:
            raise RetrievalSchemaError(
                "candidate detail identity mismatch",
                requests=(request,),
            )
        return RetrievedCandidateDetail(
            candidate_id=candidate_id,
            payload=payload,
            requests=(request,),
        )

    def fetch_resume(
        self,
        *,
        candidate_id: str,
        resume_url: str,
    ) -> RetrievedResume:
        """Fetch one indexed resume exactly once."""

        encoded_id = _encoded_candidate_id(candidate_id)
        path = f"/v1/resumes/{encoded_id}.pdf"
        self._require_canonical_url(resume_url, path, component="resume")
        response, request = self._get(
            path,
            component="resume",
            max_bytes=MAX_RESUME_BYTES,
        )
        if not response.content.startswith(b"%PDF"):
            raise RetrievalParsingError(
                "resume endpoint did not return a PDF",
                requests=(request,),
            )
        return RetrievedResume(
            candidate_id=candidate_id,
            content=response.content,
            requests=(request,),
        )

    def _get(
        self,
        path: str,
        *,
        component: str,
        max_bytes: int,
    ) -> tuple[httpx.Response, RequestRecord]:
        started = _monotonic_ms()
        status_code: int | None = None
        try:
            with self._client.stream("GET", path) as streamed:
                status_code = streamed.status_code
                request = RequestRecord(
                    "GET",
                    path,
                    status_code,
                    _monotonic_ms() - started,
                )
                try:
                    streamed.raise_for_status()
                except httpx.HTTPStatusError as exc:
                    raise RetrievalError(
                        f"{component} endpoint returned an error",
                        requests=(request,),
                    ) from exc

                declared_length = _content_length(
                    streamed,
                    component=component,
                    request=request,
                )
                if declared_length is not None and declared_length > max_bytes:
                    raise RetrievalResourceLimitError(
                        f"{component} exceeds byte limit",
                        requests=(request,),
                    )

                content = bytearray()
                for chunk in streamed.iter_bytes():
                    if len(chunk) > max_bytes - len(content):
                        raise RetrievalResourceLimitError(
                            f"{component} exceeds byte limit",
                            requests=(
                                RequestRecord(
                                    "GET",
                                    path,
                                    status_code,
                                    _monotonic_ms() - started,
                                ),
                            ),
                        )
                    content.extend(chunk)
                response = httpx.Response(
                    status_code=status_code,
                    headers=streamed.headers,
                    content=bytes(content),
                    request=streamed.request,
                )
        except RetrievalError:
            raise
        except httpx.TimeoutException as exc:
            request = RequestRecord("GET", path, status_code, _monotonic_ms() - started)
            raise RetrievalTimeout(
                f"{component} retrieval timed out",
                requests=(request,),
            ) from exc
        except httpx.HTTPError as exc:
            request = RequestRecord("GET", path, None, _monotonic_ms() - started)
            raise RetrievalError(
                f"{component} retrieval failed",
                requests=(request,),
            ) from exc

        request = RequestRecord("GET", path, status_code, _monotonic_ms() - started)
        return response, request

    def _require_canonical_url(self, raw_url: str, path: str, *, component: str) -> None:
        if not isinstance(raw_url, str) or not raw_url or len(raw_url) > 512:
            raise RetrievalSchemaError(f"{component} URL is invalid")
        try:
            supplied = self._base_url.join(raw_url)
            expected = self._base_url.join(path.removeprefix("/"))
        except (TypeError, ValueError) as exc:
            raise RetrievalSchemaError(f"{component} URL is invalid") from exc
        if supplied != expected:
            raise RetrievalSchemaError(f"{component} URL is invalid")


def _encoded_candidate_id(candidate_id: str) -> str:
    if not isinstance(candidate_id, str) or _WIRE_CANDIDATE_ID.fullmatch(candidate_id) is None:
        raise RetrievalSchemaError("invalid candidate identifier")
    return quote(candidate_id, safe="")


def _content_length(
    response: httpx.Response,
    *,
    component: str,
    request: RequestRecord,
) -> int | None:
    raw_length = response.headers.get("content-length")
    if raw_length is None:
        return None
    try:
        declared = int(raw_length)
    except ValueError as exc:
        raise RetrievalProtocolError(
            f"{component} response has invalid content length",
            requests=(request,),
        ) from exc
    if declared < 0:
        raise RetrievalProtocolError(
            f"{component} response has invalid content length",
            requests=(request,),
        )
    return declared


def _monotonic_ms() -> int:
    import time

    return int(time.monotonic() * 1_000)
