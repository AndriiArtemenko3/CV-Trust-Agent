"""Separate FastAPI process serving deliberately untrusted synthetic evidence."""

from __future__ import annotations

import argparse
import asyncio
import copy
import json
import os
import re
import tempfile
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse

from cv_trust_agent.dataset import (
    INDEX_ID,
    Scenario,
    application_index_path,
    materialize_fixture_root,
    parse_scenario,
    read_application_index,
    scenario_has_detail_delay,
)

# The public CLI's bounded source deadline is 0.5 seconds.  Keep the controlled
# failure comfortably above it so the timeout does not depend on machine speed.
DEFAULT_TIMEOUT_DELAY_SECONDS = 1.0


@dataclass(frozen=True)
class SourceSettings:
    """Source-process configuration; never serialized in API responses."""

    scenario: Scenario
    fixture_root: Path
    timeout_delay_seconds: float
    public_base_url: str | None = None

    @classmethod
    def from_env(cls) -> SourceSettings:
        """Read source configuration from documented environment variables."""

        scenario = parse_scenario(os.getenv("CV_TRUST_SCENARIO", Scenario.CLEAN.value))
        root_value = os.getenv("CV_TRUST_FIXTURE_ROOT")
        fixture_root = Path(root_value) if root_value else _default_fixture_root(scenario)
        delay_value = os.getenv(
            "CV_TRUST_TIMEOUT_DELAY_SECONDS",
            str(DEFAULT_TIMEOUT_DELAY_SECONDS),
        )
        try:
            timeout_delay_seconds = float(delay_value)
        except ValueError as exc:
            raise ValueError("CV_TRUST_TIMEOUT_DELAY_SECONDS must be numeric") from exc
        if timeout_delay_seconds < 0:
            raise ValueError("CV_TRUST_TIMEOUT_DELAY_SECONDS must be non-negative")
        public_base_url = os.getenv("CV_TRUST_SOURCE_BASE_URL") or None
        return cls(
            scenario=scenario,
            fixture_root=fixture_root,
            timeout_delay_seconds=timeout_delay_seconds,
            public_base_url=public_base_url,
        )


class FixtureStore:
    """Lazy, process-local view of one generated untrusted source root."""

    def __init__(self, settings: SourceSettings) -> None:
        self.settings = settings
        self._lock = threading.Lock()
        self._ready = False
        self._candidate_ids: frozenset[str] = frozenset()
        self._index_id = INDEX_ID

    def ensure_ready(self) -> None:
        if self._ready:
            return
        with self._lock:
            if not self._ready:
                # A caller-supplied, already materialized root is an evaluator-owned
                # input.  Serving it verbatim keeps the source generic and prevents
                # the production fixture generator from overwriting an independently
                # authored cohort.  Empty roots retain the normal scenario generator.
                if not application_index_path(self.settings.fixture_root).is_file():
                    materialize_fixture_root(
                        self.settings.fixture_root,
                        self.settings.scenario,
                        source_base_url=(self.settings.public_base_url or "http://127.0.0.1:8000"),
                    )
                index = read_application_index(self.settings.fixture_root)
                self._candidate_ids = _candidate_ids(index)
                index_id = index.get("index_id")
                if (
                    not isinstance(index_id, str)
                    or _SOURCE_CANDIDATE_ID.fullmatch(index_id) is None
                ):
                    raise RuntimeError("generated fixture contains an invalid index identity")
                self._index_id = index_id
                self._ready = True

    def candidate_ids(self) -> frozenset[str]:
        """Return the strict identities committed by the materialized index."""

        self.ensure_ready()
        return self._candidate_ids

    def index_id(self) -> str:
        """Return the strict index identity used by response metadata."""

        self.ensure_ready()
        return self._index_id

    def index(self, *, request_base_url: str) -> dict[str, Any]:
        self.ensure_ready()
        index = copy.deepcopy(read_application_index(self.settings.fixture_root))
        candidates = index.get("candidates")
        if not isinstance(candidates, list):
            raise RuntimeError("generated fixture index has no candidates list")
        public_base_url = (self.settings.public_base_url or request_base_url).rstrip("/")
        for raw_entry in candidates:
            if not isinstance(raw_entry, dict):
                raise RuntimeError("generated fixture contains a non-object index entry")
            candidate_id = raw_entry.get("candidate_id")
            if not isinstance(candidate_id, str):
                raise RuntimeError("generated fixture index entry has no candidate_id")
            raw_entry["detail_url"] = f"{public_base_url}/v1/applications/{candidate_id}"
            raw_entry["resume_url"] = f"{public_base_url}/v1/resumes/{candidate_id}.pdf"
        return index

    def detail(self, candidate_id: str, *, request_base_url: str) -> dict[str, Any]:
        self.ensure_ready()
        if candidate_id not in self._candidate_ids:
            raise KeyError(candidate_id)
        detail = copy.deepcopy(
            _read_json_object(
                self.settings.fixture_root / "details" / f"{candidate_id}.json",
                "candidate detail",
            )
        )
        public_base_url = (self.settings.public_base_url or request_base_url).rstrip("/")
        detail["resume_url"] = f"{public_base_url}/v1/resumes/{candidate_id}.pdf"
        return detail

    def resume(self, candidate_id: str) -> Path:
        self.ensure_ready()
        if candidate_id not in self._candidate_ids:
            raise KeyError(candidate_id)
        path = self.settings.fixture_root / "resumes" / f"{candidate_id}.pdf"
        if not path.is_file():
            raise FileNotFoundError(path)
        return path


def create_app(
    *,
    scenario: Scenario | str | None = None,
    fixture_root: Path | str | None = None,
    timeout_delay_seconds: float | None = None,
    public_base_url: str | None = None,
) -> FastAPI:
    """Create an untrusted source app using explicit values over environment defaults."""

    env_settings = SourceSettings.from_env()
    selected_scenario = parse_scenario(scenario or env_settings.scenario)
    selected_root = (
        Path(fixture_root)
        if fixture_root is not None
        else (
            env_settings.fixture_root
            if scenario is None or os.getenv("CV_TRUST_FIXTURE_ROOT")
            else _default_fixture_root(selected_scenario)
        )
    )
    selected_delay = (
        env_settings.timeout_delay_seconds
        if timeout_delay_seconds is None
        else timeout_delay_seconds
    )
    if selected_delay < 0:
        raise ValueError("timeout_delay_seconds must be non-negative")
    settings = SourceSettings(
        scenario=selected_scenario,
        fixture_root=selected_root,
        timeout_delay_seconds=selected_delay,
        public_base_url=(
            env_settings.public_base_url if public_base_url is None else public_base_url
        ),
    )
    store = FixtureStore(settings)

    source_app = FastAPI(
        title="CV-Trust synthetic applicant source",
        version="2.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    source_app.state.source_settings = settings
    source_app.state.fixture_store = store

    @source_app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @source_app.get("/v1/applications")
    async def applications(request: Request) -> JSONResponse:
        payload = store.index(request_base_url=str(request.base_url))
        return JSONResponse(payload, headers=_response_headers(store.index_id()))

    @source_app.get("/v1/applications/{candidate_id}")
    async def application_detail(candidate_id: str, request: Request) -> JSONResponse:
        if candidate_id not in store.candidate_ids():
            raise HTTPException(status_code=404, detail="application detail not found")
        if scenario_has_detail_delay(settings.scenario, candidate_id):
            await asyncio.sleep(settings.timeout_delay_seconds)
        try:
            payload = store.detail(candidate_id, request_base_url=str(request.base_url))
        except (KeyError, FileNotFoundError) as exc:
            raise HTTPException(status_code=404, detail="application detail not found") from exc
        return JSONResponse(payload, headers=_response_headers(store.index_id()))

    @source_app.get("/v1/resumes/{candidate_id}.pdf")
    async def resume(candidate_id: str) -> FileResponse:
        if candidate_id not in store.candidate_ids():
            raise HTTPException(status_code=404, detail="resume not found")
        try:
            path = store.resume(candidate_id)
        except (KeyError, FileNotFoundError) as exc:
            raise HTTPException(status_code=404, detail="resume not found") from exc
        return FileResponse(
            path,
            media_type="application/pdf",
            filename=f"{candidate_id}.pdf",
            headers=_response_headers(store.index_id()),
        )

    return source_app


def main(argv: Sequence[str] | None = None) -> None:
    """Run the external source as its own process."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--scenario",
        choices=[scenario.value for scenario in Scenario],
        default=None,
        help="source scenario; defaults to CV_TRUST_SCENARIO or clean",
    )
    parser.add_argument("--fixture-root", type=Path, default=None)
    parser.add_argument("--timeout-delay-seconds", type=float, default=None)
    parser.add_argument("--public-base-url", default=None)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    source_app = create_app(
        scenario=args.scenario,
        fixture_root=args.fixture_root,
        timeout_delay_seconds=args.timeout_delay_seconds,
        public_base_url=args.public_base_url,
    )
    uvicorn.run(source_app, host=args.host, port=args.port, log_level="info")


def _response_headers(index_id: str = INDEX_ID) -> dict[str, str]:
    return {"Cache-Control": "no-store", "X-Index-ID": index_id}


_SOURCE_CANDIDATE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")


def _candidate_ids(index: dict[str, Any]) -> frozenset[str]:
    raw_candidates = index.get("candidates")
    if not isinstance(raw_candidates, list) or not raw_candidates:
        raise RuntimeError("generated fixture index has no candidates list")
    candidate_ids: list[str] = []
    for raw_entry in raw_candidates:
        if not isinstance(raw_entry, dict):
            raise RuntimeError("generated fixture contains a non-object index entry")
        candidate_id = raw_entry.get("candidate_id")
        if (
            not isinstance(candidate_id, str)
            or _SOURCE_CANDIDATE_ID.fullmatch(candidate_id) is None
        ):
            raise RuntimeError("generated fixture contains an invalid candidate identity")
        candidate_ids.append(candidate_id)
    if len(candidate_ids) != len(set(candidate_ids)):
        raise RuntimeError("generated fixture contains duplicate candidate identities")
    return frozenset(candidate_ids)


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise FileNotFoundError(path) from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"generated {label} must be a JSON object")
    return value


def _default_fixture_root(scenario: Scenario) -> Path:
    return Path(tempfile.gettempdir()) / "cv-trust-agent-source" / f"{scenario.value}-{os.getpid()}"


app = create_app()


if __name__ == "__main__":  # pragma: no cover - exercised by process-level tests
    main()
