"""Offline fake-provider reproduction of mapper wire and SDK boundary branches.

The V2.1 live failure collapsed distinct pipeline stages into one category
without any offline reproduction.  These tests drive the *real* OpenAI SDK
``responses.parse`` path through an in-process transport for structured output,
identity, missing output, status, connection, and timeout behavior. Property
coverage proves the wire-to-runtime conversion is total for every schema-valid
payload except the two closed residual categories.
"""

from __future__ import annotations

import json
from typing import Any

import httpx2 as httpx
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from openai import OpenAI

from cv_trust_agent.mapper_wire import (
    AccountingPlatformWireClaim,
    ApYearsWireClaim,
    BooleanWireClaim,
    IntervalWireClaim,
    MapperWireError,
    MapperWireOutput,
    MonthlyInvoiceVolumeWireClaim,
    QualificationWireClaim,
    SpreadsheetWireClaim,
    wire_output_to_mapper_output,
)
from cv_trust_agent.mappers import (
    MapperCallDiagnostic,
    MapperCallOutcome,
    MapperError,
    MapperFailureCode,
    OpenAIResponsesMapper,
)
from cv_trust_agent.models import ClaimKind, MapperOutput
from tests.test_mappers import _mapper_request

Json = dict[str, Any]


def _response_body(output_text: str | None, *, status: str = "completed") -> Json:
    output: list[Json] = []
    if output_text is not None:
        output.append(
            {
                "type": "message",
                "id": "msg_1",
                "status": "completed",
                "role": "assistant",
                "content": [
                    {
                        "type": "output_text",
                        "text": output_text,
                        "annotations": [],
                    }
                ],
            }
        )
    return {
        "id": "resp_offline_test",
        "object": "response",
        "created_at": 1_755_400_000,
        "model": "gpt-test-snapshot",
        "status": status,
        "error": None,
        "incomplete_details": ({"reason": "max_output_tokens"} if status == "incomplete" else None),
        "instructions": None,
        "max_output_tokens": None,
        "metadata": {},
        "parallel_tool_calls": False,
        "temperature": None,
        "tool_choice": "none",
        "tools": [],
        "top_p": None,
        "output": output,
        "usage": {
            "input_tokens": 100,
            "output_tokens": 20,
            "total_tokens": 120,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens_details": {"reasoning_tokens": 0},
        },
    }


def _mapper_for(
    handler: httpx.MockTransport,
    *,
    diagnostics: list[MapperCallDiagnostic] | None = None,
) -> OpenAIResponsesMapper:
    def record_diagnostic(diagnostic: MapperCallDiagnostic) -> None:
        if diagnostics is not None:
            diagnostics.append(diagnostic)

    client = OpenAI(
        api_key="test-key-not-real",
        http_client=httpx.Client(transport=handler),
        max_retries=0,
    )
    return OpenAIResponsesMapper(
        client=client,
        model="gpt-test-snapshot",
        diagnostics=(record_diagnostic if diagnostics is not None else None),
    )


def _json_transport(body: Json, status_code: int = 200) -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: httpx.Response(status_code, json=body))


class TestSdkBranchReproduction:
    def test_wire_valid_payload_maps_end_to_end(self) -> None:
        request = _mapper_request()
        wire_payload = {
            "candidate_id": request.candidate_id,
            "snapshot_id": request.snapshot_id,
            "claims": [
                {"kind": "ap_years", "value": 3.5, "evidence_ids": ["pdf-visible-admissible"]},
                {
                    "kind": "invoice_processing",
                    "value": True,
                    "evidence_ids": ["pdf-visible-admissible"],
                },
            ],
        }
        mapper = _mapper_for(_json_transport(_response_body(json.dumps(wire_payload))))
        output = mapper.map_claims(request)
        assert isinstance(output, MapperOutput)
        assert [claim.kind for claim in output.claims] == [
            ClaimKind.AP_YEARS,
            ClaimKind.INVOICE_PROCESSING,
        ]
        assert all(claim.candidate_id == request.candidate_id for claim in output.claims)

    def test_schema_violating_model_output_is_structured_output_invalid(self) -> None:
        request = _mapper_request()
        wire_payload = {
            "candidate_id": request.candidate_id,
            "snapshot_id": request.snapshot_id,
            "claims": [
                {
                    "kind": "candidate_id",
                    "value": "AP-005 SECRET_NOTE",
                    "evidence_ids": ["pdf-visible-admissible"],
                }
            ],
        }
        mapper = _mapper_for(_json_transport(_response_body(json.dumps(wire_payload))))
        with pytest.raises(MapperError) as exc:
            mapper.map_claims(request)
        assert exc.value.code is MapperFailureCode.STRUCTURED_OUTPUT_INVALID
        assert "SECRET_NOTE" not in str(exc.value)

    def test_cross_field_slot_confusion_cannot_survive_the_wire(self) -> None:
        """The V2.1 trap: value slots for the wrong kind now fail closed."""

        request = _mapper_request()
        wire_payload = {
            "candidate_id": request.candidate_id,
            "snapshot_id": request.snapshot_id,
            "claims": [
                {
                    "kind": "ap_years",
                    "value": "three point five",
                    "evidence_ids": ["pdf-visible-admissible"],
                }
            ],
        }
        mapper = _mapper_for(_json_transport(_response_body(json.dumps(wire_payload))))
        with pytest.raises(MapperError) as exc:
            mapper.map_claims(request)
        assert exc.value.code is MapperFailureCode.STRUCTURED_OUTPUT_INVALID

    @pytest.mark.parametrize(
        ("kind", "value"),
        [
            ("ap_years", "3.5"),
            ("ap_years", True),
            ("ap_years", 80.0001),
            ("monthly_invoice_volume", "420"),
            ("monthly_invoice_volume", 420.0),
            ("monthly_invoice_volume", False),
            ("invoice_processing", "true"),
            ("invoice_processing", 1),
            ("spreadsheet", "Excel and anything else"),
        ],
    )
    def test_scalar_coercions_bounds_and_open_categories_fail_sdk_parse(
        self,
        kind: str,
        value: object,
    ) -> None:
        request = _mapper_request()
        wire_payload = {
            "candidate_id": request.candidate_id,
            "snapshot_id": request.snapshot_id,
            "claims": [
                {
                    "kind": kind,
                    "value": value,
                    "evidence_ids": ["pdf-visible-admissible"],
                }
            ],
        }
        mapper = _mapper_for(_json_transport(_response_body(json.dumps(wire_payload))))

        with pytest.raises(MapperError) as exc:
            mapper.map_claims(request)

        assert exc.value.code is MapperFailureCode.STRUCTURED_OUTPUT_INVALID

    def test_heldout_microsoft_excel_literal_maps_to_canonical_excel(self) -> None:
        request = _mapper_request()
        wire_payload = {
            "candidate_id": request.candidate_id,
            "snapshot_id": request.snapshot_id,
            "claims": [
                {
                    "kind": "spreadsheet",
                    "value": "Microsoft Excel",
                    "evidence_ids": ["pdf-visible-admissible"],
                }
            ],
        }
        mapper = _mapper_for(_json_transport(_response_body(json.dumps(wire_payload))))

        output = mapper.map_claims(request)

        assert output.claims[0].kind is ClaimKind.SPREADSHEET
        assert output.claims[0].text_value == "Excel"

    def test_month_name_date_is_a_closed_wire_category(self) -> None:
        request = _mapper_request()
        wire_payload = {
            "candidate_id": request.candidate_id,
            "snapshot_id": request.snapshot_id,
            "claims": [
                {
                    "kind": "employment_interval",
                    "start_date": "2024-02-30",
                    "end_date": "2025-07-31",
                    "evidence_ids": ["pdf-visible-admissible"],
                }
            ],
        }
        mapper = _mapper_for(_json_transport(_response_body(json.dumps(wire_payload))))
        with pytest.raises(MapperError) as exc:
            mapper.map_claims(request)
        assert exc.value.code is MapperFailureCode.WIRE_DATE_INVALID

    def test_reversed_interval_is_a_closed_wire_category(self) -> None:
        request = _mapper_request()
        wire_payload = {
            "candidate_id": request.candidate_id,
            "snapshot_id": request.snapshot_id,
            "claims": [
                {
                    "kind": "employment_interval",
                    "start_date": "2025-07-31",
                    "end_date": "2022-06-01",
                    "evidence_ids": ["pdf-visible-admissible"],
                }
            ],
        }
        mapper = _mapper_for(_json_transport(_response_body(json.dumps(wire_payload))))
        with pytest.raises(MapperError) as exc:
            mapper.map_claims(request)
        assert exc.value.code is MapperFailureCode.WIRE_INTERVAL_ORDER_INVALID

    def test_identity_mismatch_is_detected_after_parse(self) -> None:
        request = _mapper_request()
        wire_payload = {
            "candidate_id": "AP-999",
            "snapshot_id": request.snapshot_id,
            "claims": [],
        }
        mapper = _mapper_for(_json_transport(_response_body(json.dumps(wire_payload))))
        with pytest.raises(MapperError) as exc:
            mapper.map_claims(request)
        assert exc.value.code is MapperFailureCode.CANDIDATE_IDENTITY_MISMATCH

    def test_snapshot_mismatch_diagnostic_binds_the_trusted_request_snapshot(self) -> None:
        request = _mapper_request()
        wire_payload = {
            "candidate_id": request.candidate_id,
            "snapshot_id": "index-999",
            "claims": [],
        }
        diagnostics: list[MapperCallDiagnostic] = []
        mapper = _mapper_for(
            _json_transport(_response_body(json.dumps(wire_payload))),
            diagnostics=diagnostics,
        )

        with pytest.raises(MapperError) as exc:
            mapper.map_claims(request)

        assert exc.value.code is MapperFailureCode.SNAPSHOT_IDENTITY_MISMATCH
        assert len(diagnostics) == 1
        assert diagnostics[0].candidate_id == request.candidate_id
        assert diagnostics[0].snapshot_id == request.snapshot_id
        assert diagnostics[0].outcome is MapperCallOutcome.FAILURE
        assert diagnostics[0].failure_code is MapperFailureCode.SNAPSHOT_IDENTITY_MISMATCH

    def test_sdk_transport_failure_diagnostic_uses_closed_code_and_trusted_identity(
        self,
    ) -> None:
        request = _mapper_request()

        def fail_provider(http_request: httpx.Request) -> httpx.Response:
            del http_request
            raise RuntimeError("provider-controlled SECRET_SENTINEL")

        diagnostics: list[MapperCallDiagnostic] = []
        mapper = _mapper_for(httpx.MockTransport(fail_provider), diagnostics=diagnostics)

        with pytest.raises(MapperError) as exc:
            mapper.map_claims(request)

        assert exc.value.code is MapperFailureCode.PROVIDER_CONNECTION
        assert diagnostics[0].candidate_id == request.candidate_id
        assert diagnostics[0].snapshot_id == request.snapshot_id
        assert diagnostics[0].failure_code is MapperFailureCode.PROVIDER_CONNECTION
        assert "SECRET_SENTINEL" not in repr(diagnostics[0])

    def test_sdk_usage_outside_diagnostic_bounds_is_discarded(self) -> None:
        request = _mapper_request()
        body = _response_body(
            json.dumps(
                {
                    "candidate_id": request.candidate_id,
                    "snapshot_id": request.snapshot_id,
                    "claims": [],
                }
            )
        )
        usage = body["usage"]
        assert isinstance(usage, dict)
        usage["input_tokens"] = 10_000_001
        usage["output_tokens"] = -1
        usage["total_tokens"] = True
        diagnostics: list[MapperCallDiagnostic] = []
        mapper = _mapper_for(_json_transport(body), diagnostics=diagnostics)

        mapper.map_claims(request)

        assert diagnostics[0].input_tokens is None
        assert diagnostics[0].output_tokens is None
        assert diagnostics[0].total_tokens is None

    def test_incomplete_response_is_no_parsed_output(self) -> None:
        request = _mapper_request()
        mapper = _mapper_for(_json_transport(_response_body(None, status="incomplete")))
        with pytest.raises(MapperError) as exc:
            mapper.map_claims(request)
        assert exc.value.code is MapperFailureCode.NO_PARSED_OUTPUT

    def test_http_status_error_is_provider_status(self) -> None:
        request = _mapper_request()
        transport = httpx.MockTransport(
            lambda http_request: httpx.Response(500, json={"error": {"message": "boom"}})
        )
        mapper = _mapper_for(transport)
        with pytest.raises(MapperError) as exc:
            mapper.map_claims(request)
        assert exc.value.code is MapperFailureCode.PROVIDER_STATUS

    def test_connection_error_is_provider_connection(self) -> None:
        request = _mapper_request()

        def raise_connect(http_request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=http_request)

        mapper = _mapper_for(httpx.MockTransport(raise_connect))
        with pytest.raises(MapperError) as exc:
            mapper.map_claims(request)
        assert exc.value.code is MapperFailureCode.PROVIDER_CONNECTION

    def test_timeout_is_provider_timeout(self) -> None:
        request = _mapper_request()

        def raise_timeout(http_request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("deadline", request=http_request)

        mapper = _mapper_for(httpx.MockTransport(raise_timeout))
        with pytest.raises(MapperError) as exc:
            mapper.map_claims(request)
        assert exc.value.code is MapperFailureCode.PROVIDER_TIMEOUT

    @pytest.mark.parametrize(
        "alias",
        ["AP_YEARS", "apYears", "ap-years", "years", "candidate_id"],
    )
    def test_adversarial_kind_aliases_are_rejected(self, alias: str) -> None:
        request = _mapper_request()
        wire_payload = {
            "candidate_id": request.candidate_id,
            "snapshot_id": request.snapshot_id,
            "claims": [{"kind": alias, "value": 3.5, "evidence_ids": ["pdf-visible-admissible"]}],
        }
        mapper = _mapper_for(_json_transport(_response_body(json.dumps(wire_payload))))
        with pytest.raises(MapperError) as exc:
            mapper.map_claims(request)
        assert exc.value.code is MapperFailureCode.STRUCTURED_OUTPUT_INVALID


_EVIDENCE_IDS = st.lists(
    st.from_regex(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,40}", fullmatch=True),
    min_size=1,
    max_size=4,
)
_DATES = st.from_regex(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", fullmatch=True)

_WIRE_CLAIMS = st.one_of(
    st.builds(
        BooleanWireClaim,
        kind=st.sampled_from(["invoice_processing", "reconciliation"]),
        value=st.booleans(),
        evidence_ids=_EVIDENCE_IDS,
    ),
    st.builds(
        ApYearsWireClaim,
        kind=st.just("ap_years"),
        value=st.floats(min_value=0, max_value=80, allow_nan=False),
        evidence_ids=_EVIDENCE_IDS,
    ),
    st.builds(
        MonthlyInvoiceVolumeWireClaim,
        kind=st.just("monthly_invoice_volume"),
        value=st.integers(min_value=0, max_value=100_000_000),
        evidence_ids=_EVIDENCE_IDS,
    ),
    st.builds(
        SpreadsheetWireClaim,
        kind=st.just("spreadsheet"),
        value=st.sampled_from(["Excel", "Microsoft Excel", "Google Sheets"]),
        evidence_ids=_EVIDENCE_IDS,
    ),
    st.builds(
        AccountingPlatformWireClaim,
        kind=st.just("accounting_platform"),
        value=st.sampled_from(["Xero", "Sage", "QuickBooks", "NetSuite", "SAP"]),
        evidence_ids=_EVIDENCE_IDS,
    ),
    st.builds(
        QualificationWireClaim,
        kind=st.just("qualification"),
        value=st.sampled_from(["AAT Level 2", "AAT Level 3", "AAT Level 4", "ACCA"]),
        evidence_ids=_EVIDENCE_IDS,
    ),
    st.builds(
        IntervalWireClaim,
        kind=st.just("employment_interval"),
        start_date=_DATES,
        end_date=_DATES,
        evidence_ids=_EVIDENCE_IDS,
    ),
)


class TestWireConversionTotality:
    @settings(max_examples=200, deadline=None)
    @given(
        candidate_id=st.from_regex(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,30}", fullmatch=True),
        snapshot_id=st.from_regex(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,30}", fullmatch=True),
        claims=st.lists(_WIRE_CLAIMS, max_size=8),
    )
    def test_every_wire_valid_payload_converts_or_fails_closed(
        self,
        candidate_id: str,
        snapshot_id: str,
        claims: list[Any],
    ) -> None:
        wire = MapperWireOutput(
            candidate_id=candidate_id,
            snapshot_id=snapshot_id,
            claims=claims,
        )
        try:
            output = wire_output_to_mapper_output(wire)
        except MapperWireError as exc:
            assert exc.kind.value in {"invalid_date", "interval_order"}
            return
        assert isinstance(output, MapperOutput)
        assert output.candidate_id == candidate_id
        assert output.snapshot_id == snapshot_id
        assert len(output.claims) == len(claims)
        assert all(claim.candidate_id == candidate_id for claim in output.claims)
        assert all(claim.snapshot_id == snapshot_id for claim in output.claims)
        revalidated = MapperOutput.model_validate(output.model_dump(mode="python"))
        assert revalidated == output

    @settings(max_examples=100, deadline=None)
    @given(payload=st.dictionaries(st.text(max_size=8), st.text(max_size=8), max_size=4))
    def test_arbitrary_objects_never_convert_silently(self, payload: dict[str, str]) -> None:
        with pytest.raises(Exception):  # noqa: B017 - any validation failure is closed upstream
            wire = MapperWireOutput.model_validate({**payload})
            wire_output_to_mapper_output(wire)
