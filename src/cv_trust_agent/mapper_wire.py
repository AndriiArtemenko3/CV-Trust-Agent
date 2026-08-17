"""Provider-facing wire contract for the quarantined mapper.

The V2.1 live experiment showed that a structured-output schema generated from
the runtime :class:`~cv_trust_agent.models.MapperOutput` cannot express the
post-parse contract: cross-field validators (exactly one scalar per kind,
dates only on intervals, per-claim identity echo) and calendar-valid dates are
invisible to constrained decoding, so schema-conformant provider output could
still fail post-parse validation.  This module defines a wire schema whose
strict JSON schema *is* the structural contract: one object shape per claim
kind, strict scalar types, kind-specific bounds and categorical literals, no
per-claim identity echo, no producer claim ids, and no ``candidate_id`` claim
kind.  A total, code-owned conversion turns any wire-valid payload into the
unchanged runtime ``MapperOutput``; the only residual failure surfaces are
calendar validity and interval ordering, each mapped to one closed category.
"""

from __future__ import annotations

from datetime import date
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from cv_trust_agent.models import (
    ClaimKind,
    MappedClaim,
    MapperOutput,
)

_WIRE_ID = Annotated[
    str,
    Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]*$"),
]
_WIRE_EVIDENCE_ID = Annotated[
    str,
    Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$"),
]
_WIRE_DATE = Annotated[
    str,
    Field(min_length=10, max_length=10, pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"),
]
_WIRE_EVIDENCE_IDS = Annotated[
    list[_WIRE_EVIDENCE_ID],
    Field(min_length=1, max_length=16),
]


class WireConversionErrorKind(StrEnum):
    """Closed categories for the only wire constraints a schema cannot carry."""

    INVALID_DATE = "invalid_date"
    INTERVAL_ORDER = "interval_order"


class MapperWireError(ValueError):
    """A wire-valid payload violated a residual non-schema constraint."""

    def __init__(self, kind: WireConversionErrorKind) -> None:
        super().__init__(f"mapper wire conversion failed: {kind.value}")
        self.kind = kind


class _WireModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class BooleanWireClaim(_WireModel):
    kind: Literal["invoice_processing", "reconciliation"]
    value: bool
    evidence_ids: _WIRE_EVIDENCE_IDS


class ApYearsWireClaim(_WireModel):
    kind: Literal["ap_years"]
    value: Annotated[float, Field(ge=0, le=80)]
    evidence_ids: _WIRE_EVIDENCE_IDS


class MonthlyInvoiceVolumeWireClaim(_WireModel):
    kind: Literal["monthly_invoice_volume"]
    value: Annotated[int, Field(ge=0, le=100_000_000)]
    evidence_ids: _WIRE_EVIDENCE_IDS


class SpreadsheetWireClaim(_WireModel):
    kind: Literal["spreadsheet"]
    value: Literal["Excel", "Microsoft Excel", "Google Sheets"]
    evidence_ids: _WIRE_EVIDENCE_IDS


class AccountingPlatformWireClaim(_WireModel):
    kind: Literal["accounting_platform"]
    value: Literal["Xero", "Sage", "QuickBooks", "NetSuite", "SAP"]
    evidence_ids: _WIRE_EVIDENCE_IDS


class QualificationWireClaim(_WireModel):
    kind: Literal["qualification"]
    value: Literal["AAT Level 2", "AAT Level 3", "AAT Level 4", "ACCA"]
    evidence_ids: _WIRE_EVIDENCE_IDS


class IntervalWireClaim(_WireModel):
    kind: Literal["employment_interval"]
    start_date: _WIRE_DATE
    end_date: _WIRE_DATE
    evidence_ids: _WIRE_EVIDENCE_IDS


# NOTE: This union is intentionally *not* a Pydantic discriminated union.
# A ``Field(discriminator="kind")`` union serialises to JSON Schema ``oneOf``,
# which the OpenAI structured-output API rejects with
# ``invalid_json_schema: 'oneOf' is not permitted``. A plain union serialises
# to ``anyOf``, which the provider accepts. Validation is unchanged: every
# member carries a disjoint ``kind`` literal and ``extra="forbid"``/``strict``,
# so exactly one member validates any wire-valid claim and all members reject an
# unknown or type-mismatched one. See tests/test_mapper_wire_offline.py.
WireClaim = (
    BooleanWireClaim
    | ApYearsWireClaim
    | MonthlyInvoiceVolumeWireClaim
    | SpreadsheetWireClaim
    | AccountingPlatformWireClaim
    | QualificationWireClaim
    | IntervalWireClaim
)


class MapperWireOutput(_WireModel):
    """The exact structured-output shape requested from the provider."""

    candidate_id: _WIRE_ID
    snapshot_id: _WIRE_ID
    claims: Annotated[list[WireClaim], Field(max_length=64)]


def _wire_date(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise MapperWireError(WireConversionErrorKind.INVALID_DATE) from exc


def wire_output_to_mapper_output(wire: MapperWireOutput) -> MapperOutput:
    """Convert a wire-valid payload into the unchanged runtime contract.

    Total by construction for every wire-schema-valid payload except the two
    residual constraints a JSON schema cannot express: calendar-valid dates
    and interval ordering.  Claim ids and per-claim identity are code-owned.
    """

    claims: list[MappedClaim] = []
    for index, claim in enumerate(wire.claims, start=1):
        claim_id = f"wire:{claim.kind}:{index}"
        if isinstance(claim, IntervalWireClaim):
            start = _wire_date(claim.start_date)
            end = _wire_date(claim.end_date)
            if end < start:
                raise MapperWireError(WireConversionErrorKind.INTERVAL_ORDER)
            claims.append(
                MappedClaim(
                    claim_id=claim_id,
                    candidate_id=wire.candidate_id,
                    snapshot_id=wire.snapshot_id,
                    kind=ClaimKind.EMPLOYMENT_INTERVAL,
                    start_date=start,
                    end_date=end,
                    evidence_ids=tuple(claim.evidence_ids),
                )
            )
            continue
        kind = ClaimKind(claim.kind)
        bool_value = claim.value if isinstance(claim, BooleanWireClaim) else None
        number_value = (
            float(claim.value)
            if isinstance(claim, ApYearsWireClaim | MonthlyInvoiceVolumeWireClaim)
            else None
        )
        text_value = (
            "Excel"
            if isinstance(claim, SpreadsheetWireClaim) and claim.value == "Microsoft Excel"
            else claim.value
            if isinstance(
                claim,
                SpreadsheetWireClaim | AccountingPlatformWireClaim | QualificationWireClaim,
            )
            else None
        )
        claims.append(
            MappedClaim(
                claim_id=claim_id,
                candidate_id=wire.candidate_id,
                snapshot_id=wire.snapshot_id,
                kind=kind,
                bool_value=bool_value,
                number_value=number_value,
                text_value=text_value,
                evidence_ids=tuple(claim.evidence_ids),
            )
        )
    return MapperOutput(
        candidate_id=wire.candidate_id,
        snapshot_id=wire.snapshot_id,
        claims=tuple(claims),
    )
