"""Neutral frozen-span oracle schema for the held-out V2 mapper smoke."""

from __future__ import annotations

import hashlib
import math
import re
from datetime import date
from pathlib import Path
from typing import Annotated, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from evaluation.release_spec_v2 import (
    CATEGORICAL_ALLOW_LISTS_V2,
    Digest,
    SourceId,
    Token,
    canonical_json_bytes,
    load_strict_json_object,
)

SECURE_ORACLE_DOMAIN_V2 = b"cv-trust-agent/heldout-release-oracle/v2\0"
CANONICAL_SECURE_PROMPT_SHA256_V2 = (
    "59948685706287059a6522855fa19ab61fd2cb876a53f84a10f398673db5b8d5"
)
HELDOUT_SECURE_PROMPT_SHA256_V2 = "31489fbe818cb9c14e180bfae62443892e41a29565ca5836208ed857bf4a9050"
SECURE_MAPPER_TIMEOUT_SECONDS_V2 = 30.0
FACT_KINDS_V2 = (
    "ap_years",
    "invoice_processing",
    "reconciliation",
    "spreadsheet",
    "accounting_platform",
    "monthly_invoice_volume",
    "qualification",
)
CLAIM_KINDS_V2 = (*FACT_KINDS_V2, "candidate_id", "employment_interval")
FactValue: TypeAlias = bool | int | float | str | None
SafeClaimTextV2 = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9](?:[A-Za-z0-9 ._-]{0,78}[A-Za-z0-9])?$"),
]


class HeldoutOracleSpecV2Error(ValueError):
    """The neutral held-out V2 oracle is invalid."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ClaimExpectationV2(_StrictModel):
    kind: Token
    bool_value: bool | None = None
    number_value: float | None = None
    text_value: SafeClaimTextV2 | None = None
    start_date: date | None = None
    end_date: date | None = None
    required_span_sha256: tuple[Digest, ...] = Field(min_length=1, max_length=16)
    allowed_span_sha256: tuple[Digest, ...] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def citations_are_closed(self) -> ClaimExpectationV2:
        if not set(self.required_span_sha256).issubset(self.allowed_span_sha256):
            raise ValueError("required held-out spans must be allowed")
        validate_claim_value_v2(
            kind=self.kind,
            bool_value=self.bool_value,
            number_value=self.number_value,
            text_value=self.text_value,
            start_date=self.start_date,
            end_date=self.end_date,
        )
        return self


class HeldoutCandidateOracleV2(_StrictModel):
    candidate_id: SourceId
    expected_band: Literal[
        "STRONG_EVIDENCE_MATCH",
        "POTENTIAL_EVIDENCE_MATCH",
        "INSUFFICIENT_SUPPORTED_EVIDENCE",
    ]
    supported_facts: dict[Token, FactValue]
    claims: tuple[ClaimExpectationV2, ...] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def fact_contract_is_complete(self) -> HeldoutCandidateOracleV2:
        if set(self.supported_facts) != set(FACT_KINDS_V2):
            raise ValueError("held-out supported facts must use the complete bounded contract")
        _validate_supported_facts(self.supported_facts)
        kinds = [claim.kind for claim in self.claims]
        if len(kinds) != len(set(kinds)):
            raise ValueError("held-out expected claim kinds must be unique")
        return self


class HeldoutReleaseOracleV2(_StrictModel):
    schema_version: Literal[2]
    suite_id: Token
    clean_fixture_tree_sha256: Digest
    directive_fixture_tree_sha256: Digest
    candidates: tuple[HeldoutCandidateOracleV2, ...] = Field(min_length=4, max_length=4)

    @model_validator(mode="after")
    def candidates_are_unique(self) -> HeldoutReleaseOracleV2:
        identities = [item.candidate_id for item in self.candidates]
        if len(identities) != len(set(identities)):
            raise ValueError("held-out oracle candidate IDs must be unique")
        if self.clean_fixture_tree_sha256 == self.directive_fixture_tree_sha256:
            raise ValueError("held-out clean and directive fixtures must differ")
        return self


def heldout_oracle_sha256_v2(oracle: HeldoutReleaseOracleV2) -> str:
    return hashlib.sha256(
        SECURE_ORACLE_DOMAIN_V2
        + canonical_json_bytes(oracle.model_dump(mode="json", exclude_none=False))
    ).hexdigest()


def load_heldout_release_oracle_v2(path: Path) -> HeldoutReleaseOracleV2:
    raw = load_strict_json_object(path, maximum_bytes=2 * 1024 * 1024)
    try:
        return HeldoutReleaseOracleV2.model_validate_json(canonical_json_bytes(raw))
    except Exception as exc:
        raise HeldoutOracleSpecV2Error("held-out V2 release oracle is invalid") from exc


def validate_claim_value_v2(
    *,
    kind: str,
    bool_value: bool | None,
    number_value: float | None,
    text_value: str | None,
    start_date: date | str | None,
    end_date: date | str | None,
) -> None:
    """Validate a claim against the bounded AP evidence vocabulary."""

    if kind not in CLAIM_KINDS_V2:
        raise ValueError("claim kind is outside the bounded evidence contract")
    if number_value is not None and (
        isinstance(number_value, bool) or not math.isfinite(number_value)
    ):
        raise ValueError("numeric claim must be a finite non-boolean number")
    scalar_count = sum(item is not None for item in (bool_value, number_value, text_value))
    if kind == "employment_interval":
        if scalar_count or start_date is None or end_date is None:
            raise ValueError("employment intervals require dates only")
        parsed_start = date.fromisoformat(start_date) if isinstance(start_date, str) else start_date
        parsed_end = date.fromisoformat(end_date) if isinstance(end_date, str) else end_date
        if parsed_end < parsed_start:
            raise ValueError("employment interval end precedes start")
        return
    if start_date is not None or end_date is not None or scalar_count != 1:
        raise ValueError("scalar claims require exactly one typed value")
    if kind == "candidate_id":
        if (
            text_value is None
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", text_value) is None
        ):
            raise ValueError("candidate identity claims require a safe source identifier")
        return
    if kind in CATEGORICAL_ALLOW_LISTS_V2:
        if (
            text_value is None
            or " ".join(text_value.casefold().split()) not in (CATEGORICAL_ALLOW_LISTS_V2[kind])
        ):
            raise ValueError("categorical claim is outside the bounded allow-list")
        return
    expected_type = {
        "ap_years": "number",
        "monthly_invoice_volume": "number",
        "invoice_processing": "bool",
        "reconciliation": "bool",
    }[kind]
    if expected_type == "number" and (number_value is None or isinstance(number_value, bool)):
        raise ValueError("numeric claim has the wrong scalar type")
    if kind == "ap_years" and number_value is not None and not 0 <= number_value <= 80:
        raise ValueError("AP-years claim is outside the bounded range")
    if (
        kind == "monthly_invoice_volume"
        and number_value is not None
        and not 0 <= number_value <= 100_000_000
    ):
        raise ValueError("monthly-volume claim is outside the bounded range")
    if expected_type == "bool" and bool_value is None:
        raise ValueError("boolean claim has the wrong scalar type")


def _validate_supported_facts(facts: dict[Token, FactValue]) -> None:
    for kind, value in facts.items():
        if value is None:
            continue
        if kind in {"invoice_processing", "reconciliation"}:
            if not isinstance(value, bool):
                raise ValueError("oracle boolean fact has the wrong type")
        elif kind in {"ap_years", "monthly_invoice_volume"}:
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise ValueError("oracle numeric fact has the wrong type")
            if not math.isfinite(float(value)):
                raise ValueError("oracle numeric fact must be finite")
            upper = 80 if kind == "ap_years" else 100_000_000
            if not 0 <= float(value) <= upper:
                raise ValueError("oracle numeric fact is outside the bounded range")
        elif kind in CATEGORICAL_ALLOW_LISTS_V2 and (
            not isinstance(value, str)
            or " ".join(value.casefold().split()) not in CATEGORICAL_ALLOW_LISTS_V2[kind]
        ):
            raise ValueError("oracle categorical fact is outside the allow-list")
