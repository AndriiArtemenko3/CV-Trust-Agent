"""Neutral frozen-span oracle schema for the held-out V2.2 regression arm.

The cohort and its labels are byte-carried from the frozen V2.1 oracle: the
same four fictional candidates, values, spans, and bands, re-wrapped with the
V2.2 protocol envelope.  No label may change; only the schema version, oracle
domain, and the frozen prompt digests (which follow the wire-contract
instruction text) differ from the V2 spec.
"""

from __future__ import annotations

import hashlib
from datetime import date
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from evaluation.heldout_oracle_spec_v2 import (
    CLAIM_KINDS_V2,
    FACT_KINDS_V2,
    FactValue,
    SafeClaimTextV2,
    _validate_supported_facts,
    validate_claim_value_v2,
)
from evaluation.release_spec_v2 import (
    Digest,
    SourceId,
    Token,
    canonical_json_bytes,
    load_strict_json_object,
)

SCHEMA_VERSION_V22 = 3
PROTOCOL_VERSION_V22 = "2.2"
SECURE_ORACLE_DOMAIN_V22 = b"cv-trust-agent/heldout-release-oracle/v3\0"
CANONICAL_SECURE_PROMPT_SHA256_V22 = (
    "f43c989e244fb8b7ec5933abb1bca7f18c54532b5dae574e9d57a435dcb1982d"
)
HELDOUT_SECURE_PROMPT_SHA256_V22 = (
    "14946dd69e6f2610dc483554ce33266468fecc10cfc170c67f80f13249fc7bfb"
)
SECURE_MAPPER_TIMEOUT_SECONDS_V22 = 30.0
FACT_KINDS_V22 = FACT_KINDS_V2
CLAIM_KINDS_V22 = CLAIM_KINDS_V2
# The V2.2 wire schema cannot express a candidate_id claim, so a mapper claim
# must use one of these kinds; oracle rows may still carry a candidate_id
# expectation for label fidelity, which simply never matches a mapper claim.
MAPPER_CLAIM_KINDS_V22 = (*FACT_KINDS_V2, "employment_interval")

validate_claim_value_v22 = validate_claim_value_v2


class HeldoutOracleSpecV22Error(ValueError):
    """The neutral held-out V2.2 oracle is invalid."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class ClaimExpectationV22(_StrictModel):
    kind: Token
    bool_value: bool | None = None
    number_value: float | None = None
    text_value: SafeClaimTextV2 | None = None
    start_date: date | None = None
    end_date: date | None = None
    required_span_sha256: tuple[Digest, ...] = Field(min_length=1, max_length=16)
    allowed_span_sha256: tuple[Digest, ...] = Field(min_length=1, max_length=16)

    @model_validator(mode="after")
    def citations_are_closed(self) -> ClaimExpectationV22:
        if not set(self.required_span_sha256).issubset(self.allowed_span_sha256):
            raise ValueError("required held-out spans must be allowed")
        validate_claim_value_v22(
            kind=self.kind,
            bool_value=self.bool_value,
            number_value=self.number_value,
            text_value=self.text_value,
            start_date=self.start_date,
            end_date=self.end_date,
        )
        return self


class HeldoutCandidateOracleV22(_StrictModel):
    candidate_id: SourceId
    expected_band: Literal[
        "STRONG_EVIDENCE_MATCH",
        "POTENTIAL_EVIDENCE_MATCH",
        "INSUFFICIENT_SUPPORTED_EVIDENCE",
    ]
    supported_facts: dict[Token, FactValue]
    claims: tuple[ClaimExpectationV22, ...] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def fact_contract_is_complete(self) -> HeldoutCandidateOracleV22:
        if set(self.supported_facts) != set(FACT_KINDS_V22):
            raise ValueError("held-out supported facts must use the complete bounded contract")
        _validate_supported_facts(self.supported_facts)
        kinds = [claim.kind for claim in self.claims]
        if len(kinds) != len(set(kinds)):
            raise ValueError("held-out expected claim kinds must be unique")
        return self

    def requires_facts(self) -> bool:
        """Report whether the frozen labels require any extracted fact."""

        return any(value is not None for value in self.supported_facts.values())


class HeldoutReleaseOracleV22(_StrictModel):
    schema_version: Literal[3]
    protocol_version: Literal["2.2"]
    suite_id: Token
    clean_fixture_tree_sha256: Digest
    directive_fixture_tree_sha256: Digest
    candidates: tuple[HeldoutCandidateOracleV22, ...] = Field(min_length=4, max_length=4)

    @model_validator(mode="after")
    def candidates_are_unique(self) -> HeldoutReleaseOracleV22:
        identities = [item.candidate_id for item in self.candidates]
        if len(identities) != len(set(identities)):
            raise ValueError("held-out oracle candidate IDs must be unique")
        if self.clean_fixture_tree_sha256 == self.directive_fixture_tree_sha256:
            raise ValueError("held-out clean and directive fixtures must differ")
        return self


def heldout_oracle_sha256_v22(oracle: HeldoutReleaseOracleV22) -> str:
    return hashlib.sha256(
        SECURE_ORACLE_DOMAIN_V22
        + canonical_json_bytes(oracle.model_dump(mode="json", exclude_none=False))
    ).hexdigest()


def load_heldout_release_oracle_v22(path: Path) -> HeldoutReleaseOracleV22:
    raw = load_strict_json_object(path, maximum_bytes=2 * 1024 * 1024)
    try:
        return HeldoutReleaseOracleV22.model_validate_json(canonical_json_bytes(raw))
    except Exception as exc:
        raise HeldoutOracleSpecV22Error("held-out V2.2 release oracle is invalid") from exc
