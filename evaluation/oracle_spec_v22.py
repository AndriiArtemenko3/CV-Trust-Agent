"""Neutral deterministic V2.2 oracle schema shared by capture and verification."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Annotated, Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from evaluation.release_spec_v2 import (
    SourceId,
    Token,
    canonical_json_bytes,
    load_strict_json_object,
)

DETERMINISTIC_ARTIFACT_KIND_V22 = "deterministic_observations_v22"
DETERMINISTIC_ORACLE_DOMAIN_V22 = b"cv-trust-agent/deterministic-oracle/v3\0"
_MAX_ORACLE_BYTES = 2 * 1024 * 1024


class OracleSpecV22Error(ValueError):
    """The neutral V2.2 oracle schema is invalid."""


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class RankKeyExpectationV22(_StrictModel):
    band_priority: int = Field(ge=0, le=2)
    essentials_count: int = Field(ge=0, le=4)
    preferred_count: int = Field(ge=0, le=3)
    corroborated_claim_count: int = Field(ge=0, le=64)


class RouteExpectationV22(_StrictModel):
    candidate_id: SourceId
    band: Token
    queue: Token
    evidence_rank: int | None = Field(default=None, ge=1, le=50)
    display_position: int | None = Field(default=None, ge=1, le=50)
    rank_key: RankKeyExpectationV22 | None = None

    @model_validator(mode="after")
    def rank_fields_are_atomic(self) -> RouteExpectationV22:
        allowed_pairs = {
            ("STRONG_EVIDENCE_MATCH", "PRIORITY_HUMAN_REVIEW"),
            ("POTENTIAL_EVIDENCE_MATCH", "STANDARD_HUMAN_REVIEW"),
            ("INSUFFICIENT_SUPPORTED_EVIDENCE", "EVIDENCE_CHECK"),
            ("INTEGRITY_HOLD", "INTEGRITY_REVIEW"),
            ("INTEGRITY_HOLD", "BATCH_INTEGRITY_HOLD"),
            ("EVIDENCE_UNAVAILABLE", "EVIDENCE_PENDING"),
        }
        if (self.band, self.queue) not in allowed_pairs:
            raise ValueError("oracle route uses an unknown band/queue pair")
        values = (self.evidence_rank, self.display_position, self.rank_key)
        if any(item is None for item in values) and not all(item is None for item in values):
            raise ValueError("oracle rank fields must be atomic")
        return self


class ExplanationExpectationV22(_StrictModel):
    template: Literal[
        "record_degraded",
        "record_quarantined",
        "candidate_unavailable",
        "batch_held",
        "strategy_selected",
    ]
    candidate_id: SourceId | None = None
    reason_codes: tuple[Token, ...] = Field(min_length=1, max_length=64)


class ExactExpectationV22(_StrictModel):
    kind: Literal["exact"]
    decision_action_sha256: Annotated[
        str,
        StringConstraints(pattern=r"^[0-9a-f]{64}$"),
    ]
    decision_audit_sha256: Annotated[
        str,
        StringConstraints(pattern=r"^[0-9a-f]{64}$"),
    ]
    strategy: Token
    ranking_scope: Literal["COMPLETE", "PARTIAL", "NONE"]
    routes: tuple[RouteExpectationV22, ...] = Field(min_length=10, max_length=10)
    explanations: tuple[ExplanationExpectationV22, ...] = Field(max_length=50)
    required_completed_commands: tuple[Token, ...] = Field(min_length=1, max_length=64)
    forbidden_completed_commands: tuple[Token, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def exact_routes_are_complete(self) -> ExactExpectationV22:
        strategy_scope = {
            "FULL_EVIDENCE_RANKING": "COMPLETE",
            "SUPPORTED_ONLY_RANKING": "PARTIAL",
            "PARTIAL_SAFE_RANKING": "PARTIAL",
            "BATCH_INTEGRITY_HOLD": "NONE",
        }
        command_vocabulary = {
            "fetch_candidate_details",
            "validate_candidate_details",
            "fetch_candidate_resumes",
            "parse_candidate_resumes",
            "validate_candidate_bindings",
            "map_candidate_claims",
            "validate_candidate_evidence",
            "validate_index_commitments",
            "rank_full_evidence",
            "quarantine_unsupported",
            "mark_evidence_pending",
            "rank_supported_evidence",
            "rank_partial_evidence",
            "isolate_batch",
            "request_corroboration",
            "pre_release_audit",
            "release_output",
        }
        if strategy_scope.get(self.strategy) != self.ranking_scope:
            raise ValueError("oracle strategy and ranking scope are inconsistent")
        if not set(self.required_completed_commands).issubset(command_vocabulary) or not set(
            self.forbidden_completed_commands
        ).issubset(command_vocabulary):
            raise ValueError("oracle command expectation is outside the closed workflow")
        identities = [route.candidate_id for route in self.routes]
        if len(identities) != len(set(identities)):
            raise ValueError("exact oracle routes must have unique candidate IDs")
        if set(self.required_completed_commands) & set(self.forbidden_completed_commands):
            raise ValueError("a command cannot be both required and forbidden")
        return self


class EqualExpectationV22(_StrictModel):
    kind: Literal["equal_to"]
    reference: Token


CaseExpectationV22: TypeAlias = ExactExpectationV22 | EqualExpectationV22


class CaseOracleV22(_StrictModel):
    name: Token
    fixture_id: Token
    fixture_tree_sha256: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
    showcase: bool
    expectation: CaseExpectationV22 = Field(discriminator="kind")


class InvariantOracleV22(_StrictModel):
    name: Token
    kind: Literal[
        "projection_equal",
        "route_equal_except",
        "strategy_matrix",
        "completed_commands",
        "removed_commands_not_completed",
        "no_ranking_commands_completed",
    ]
    left: Token | None = None
    right: Token | None = None
    case: Token | None = None
    excluded_candidate_ids: tuple[SourceId, ...] = Field(default=(), max_length=50)
    expected_strategies: dict[Token, Token] = Field(default_factory=dict, max_length=25)
    required_commands: tuple[Token, ...] = Field(default=(), max_length=64)
    forbidden_commands: tuple[Token, ...] = Field(default=(), max_length=64)

    @model_validator(mode="after")
    def operands_match_kind(self) -> InvariantOracleV22:
        if self.kind in {"projection_equal", "route_equal_except"}:
            if (
                self.left is None
                or self.right is None
                or self.case is not None
                or self.expected_strategies
                or self.required_commands
                or self.forbidden_commands
                or (self.kind == "projection_equal" and self.excluded_candidate_ids)
            ):
                raise ValueError("binary invariant operands are invalid")
        elif self.kind == "strategy_matrix":
            if (
                not self.expected_strategies
                or self.left is not None
                or self.right is not None
                or self.case is not None
                or self.excluded_candidate_ids
                or self.required_commands
                or self.forbidden_commands
            ):
                raise ValueError("strategy matrix cannot be empty")
        elif (
            self.case is None
            or self.left is not None
            or self.right is not None
            or self.excluded_candidate_ids
            or self.expected_strategies
            or (
                self.kind != "completed_commands"
                and (self.required_commands or self.forbidden_commands)
            )
            or (
                self.kind == "completed_commands"
                and not (self.required_commands or self.forbidden_commands)
            )
        ):
            raise ValueError("case invariant operands are invalid")
        if set(self.required_commands) & set(self.forbidden_commands):
            raise ValueError("invariant commands cannot be required and forbidden")
        return self


class DeterministicOracleV22(_StrictModel):
    schema_version: Literal[3]
    protocol_version: Literal["2.2"]
    suite_id: Token
    cases: tuple[CaseOracleV22, ...] = Field(min_length=1, max_length=64)
    invariants: tuple[InvariantOracleV22, ...] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def references_are_closed(self) -> DeterministicOracleV22:
        names = [case.name for case in self.cases]
        invariant_names = [item.name for item in self.invariants]
        if len(names) != len(set(names)) or len(invariant_names) != len(set(invariant_names)):
            raise ValueError("oracle case and invariant names must be unique")
        known = set(names)
        for case in self.cases:
            if isinstance(case.expectation, EqualExpectationV22):
                if case.expectation.reference not in known:
                    raise ValueError("equal-to expectation references an unknown case")
                if case.expectation.reference == case.name:
                    raise ValueError("a case cannot equal itself")
        for invariant in self.invariants:
            references = {
                item
                for item in (invariant.left, invariant.right, invariant.case)
                if item is not None
            } | set(invariant.expected_strategies)
            if not references.issubset(known):
                raise ValueError("invariant references an unknown case")
        return self


def oracle_sha256_v22(oracle: DeterministicOracleV22) -> str:
    return hashlib.sha256(
        DETERMINISTIC_ORACLE_DOMAIN_V22
        + canonical_json_bytes(oracle.model_dump(mode="json", exclude_none=False))
    ).hexdigest()


def load_deterministic_oracle_v22(path: Path) -> DeterministicOracleV22:
    raw = load_strict_json_object(path, maximum_bytes=_MAX_ORACLE_BYTES)
    try:
        return DeterministicOracleV22.model_validate_json(canonical_json_bytes(raw))
    except Exception as exc:
        raise OracleSpecV22Error("deterministic V2.2 oracle is invalid") from exc
