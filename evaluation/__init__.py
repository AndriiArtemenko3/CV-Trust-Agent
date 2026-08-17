"""Repository-only evaluation harness for the public CV-Trust interfaces.

This package contains expectations and scoring logic.  The installable
``cv_trust_agent`` package must never import it.
"""

from evaluation.core import (
    EvaluationError,
    EvaluationReport,
    evaluate_cases,
    load_oracle,
)

__all__ = (
    "EvaluationError",
    "EvaluationReport",
    "evaluate_cases",
    "load_oracle",
)
