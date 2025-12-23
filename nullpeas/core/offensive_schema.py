from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional, Literal
import uuid

# ---------------------------------------------------------------------------
# ENUM-LIKE TYPE ALIASES
# ---------------------------------------------------------------------------

Exploitability = Literal["trivial", "moderate", "advanced", "theoretical"]
Stability = Literal["safe", "moderate", "risky", "dangerous"]
Noise = Literal["silent", "low", "noticeable", "loud"]
Classification = Literal["catastrophic", "severe", "useful", "niche"]

Goal = Literal[
    "root_shell",
    "privilege_escalation",
    "persistence",
    "lateral_movement",
    "credential_access",
]


# ---------------------------------------------------------------------------
# PRIMITIVE SCHEMA
# ---------------------------------------------------------------------------

@dataclass
class PrimitiveConfidence:
    """
    Confidence that this primitive is actually usable on this host.

    score:   0–10 (float)   – higher means more confident
    reason:  short human-readable justification
    """

    score: float
    reason: str


@dataclass
class OffensiveValue:
    """
    How valuable this primitive is from an operator's perspective.

    classification: catastrophic / severe / useful / niche
    why:            short justification, shown in reports
    """

    classification: Classification
    why: str


@dataclass
class Primitive:
    """
    Represents an offensive capability discovered on the host.

    This is NOT a "finding" or "alert". This is POWER:
    something an operator could use as part of an attack chain.
    """

    # Identity
    id: str
    surface: str               # e.g. "sudo", "cron", "docker", "suid"
    type: str                  # e.g. "root_shell_primitive", "arbitrary_file_write"

    # Who / how it runs
    run_as: str                # effective user if used (normally "root", or another user)
    origin_user: str           # the account we started from (current user)

    # Behavioural profile
    exploitability: Exploitability
    stability: Stability
    noise: Noise

    # Meta-evaluation
    confidence: PrimitiveConfidence
    offensive_value: OffensiveValue

    # Timeline
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # Extra context for chaining/reporting
    context: Dict[str, Any] = field(default_factory=dict)       # arbitrary module-specific context
    conditions: Dict[str, Any] = field(default_factory=dict)    # preconditions (e.g. "needs writable path X")
    integration_flags: Dict[str, Any] = field(default_factory=dict)  # hints for chaining_engine

    # Cross-references: external material for operators
    cross_refs: Dict[str, List[str]] = field(
        default_factory=lambda: {"gtfobins": [], "cves": [], "documentation": []}
    )

    # Defensive impact notes (for blue teams / reporting)
    defensive_impact: Dict[str, Any] = field(default_factory=dict)

    # Provenance
    module_source: str = "unknown"   # which module produced this
    probe_source: str = "unknown"    # which probe(s) it relied on


# ---------------------------------------------------------------------------
# ATTACK CHAIN SCHEMA
# ---------------------------------------------------------------------------

@dataclass
class ChainConfidence:
    """
    Confidence that the full chain is realistic and reproducible
    on this host in its current state.
    """

    score: float
    reason: str


@dataclass
class AttackChain:
    """
    Represents a real offensive path to a meaningful objective.

    Chains are built from one or more Primitives and are what end up being
    narrated in the "Offensive Attack Chains" section of the report.
    """

    chain_id: str
    goal: Goal                  # root_shell / privilege_escalation / persistence / etc.

    priority: int               # simple ordering hint: 1 = most interesting/urgent

    exploitability: Exploitability
    stability: Stability
    noise: Noise

    classification: Classification  # catastrophic / severe / useful / niche

    summary: str                # one-line human summary
    offensive_truth: str        # honest operator-level description ("this is basically root")

    # Steps normally reference primitive IDs and human-readable descriptions
    # e.g. {"primitive_id": "sudo_root_shell_XYZ", "description": "Use passwordless sudo vim to write to /etc/sudoers"}
    steps: List[Dict[str, Any]]

    # Extra structure for future engines / reporting
    prerequisites: List[str] = field(default_factory=list)
    dependent_surfaces: List[str] = field(default_factory=list)

    confidence: ChainConfidence = field(
        default_factory=lambda: ChainConfidence(score=5.0, reason="not evaluated")
    )

    time_profile: Dict[str, Any] = field(
        default_factory=lambda: {
            "immediacy": "unknown",           # e.g. "immediate", "delayed", "long_term"
            "execution_window": "unknown",    # e.g. "anytime", "cron_window", "maintenance_only"
        }
    )

    operator_value: Dict[str, Any] = field(
        default_factory=lambda: {
            "persistence_potential": "unknown",   # e.g. "strong", "weak", "none"
            "pivot_value": "unknown",            # how good this is for lateral movement
            "loot_value": "unknown",             # expected credential/secret payoff
        }
    )

    defender_risk: Dict[str, Any] = field(
        default_factory=lambda: {
            "breach_likelihood": "unknown",      # qualitative risk for defenders
            "impact_scope": "unknown",           # e.g. "single host", "tenant", "environment"
        }
    )


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def new_primitive_id(surface: str, primitive_type: str) -> str:
    """
    Generate a short, reasonably unique primitive ID.
    """
    return f"{surface}_{primitive_type}_{uuid.uuid4().hex[:8]}"


def new_chain_id(goal: str) -> str:
    """
    Generate a short, reasonably unique chain ID.
    """
    return f"chain_{goal}_{uuid.uuid4().hex[:6]}"


def validate_primitive(p: Primitive) -> bool:
    """
    Light-weight schema integrity check.

    Returns True if the primitive looks sane, False if obvious problems exist.
    (Intentionally non-strict to avoid crashing on imperfect data.)
    """
    if not p.surface or not p.type:
        return False
    if not p.run_as or not p.origin_user:
        return False
    if not (0.0 <= p.confidence.score <= 10.0):
        return False
    return True


def validate_chain(c: AttackChain) -> bool:
    """
    Light-weight schema integrity check for AttackChain.
    """
    if not c.goal:
        return False
    if not c.steps:
        return False
    if not (0.0 <= c.confidence.score <= 10.0):
        return False
    return True


__all__ = [
    "Exploitability",
    "Stability",
    "Noise",
    "Classification",
    "Goal",
    "PrimitiveConfidence",
    "OffensiveValue",
    "Primitive",
    "ChainConfidence",
    "AttackChain",
    "new_primitive_id",
    "new_chain_id",
    "validate_primitive",
    "validate_chain",
]