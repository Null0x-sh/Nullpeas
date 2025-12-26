# nullpeas/core/offensive_schema.py

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
    """

    # Identity
    id: str
    surface: str               # e.g. "sudo", "cron", "docker", "suid"
    type: str                  # e.g. "root_shell_primitive", "arbitrary_file_write"

    # Who / how it runs
    run_as: str                # effective user if used (normally "root")
    origin_user: str           # the account we started from

    # Behavioural profile
    exploitability: Exploitability
    stability: Stability
    noise: Noise

    # Meta-evaluation
    confidence: PrimitiveConfidence
    offensive_value: OffensiveValue

    # Timeline
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # === NEW: Logic Hardening ===
    # Defines the specific resource this primitive controls (e.g., "/etc/passwd", "docker.sock").
    # Used by the chaining engine to ensure we don't link unrelated primitives.
    affected_resource: Optional[str] = None

    # Extra context for chaining/reporting
    context: Dict[str, Any] = field(default_factory=dict)       
    conditions: Dict[str, Any] = field(default_factory=dict)    
    integration_flags: Dict[str, Any] = field(default_factory=dict)

    # Cross-references
    cross_refs: Dict[str, List[str]] = field(
        default_factory=lambda: {"gtfobins": [], "cves": [], "documentation": []}
    )

    # Defensive impact notes
    defensive_impact: Dict[str, Any] = field(default_factory=dict)

    # Provenance
    module_source: str = "unknown"
    probe_source: str = "unknown"


# ---------------------------------------------------------------------------
# ATTACK CHAIN SCHEMA
# ---------------------------------------------------------------------------

@dataclass
class ChainConfidence:
    """
    Confidence that the full chain is realistic.
    """
    score: float
    reason: str


@dataclass
class AttackChain:
    """
    Represents a real offensive path to a meaningful objective.
    """

    chain_id: str
    goal: Goal

    priority: int
    exploitability: Exploitability
    stability: Stability
    noise: Noise
    classification: Classification

    summary: str
    offensive_truth: str

    steps: List[Dict[str, Any]]

    # Extra structure
    prerequisites: List[str] = field(default_factory=list)
    dependent_surfaces: List[str] = field(default_factory=list)

    confidence: ChainConfidence = field(
        default_factory=lambda: ChainConfidence(score=5.0, reason="not evaluated")
    )

    # === NEW: Exploitation Support ===
    # A list of copy-pasteable commands to execute this chain.
    # Populated by the Chaining Engine using exploit_templates.py.
    exploit_commands: List[str] = field(default_factory=list)

    time_profile: Dict[str, Any] = field(
        default_factory=lambda: {
            "immediacy": "unknown",
            "execution_window": "unknown",
        }
    )

    operator_value: Dict[str, Any] = field(
        default_factory=lambda: {
            "persistence_potential": "unknown",
            "pivot_value": "unknown",
            "loot_value": "unknown",
        }
    )

    defender_risk: Dict[str, Any] = field(
        default_factory=lambda: {
            "breach_likelihood": "unknown",
            "impact_scope": "unknown",
        }
    )


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def new_primitive_id(surface: str, primitive_type: str) -> str:
    return f"{surface}_{primitive_type}_{uuid.uuid4().hex[:8]}"


def new_chain_id(goal: str) -> str:
    return f"chain_{goal}_{uuid.uuid4().hex[:6]}"


def validate_primitive(p: Primitive) -> bool:
    if not p.surface or not p.type:
        return False
    if not p.run_as or not p.origin_user:
        return False
    if not (0.0 <= p.confidence.score <= 10.0):
        return False
    return True


def validate_chain(c: AttackChain) -> bool:
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
