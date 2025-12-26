"""
Nullpeas Offensive Chaining Engine

This is the intelligence core that transforms discovered primitives into
realistic attack chains meaningful to offensive operators and blue teams.

It:
 - Consumes structured primitives
 - Builds offensive chains
 - Evaluates feasibility
 - Assigns truth-based offensive classification
 - Ranks opportunities
 - Remains quiet and ethical (NO exploitation)
"""

from __future__ import annotations
from typing import List, Dict, Optional
from dataclasses import asdict
from nullpeas.core.offensive_schema import (
    Primitive,
    AttackChain,
    ChainConfidence,
    new_chain_id,
)
from nullpeas.core.exploit_templates import generate_exploit_for_chain


# ----------------------------------------------------------------------
# HIGH LEVEL OFFENSIVE MODEL
# ----------------------------------------------------------------------

"""
This engine thinks like an attacker, but stops one step before exploitation.

If something is basically a guaranteed root escalation,
we call it that. We do not sanitize truth.

We do NOT execute anything.
We do NOT generate payloads.
We do NOT modify targets.
"""


# ----------------------------------------------------------------------
# PRIORITY LOGIC
# ----------------------------------------------------------------------

GOAL_PRIORITY = {
    "root_shell": 1,
    "privilege_escalation": 2,
    "persistence": 3,
    "credential_access": 4,
    "lateral_movement": 5,
}


CLASS_WEIGHT = {
    "catastrophic": 10,
    "severe": 7,
    "useful": 4,
    "niche": 1,
}

EXPLOIT_WEIGHT = {
    "trivial": 10,
    "moderate": 6,
    "advanced": 3,
    "theoretical": 1,
}


# ----------------------------------------------------------------------
# INTERNAL HELPERS
# ----------------------------------------------------------------------

def _primitive_lookup(primitives: List[Primitive]) -> Dict[str, Primitive]:
    lookup = {}
    for p in primitives:
        lookup[p.id] = p
    return lookup


def _score_chain(classification: str, exploitability: str) -> int:
    return CLASS_WEIGHT.get(classification, 1) + EXPLOIT_WEIGHT.get(exploitability, 1)


# ----------------------------------------------------------------------
# OFFENSIVE CLASSIFICATION LANGUAGE
# ----------------------------------------------------------------------

def _offensive_truth_for(primitive: Primitive) -> str:
    t = primitive.type
    run_as = primitive.run_as

    if t == "root_shell_primitive":
        return "This effectively grants direct root execution. In offensive reality, this is game-over."

    if t == "docker_host_takeover":
        return "Docker-level control is commonly equivalent to full host compromise. This is catastrophic."

    if t == "suid_primitive":
        return "Unknown SUID binary detected. While not a known GTFOBin, SUID binaries often harbor logic bugs or buffer overflows allowing root."

    if t == "cron_exec_primitive":
        return "This provides timed and repeatable privileged execution. It is a persistence and escalation vector."
    
    if t == "path_hijack_surface":
        return "Writable PATH directory allows interception of commands run by other users. High-value trap."

    if t == "arbitrary_file_write_primitive":
        return "Arbitrary privileged file write enables service hijack, persistence, and potential direct escalation."

    if run_as.lower() == "root":
        return "This surface results in privileged execution and is realistically abusable."

    return "This primitive represents meaningful offensive opportunity with realistic exploitation potential."


# ----------------------------------------------------------------------
# CORE CHAIN BUILDING LOGIC
# ----------------------------------------------------------------------

def _build_direct_chains(primitives: List[Primitive]) -> List[AttackChain]:
    chains = []

    for p in primitives:
        # Direct Root Win Chains
        # Included: Known SUIDs (root_shell_primitive), Docker, and Unknown SUIDs (suid_primitive)
        if p.type in {"root_shell_primitive", "docker_host_takeover", "suid_primitive"}:
            
            # For unknown SUIDs, the confidence is naturally lower (from the primitive itself),
            # but the goal is still root_shell.
            
            chain = AttackChain(
                chain_id=new_chain_id("root"),
                goal="root_shell",
                priority=1,
                exploitability=p.exploitability,
                stability=p.stability,
                noise=p.noise,
                classification=p.offensive_value.classification,
                summary=f"Privileged execution via {p.surface}",
                offensive_truth=_offensive_truth_for(p),
                steps=[{"primitive_id": p.id, "description": f"Leverage {p.surface} privileged capability"}],
                dependent_surfaces=[p.surface],
                confidence=ChainConfidence(
                    score=p.confidence.score,
                    reason=f"Derived directly from {p.surface} primitive"
                ),
                time_profile={
                    "immediacy": "instant",
                    "execution_window": "anytime"
                },
                operator_value={
                    "persistence_potential": "high",
                    "pivot_value": "medium",
                    "loot_value": "high",
                },
                defender_risk={
                    "breach_likelihood": "almost_certain",
                    "impact_scope": "complete_host_compromise",
                },
                exploit_commands=generate_exploit_for_chain(p)
            )
            chains.append(chain)

    return chains


def _build_two_stage_chains(primitives: List[Primitive]) -> List[AttackChain]:
    """
    Handles Multi-Stage and Delayed Execution Chains.
    Includes:
    1. File Write -> Service Restart (Persistence)
    2. Writable Cron Job (Timed Escalation)
    3. PATH Hijacking (Trap Escalation)
    """
    chains = []
    
    # Index file writes by the resource they control
    writes = {
        p.affected_resource: p 
        for p in primitives 
        if p.type == "arbitrary_file_write_primitive" and p.affected_resource
    }
    
    # 1. Service Hijacking (Write Config -> Restart Service)
    services = [p for p in primitives if p.surface in {"systemd", "services"}]
    
    for svc in services:
        config_path = svc.context.get("unit_file_path") or svc.context.get("config_path")
        
        if config_path and config_path in writes:
            writer = writes[config_path]
            
            chain = AttackChain(
                chain_id=new_chain_id("persistence"),
                goal="persistence",
                priority=2,
                exploitability="moderate",
                stability="moderate",
                noise="noticeable",
                classification="severe",
                summary=f"Overwrite service config {config_path} via {writer.surface}",
                offensive_truth="This chain reliably converts file write into root persistence.",
                steps=[
                    {"primitive_id": writer.id, "description": f"Modify {config_path} via {writer.surface}"},
                    {"primitive_id": svc.id, "description": "Trigger service reload/restart"},
                ],
                dependent_surfaces=[writer.surface, svc.surface],
                confidence=ChainConfidence(
                    score=min(writer.confidence.score, svc.confidence.score),
                    reason="Validated resource intersection (write->read)"
                ),
                exploit_commands=[]
            )
            chains.append(chain)

    # 2. Cron + Writable Script (Classic)
    # Includes both root-owned system files and user-level persistence hooks
    cron_primitives = [p for p in primitives if p.type in {"cron_exec_primitive", "cron_user_persistence_surface"}]

    for c in cron_primitives:
        goal = "privilege_escalation" if c.run_as == "root" else "persistence"
        
        chain = AttackChain(
            chain_id=new_chain_id("timed"),
            goal=goal,
            priority=3,
            exploitability=c.exploitability,
            stability=c.stability,
            noise=c.noise,
            classification=c.offensive_value.classification,
            summary="Scheduled execution injection",
            offensive_truth=_offensive_truth_for(c),
            steps=[
                {"primitive_id": c.id, "description": "Modify scheduled execution path/file"},
            ],
            dependent_surfaces=["cron"],
            confidence=ChainConfidence(
                score=c.confidence.score,
                reason="Verified writable cron resource"
            ),
            exploit_commands=generate_exploit_for_chain(c)
        )
        chains.append(chain)

    # 3. PATH Hijacking (New in v2.0)
    path_primitives = [p for p in primitives if p.type == "path_hijack_surface"]
    
    for p in path_primitives:
        chain = AttackChain(
            chain_id=new_chain_id("trap"),
            goal="privilege_escalation", # Assume we want to trap root or a higher user
            priority=3,
            exploitability=p.exploitability,
            stability="safe",
            noise="moderate",
            classification="severe",
            summary=f"PATH Interception via {p.affected_resource}",
            offensive_truth=_offensive_truth_for(p),
            steps=[
                {"primitive_id": p.id, "description": "Plant malicious binary in writable PATH directory"},
                {"primitive_id": "wait", "description": "Wait for privileged user to execute command (Interception)"},
            ],
            dependent_surfaces=["path"],
            confidence=ChainConfidence(
                score=p.confidence.score,
                reason="Verified writable PATH directory (os.access)"
            ),
            exploit_commands=generate_exploit_for_chain(p)
        )
        chains.append(chain)

    return chains


# ----------------------------------------------------------------------
# PUBLIC ENGINE ENTRYPOINT
# ----------------------------------------------------------------------

def build_attack_chains(primitives: List[Primitive]) -> List[AttackChain]:
    """
    Takes a set of offensive primitives and produces prioritized, meaningful attack chains.
    """

    if not primitives:
        return []

    chains: List[AttackChain] = []

    # Direct escalation chains
    chains.extend(_build_direct_chains(primitives))

    # Multi-stage escalation chains
    chains.extend(_build_two_stage_chains(primitives))

    # Rank chains by offensive value
    chains.sort(
        key=lambda c: (
            GOAL_PRIORITY.get(c.goal, 99),
            -_score_chain(c.classification, c.exploitability)
        )
    )

    return chains


# ----------------------------------------------------------------------
# RENDERING SUPPORT (OPTIONAL FOR REPORT ENGINE)
# ----------------------------------------------------------------------

def chains_to_dict(chains: List[AttackChain]) -> List[Dict]:
    """
    Convert chains to serializable form
    """
    return [asdict(c) for c in chains]


def summarize_chains(chains: List[AttackChain]) -> str:
    """
    Provide a short operator summary text.
    """
    if not chains:
        return "No meaningful offensive chains were identified."

    strongest = chains[0]

    txt = f"""
Nullpeas Offensive Chain Summary

Top Chain:
 - Goal: {strongest.goal}
 - Exploitability: {strongest.exploitability}
 - Stability: {strongest.stability}
 - Noise: {strongest.noise}
 - Truth: {strongest.offensive_truth}

Total Chains Identified: {len(chains)}
"""

    return txt.strip()
