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
from typing import List, Dict
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
    "reconnaissance": 6, 
}

LOOT_TYPES = {"credential_file", "password_store", "config_file", "info_disclosure"}

CLASS_WEIGHT = {
    "catastrophic": 10, # Guaranteed Root / Game Over
    "critical": 9,      # Immediate high risk (SSH Keys, Shadow file)
    "severe": 7,        # High risk but might need extra steps
    "high": 6,          # Added for safety
    "useful": 4,        # Good for pivoting/recon
    "niche": 1,         # Edge cases
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

def _score_chain(classification: str, exploitability: str) -> int:
    # Now 'critical' will correctly return 9 instead of default 1
    return CLASS_WEIGHT.get(classification, 1) + EXPLOIT_WEIGHT.get(exploitability, 1)


# ----------------------------------------------------------------------
# OFFENSIVE CLASSIFICATION LANGUAGE
# ----------------------------------------------------------------------

def _offensive_truth_for(primitive: Primitive) -> str:
    t = primitive.type
    run_as = primitive.run_as

    if t == "root_shell_primitive":
        if primitive.surface == "capabilities":
            return "Binary has 'cap_setuid+ep'. Allows spawning a shell and explicitly setting UID to 0 (Root)."
        return "This effectively grants direct root execution. In offensive reality, this is game-over."

    if t == "docker_host_takeover":
        return "Docker-level control is commonly equivalent to full host compromise. This is catastrophic."

    if t == "suid_primitive":
        return "Unknown SUID binary detected. While not a known GTFOBin, SUID binaries often harbor logic bugs or buffer overflows allowing root."

    if t == "cron_exec_primitive":
        return "This provides timed and repeatable privileged execution. It is a persistence and escalation vector."
    
    if t == "path_hijack_surface":
        return "Writable PATH directory allows interception of commands run by other users. High-value trap."
        
    # === Capabilities Truths ===
    if t == "group_pivot_primitive":
        return "Binary has 'cap_setgid'. Allows pivoting to sensitive groups (disk, shadow) which often leads to root."
    
    if t == "arbitrary_file_access_primitive":
        return "Binary has 'cap_dac_override'. Bypasses all file permissions to Read/Write ANY file on the system."

    # === Systemd Truths ===
    if t == "systemd_unit_write":
        return "Writable service unit allows re-defining ExecStart. This grants root access upon service restart."
    if t == "systemd_binary_write":
        return "Service runs a writable binary. Overwriting this binary grants root access when the service runs."
    if t == "systemd_relative_path":
        return "Service executes a relative path. This allows Interception/Path Hijacking in the service's working directory."

    if t == "arbitrary_file_write_primitive":
        return "Arbitrary privileged file write enables service hijack, persistence, and potential direct escalation."

    # === Loot Truths ===
    if t == "credential_file":
        return "Discovered credentials often allow immediate lateral movement or access to critical infrastructure."
    if t == "password_store":
        return "Access to password hashes allows offline cracking and potential impersonation of users."
    if t == "config_file":
        return "Configuration files frequently contain hardcoded database passwords, API keys, or internal network details."
    if t == "info_disclosure":
        return "Historical commands and environment configs provide critical context for pivoting and identifying high-value targets."

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
        if p.type in {"root_shell_primitive", "docker_host_takeover", "suid_primitive"}:
            
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

        # === Group Pivot (Caps) ===
        if p.type == "group_pivot_primitive":
            chain = AttackChain(
                chain_id=new_chain_id("privesc"),
                goal="privilege_escalation",
                priority=2,
                exploitability=p.exploitability,
                stability=p.stability,
                noise=p.noise,
                classification=p.offensive_value.classification,
                summary=f"Group Pivot via {p.surface}",
                offensive_truth=_offensive_truth_for(p),
                steps=[{"primitive_id": p.id, "description": "Abuse cap_setgid to gain new group membership"}],
                dependent_surfaces=[p.surface],
                confidence=ChainConfidence(score=p.confidence.score, reason="Verified Capability"),
                exploit_commands=generate_exploit_for_chain(p)
            )
            chains.append(chain)

        # === Loot & Intelligence ===
        if p.type in LOOT_TYPES:
            
            target_file = p.context.get("path", "file")
            cmds = [f"cat {target_file}"]
            
            # Default goal/priority
            goal = "credential_access"
            priority = 4
            summary_text = f"Intelligence collection via {p.surface}"
            
            # 1. Info Disclosure Adjustment
            if p.type == "info_disclosure":
                goal = "reconnaissance"
                priority = 5  
            
            # 2. Summary Adjustment
            if p.type in {"credential_file", "password_store"}:
                summary_text = f"Credential harvest via {p.surface}"
            
            chain = AttackChain(
                chain_id=new_chain_id("loot"),
                goal=goal,
                priority=priority,
                exploitability=p.exploitability,
                stability=p.stability, # Dynamic: Inherit from primitive
                noise=p.noise,         # Dynamic: Inherit from primitive
                classification=p.offensive_value.classification,
                summary=summary_text,
                offensive_truth=_offensive_truth_for(p),
                steps=[{"primitive_id": p.id, "description": f"Harvest {target_file}"}],
                dependent_surfaces=[p.surface],
                confidence=ChainConfidence(score=p.confidence.score, reason="Verified file existence"),
                exploit_commands=cmds
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
    4. Systemd Service Abuse (New)
    5. DAC Override -> File Write -> Service (New)
    """
    chains = []
    
    # Index file writes by the resource they control
    writes = {
        p.affected_resource: p 
        for p in primitives 
        if p.type == "arbitrary_file_write_primitive" and p.affected_resource
    }
    
    # Detect CAP_DAC_OVERRIDE (Universal Writer)
    universal_writers = [p for p in primitives if p.type == "arbitrary_file_access_primitive"]

    # 1. Service Hijacking (Generic Write Config -> Restart Service)
    services = [p for p in primitives if p.surface in {"systemd", "services"}]
    
    for svc in services:
        config_path = svc.context.get("unit_file_path") or svc.context.get("config_path")
        
        # A) Standard File Write Logic
        if config_path and config_path in writes:
            writer = writes[config_path]
            chains.append(_create_service_write_chain(writer, svc, config_path))

        # B) CAP_DAC_OVERRIDE Logic (Universal Writer)
        if config_path and universal_writers:
            for writer in universal_writers:
                chains.append(_create_service_write_chain(writer, svc, config_path, method="capabilities"))

    # 2. Cron + Writable Script (Classic)
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

    # 3. PATH Hijacking
    path_primitives = [p for p in primitives if p.type == "path_hijack_surface"]
    
    for p in path_primitives:
        chain = AttackChain(
            chain_id=new_chain_id("trap"),
            goal="privilege_escalation",
            priority=3,
            exploitability=p.exploitability,
            stability=p.stability, # Dynamic
            noise=p.noise,         # Dynamic
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

    # 4. Systemd Service Abuse
    systemd_primitives = [
        p for p in primitives 
        if p.type in {"systemd_unit_write", "systemd_binary_write", "systemd_relative_path"}
    ]

    for p in systemd_primitives:
        cmds = []
        if p.context.get("exploit_hint"):
            cmds.append(p.context.get("exploit_hint"))
        else:
            cmds = generate_exploit_for_chain(p)

        chain = AttackChain(
            chain_id=new_chain_id("service"),
            goal="privilege_escalation", 
            priority=2,
            exploitability=p.exploitability,
            stability=p.stability,
            noise=p.noise,
            classification=p.offensive_value.classification,
            summary=f"Service Abuse via {p.context.get('unit_name', 'unknown')}",
            offensive_truth=_offensive_truth_for(p),
            steps=[
                {"primitive_id": p.id, "description": f"Exploit {p.surface} vulnerability ({p.type})"},
                {"primitive_id": "trigger", "description": "Restart service or wait for reboot"},
            ],
            dependent_surfaces=["systemd"],
            confidence=ChainConfidence(
                score=p.confidence.score,
                reason="Verified service misconfiguration (os.access)"
            ),
            exploit_commands=cmds
        )
        chains.append(chain)

    return chains


def _create_service_write_chain(writer: Primitive, svc: Primitive, target: str, method="fs") -> AttackChain:
    """Helper to build file write -> service restart chain"""
    truth = "This chain reliably converts file write into root persistence."
    desc = f"Modify {target} via {writer.surface}"
    
    if method == "capabilities":
        truth = "Using CAP_DAC_OVERRIDE bypasses file permissions to overwrite the service unit."
        desc = f"Overwrite {target} using binary with cap_dac_override"

    return AttackChain(
        chain_id=new_chain_id("persistence"),
        goal="persistence",
        priority=2,
        exploitability="moderate",
        stability="moderate",
        noise="noticeable",
        classification="severe",
        summary=f"Overwrite service config via {writer.surface}",
        offensive_truth=truth,
        steps=[
            {"primitive_id": writer.id, "description": desc},
            {"primitive_id": svc.id, "description": "Trigger service reload/restart"},
        ],
        dependent_surfaces=[writer.surface, svc.surface],
        confidence=ChainConfidence(
            score=min(writer.confidence.score, svc.confidence.score),
            reason="Validated resource intersection"
        ),
        exploit_commands=[] 
    )


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
# RENDERING SUPPORT
# ----------------------------------------------------------------------

def chains_to_dict(chains: List[AttackChain]) -> List[Dict]:
    return [asdict(c) for c in chains]


def summarize_chains(chains: List[AttackChain]) -> str:
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
