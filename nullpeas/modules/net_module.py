"""
nullpeas/modules/net_module.py
Analyzes network state for pivot points, internal services, and lateral movement targets.
v2.3:
- Semantic Types: 'network_active_session_surface' vs 'network_remote_access_surface'.
- Explicit Confidence: Reason strings now include risk classification.
- Logic: Treats 0.0.0.0 (wildcard) as locally exploitable.
"""

from typing import Dict, Any
from nullpeas.core.report import Report
from nullpeas.modules import register_module
from nullpeas.core.offensive_schema import (
    Primitive,
    PrimitiveConfidence,
    OffensiveValue,
    new_primitive_id,
)

# Detailed descriptions for the "High Value" ports
PORT_DESCRIPTIONS = {
    # Remote Access
    22: "SSH (Potential Agent Hijacking)",
    3389: "RDP",
    5900: "VNC",
    
    # Databases
    6379: "Redis (Often unauthenticated RCE via cron/ssh)",
    27017: "MongoDB (Check for NoSQL Injection/Unauth)",
    3306: "MySQL (Check for root/root or nopass)",
    5432: "PostgreSQL (Check for trust auth)",
    
    # Cloud / Container
    2375: "Docker Daemon (Unencrypted - Root Privilege Escalation)",
    2376: "Docker Daemon (TLS)",
    10250: "Kubelet API (Check anonymous access)",
    
    # Web / Dev
    8000: "Internal Web App (Dev)",
    8080: "Internal Web App (Dev)",
    9000: "Portainer / PHP-FPM",
    9200: "Elasticsearch",
}

@register_module(
    key="net_module",
    description="Analyze network listening ports and neighbors for pivot opportunities",
    required_triggers=[], 
)
def run(state: Dict[str, Any], report: Report):
    net = state.get("net", {})
    listeners = net.get("listeners", [])
    neighbors = net.get("neighbors", [])
    connections = net.get("connections", [])
    
    if not listeners and not neighbors:
        return

    user = state.get("user", {}) or {}
    origin_user = user.get("name") or "current_user"
    primitives = state.setdefault("offensive_primitives", [])
    
    lines = []
    lines.append("Analysis of Network Surface (Ports & Pivots).")
    lines.append("")

    # 1. Listening Ports Analysis
    if listeners:
        lines.append("### 🎧 Local Listening Services")
        lines.append("Services listening on localhost are prime targets for tunneling or local exploitation.")
        lines.append("")
        
        # Sort by port for readability
        listeners.sort(key=lambda x: x["local_port"])
        
        found_interesting = False
        
        for l in listeners:
            ip = l["local_ip"]
            port = l["local_port"]
            scope = l.get("scope", "bound")
            
            # Lookup Description
            desc = PORT_DESCRIPTIONS.get(port, "")
            
            # Icon Logic
            icon = "🔹"
            if l.get("high_value"):
                # Mark both Local and Wildcard as high interest for LPE
                icon = "🚨" if scope in ("local", "wildcard") else "⚠️"
                found_interesting = True
            
            # Render Report Line
            line_str = f"- {icon} `{ip}:{port}` ({l['proto']})"
            if desc:
                line_str += f" **<- {desc}**"
            elif scope == "local":
                line_str += " (Localhost Only)"
            
            lines.append(line_str)
            
            # === GENERATE PRIMITIVE ===
            if l.get("high_value"):
                _add_service_primitive(primitives, ip, port, desc, origin_user, scope)

        if not found_interesting:
            lines.append("> No critical exploit services (Redis, Docker, SQL) found.")
        lines.append("")

    # 2. Active Connections
    # Looking for INCOMING connections to port 22 (SSH)
    ssh_sessions = [c for c in connections if c["local_port"] == 22]
    
    if ssh_sessions:
        lines.append("### 🔌 Active Admin Sessions")
        for s in ssh_sessions:
            remote = s["remote_ip"]
            lines.append(f"- 👤 Established SSH from `{remote}`")
            
            primitives.append(Primitive(
                id=new_primitive_id("net", "active_session"),
                surface="network",
                type="network_active_session_surface", # v2.3: Explicit Type
                run_as=origin_user,
                origin_user=origin_user,
                exploitability="theoretical",
                stability="risky",
                noise="low",
                confidence=PrimitiveConfidence(
                    score=6.0, 
                    reason="Active SSH connection confirmed (risk=useful)"
                ),
                offensive_value=OffensiveValue(
                    classification="useful",
                    why="Active admin session implies potential for SSH Agent Hijacking (SSH_AUTH_SOCK)."
                ),
                context={"remote_ip": remote, "target_port": 22},
                affected_resource=f"SSH Session from {remote}",
                module_source="net_module",
                probe_source="net_probe"
            ))
        lines.append("")

    # 3. Neighbors
    if neighbors:
        lines.append(f"### 📡 Network Neighbors (ARP Cache)")
        lines.append(f"Found {len(neighbors)} neighbors. Potential targets for pivoting.")
        for n in neighbors[:10]: # Cap output
            lines.append(f"- `{n['ip']}` ({n['mac']}) on `{n['interface']}`")
        if len(neighbors) > 10:
            lines.append(f"- ... and {len(neighbors) - 10} more.")
        lines.append("")
        
    if net.get("error"):
        lines.append(f"> ⚠️ **Note:** {net['error']}")

    report.add_section("Network Analysis", lines)


def _add_service_primitive(primitives, ip, port, desc, user, scope):
    """Helper to create primitives for interesting ports with Semantic Types"""
    
    # Default: Generic Service
    primitive_type = "network_generic_surface"
    classification = "useful"
    exploitability = "moderate"
    confidence_score = 5.0 # Baseline
    
    # Important: Treat 0.0.0.0 (wildcard) as locally accessible too
    is_local_access = scope in ("local", "wildcard")

    # 1. Critical Surfaces (Docker / Redis)
    if port == 2375 and is_local_access:
        primitive_type = "network_docker_surface"
        classification = "catastrophic"
        exploitability = "trivial"
        desc = "Docker Socket exposed on TCP (Root Compromise)"
        confidence_score = 9.5
        
    elif port == 6379 and is_local_access:
        primitive_type = "network_redis_surface"
        classification = "critical"
        exploitability = "trivial"
        desc = "Local Redis (Potential RCE via Cron/SSH)"
        confidence_score = 8.0

    # 2. Database Surfaces (SQL / Mongo)
    elif port in [5432, 3306, 27017]:
        primitive_type = "network_db_surface"
        classification = "severe" 
        confidence_score = 6.5
    
    # 3. Remote Access Surfaces (SSH/RDP)
    elif port in [22, 3389, 5900]:
        primitive_type = "network_remote_access_surface"
        classification = "useful"
        confidence_score = 6.0
    
    primitives.append(Primitive(
        id=new_primitive_id("net", "local_service"),
        surface="network",
        type=primitive_type,
        run_as="unknown",
        origin_user=user,
        exploitability=exploitability, # type: ignore
        stability="safe",
        noise="low",
        confidence=PrimitiveConfidence(
            score=confidence_score, 
            reason=f"Port {port} confirmed listening ({scope}); risk={classification}"
        ),
        offensive_value=OffensiveValue(
            classification=classification, # type: ignore
            why=f"{desc}"
        ),
        context={"ip": ip, "port": port, "desc": desc, "scope": scope},
        affected_resource=f"{ip}:{port}",
        module_source="net_module",
        probe_source="net_probe"
    ))
