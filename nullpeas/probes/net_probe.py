"""
nullpeas/probes/net_probe.py
Enumerates network state via /proc/net filesystem (binary independent).
Finds:
1. Listening Ports (focusing on localhost/internal).
2. Established Connections (admin sessions).
3. ARP Neighbors (lateral movement targets).

v2.1 Fixes:
- Fixed IPv6 wildcard detection logic (:: match).
- Cleaned up imports.
"""

import os
from typing import Dict, Any

# Standard "High Value" ports for Admin/DB/Remote Access
HIGH_VALUE_PORTS = {
    22, 3389, 5900,          # Remote Access
    5432, 3306, 6379, 27017, # Databases
    389, 445, 88,            # AD/SMB
    2375, 2376, 10250        # Cloud/Container
}

def run(state: Dict[str, Any]) -> None:
    net_data = {
        "listeners": [],
        "connections": [],
        "neighbors": [],
        "error": None,
        "method": "proc_fs"
    }

    try:
        # 1. Parse TCP/UDP Listeners & Connections
        # We check both IPv4 and IPv6 if available
        for proto, path in [("tcp", "/proc/net/tcp"), ("tcp6", "/proc/net/tcp6"), 
                            ("udp", "/proc/net/udp"), ("udp6", "/proc/net/udp6")]:
            if os.path.exists(path):
                _parse_proc_net(path, proto, net_data)

        # 2. Parse ARP Neighbors (Lateral Movement targets)
        if os.path.exists("/proc/net/arp"):
            _parse_proc_arp("/proc/net/arp", net_data)

    except Exception as e:
        net_data["error"] = str(e)

    state["net"] = net_data


def _parse_proc_net(path: str, proto: str, data: Dict[str, Any]):
    """
    Parses Linux /proc/net/tcp format.
    Format: sl local_address rem_address st ...
    """
    try:
        with open(path, "r") as f:
            lines = f.readlines()
            
        # Skip header row
        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) < 4:
                continue

            # Parse Local Address (IP:Port)
            local_ip, local_port = _hex_to_ip_port(parts[1])
            if local_ip == "unknown":
                continue # Skip garbage

            # Parse Remote Address
            rem_ip, rem_port = _hex_to_ip_port(parts[2])
            
            # State (0A = Listen, 01 = Established)
            state_hex = parts[3]

            # === Logic 1: Scope Tagging ===
            scope = "bound"
            if local_ip in ("127.0.0.1", "::1"):
                scope = "local"
            # Fix: Check for normalized wildcard '::' or standard '0.0.0.0'
            elif local_ip in ("0.0.0.0", "::"):
                scope = "wildcard"
            
            # === Logic 2: High Value Tagging ===
            is_high_value = (local_port in HIGH_VALUE_PORTS) or (rem_port in HIGH_VALUE_PORTS)

            entry = {
                "proto": proto,
                "local_ip": local_ip,
                "local_port": local_port,
                "remote_ip": rem_ip,
                "remote_port": rem_port,
                "state_raw": state_hex,
                "scope": scope,
                "high_value": is_high_value,
                "pid": None # Placeholder for future inode -> pid mapping
            }

            # TCP Listen (0A) / UDP (07)
            if state_hex == "0A" or (proto.startswith("udp") and state_hex == "07"):
                data["listeners"].append(entry)
            
            # TCP Established (01)
            elif state_hex == "01":
                data["connections"].append(entry)

    except Exception:
        pass # Best effort


def _parse_proc_arp(path: str, data: Dict[str, Any]):
    """
    Parses /proc/net/arp to find neighbors.
    """
    try:
        with open(path, "r") as f:
            lines = f.readlines()
        
        # Header: IP address HW type Flags HW address Mask Device
        for line in lines[1:]:
            parts = line.split()
            if len(parts) >= 6:
                ip = parts[0]
                mac = parts[3]
                dev = parts[5]
                if mac != "00:00:00:00:00:00": # Filter incomplete entries
                    data["neighbors"].append({"ip": ip, "mac": mac, "interface": dev})
    except Exception:
        pass


def _hex_to_ip_port(hex_str: str):
    """
    Converts '0100007F:1F90' -> ('127.0.0.1', 8080)
    Handles Little Endian IP logic of /proc/net.
    """
    try:
        if ':' not in hex_str:
            return "unknown", 0
            
        ip_hex, port_hex = hex_str.split(':')
        port = int(port_hex, 16)
        
        # IP Conversion (Little Endian for IPv4)
        if len(ip_hex) == 8: # IPv4
            # 01 00 00 7F -> 7F 00 00 01 -> 127.0.0.1
            try:
                ip_parts = [str(int(ip_hex[i:i+2], 16)) for i in range(6, -2, -2)]
                ip = ".".join(ip_parts)
            except ValueError:
                return "unknown", 0
        else:
            # IPv6
            if ip_hex == "00000000000000000000000000000000":
                ip = "::"
            elif ip_hex == "00000000000000000000000001000000":
                ip = "::1"
            else:
                # Truncated representation for readability
                ip = f"IPv6:{ip_hex[:8]}..."

        return ip, port
    except Exception:
        return "unknown", 0
