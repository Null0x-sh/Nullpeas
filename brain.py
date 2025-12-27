#!/usr/bin/env python3

"""
Nullpeas main entrypoint.

Refactored for v2.5:
- Added Network probe integration (ports, neighbors, pivots).
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
import sys

from nullpeas.core.cache import save_state
from nullpeas.core.report import Report
from nullpeas.core.chaining_engine import build_attack_chains, summarize_chains
from nullpeas.core.offensive_schema import Primitive

from nullpeas.probes.users_groups_probe import run as run_users_groups_probe
from nullpeas.probes.env_probe import run as run_env_probe
from nullpeas.probes.sudo_probe import run as run_sudo_probe
from nullpeas.probes.cron_probe import run as run_cron_probe
from nullpeas.probes.runtime_probe import run as run_runtime_probe
from nullpeas.probes.path_probe import run as run_path_probe
from nullpeas.probes.suid_probe import run as run_suid_probe
from nullpeas.probes.systemd_probe import run as run_systemd_probe
from nullpeas.probes.caps_probe import run as run_caps_probe
from nullpeas.probes.loot_probe import run as run_loot_probe
from nullpeas.probes.net_probe import run as run_net_probe 

from nullpeas.modules import get_available_modules


# ========================= Probes =========================


def _run_probe_isolated(name, func):
    local_state = {}
    error = None
    try:
        func(local_state)
    except Exception as e:
        error = str(e)
    return name, local_state, error


def _run_all_probes_threaded() -> dict:
    state: dict = {}
    probe_errors: dict = {}

    probes = [
        ("users_groups", run_users_groups_probe),
        ("env", run_env_probe),
        ("sudo", run_sudo_probe),
        ("cron", run_cron_probe),
        ("runtime", run_runtime_probe),
        ("path", run_path_probe),
        ("suid", run_suid_probe),
        ("systemd", run_systemd_probe),
        ("caps", run_caps_probe),
        ("loot", run_loot_probe),
        ("net", run_net_probe),  
    ]

    with ThreadPoolExecutor(max_workers=len(probes)) as executor:
        future_map = {
            executor.submit(_run_probe_isolated, name, func): name
            for name, func in probes
        }

        for future in as_completed(future_map):
            name = future_map[future]
            try:
                probe_name, local_state, error = future.result()
            except Exception as e:
                probe_errors[name] = f"unhandled probe exception: {e}"
                continue

            state.update(local_state)
            if error:
                probe_errors[probe_name] = error

    if probe_errors:
        state["probe_errors"] = probe_errors

    return state


# ========================= Triggers =========================


def _build_triggers(state: dict):
    user = state.get("user", {}) or {}
    sudo = state.get("sudo", {}) or {}
    cron = state.get("cron", {}) or {}
    runtime = state.get("runtime", {}) or {}
    path = state.get("path", {}) or {}
    suid = state.get("suid", {}) or {}
    systemd = state.get("systemd", {}) or {}
    # caps, loot, net don't strictly need trigger logic yet

    container = runtime.get("container", {}) or {}
    virt = runtime.get("virtualization", {}) or {}
    docker = runtime.get("docker", {}) or {}

    triggers: dict = {}

    # User and groups
    triggers["is_root"] = bool(user.get("is_root"))
    triggers["in_sudo_group"] = bool(user.get("in_sudo_group"))
    triggers["in_docker_group"] = bool(user.get("in_docker_group"))
    triggers["in_lxd_group"] = bool(user.get("in_lxd_group"))

    # Sudo
    triggers["sudo_rules_present"] = bool(sudo.get("has_sudo_rules"))
    triggers["sudo_passwordless_possible"] = bool(sudo.get("passwordless_possible"))
    triggers["sudo_denied_completely"] = bool(sudo.get("denied_completely"))

    # Cron
    files_meta = cron.get("files_metadata") or []
    triggers["cron_files_present"] = len(files_meta) > 0
    user_cron_status = (cron.get("user_crontab") or {}).get("status")
    triggers["user_crontab_present"] = user_cron_status == "ok"
    
    # SUID
    triggers["suid_files_present"] = bool(suid.get("found"))

    # Systemd
    triggers["systemd_files_present"] = bool(systemd.get("units"))

    # Runtime and docker
    triggers["in_container"] = bool(container.get("in_container"))
    triggers["container_type"] = container.get("container_type")
    triggers["virt_type"] = virt.get("type")
    triggers["virt_is_vm"] = virt.get("is_vm")
    triggers["docker_cli_present"] = bool(docker.get("binary_present"))
    triggers["docker_socket_present"] = bool(docker.get("socket_exists"))

    # PATH surface from path probe
    entries = path.get("entries") or []
    triggers["path_entries_present"] = bool(entries)

    any_world_writable = False
    any_group_writable = False
    any_home_path = False
    any_tmp_path = False

    for e in entries:
        if e.get("world_writable"):
            any_world_writable = True
        if e.get("group_writable"):
            any_group_writable = True
        if e.get("in_home"):
            any_home_path = True
        if e.get("in_tmpfs_like"):
            any_tmp_path = True

    triggers["path_world_writable_present"] = any_world_writable
    triggers["path_group_writable_present"] = any_group_writable
    triggers["path_home_segment_present"] = any_home_path
    triggers["path_tmp_segment_present"] = any_tmp_path

    # Aggregated surface flags

    triggers["sudo_privesc_surface"] = (
        not triggers["is_root"] and triggers["sudo_rules_present"]
    )

    triggers["passwordless_sudo_surface"] = (
        not triggers["is_root"] and triggers["sudo_passwordless_possible"]
    )

    triggers["cron_privesc_surface"] = (
        not triggers["is_root"] and triggers["cron_files_present"]
    )

    triggers["docker_escape_surface"] = (
        not triggers["is_root"]
        and (
            triggers["in_docker_group"]
            or (triggers["docker_cli_present"] and triggers["docker_socket_present"])
        )
    )

    triggers["container_escape_surface"] = (
        not triggers["is_root"] and triggers["in_container"]
    )

    # PATH hijack surface: any writable or user controlled PATH segment
    triggers["path_hijack_surface"] = (
        not triggers["is_root"]
        and (
            triggers["path_world_writable_present"]
            or triggers["path_home_segment_present"]
            or triggers["path_tmp_segment_present"]
        )
    )

    state["triggers"] = triggers


# ========================= Output =========================


def _print_summary(state: dict):
    user = state.get("user", {})
    env = state.get("env", {})
    sudo = state.get("sudo", {})
    cron = state.get("cron", {})
    runtime = state.get("runtime", {})
    suid = state.get("suid", {})
    systemd = state.get("systemd", {})
    caps = state.get("caps", {})
    loot = state.get("loot", {})
    net = state.get("net", {}) # <--- Get Net data

    print("=== User ===")
    print(f"  Name : {user.get('name')}")
    print(f"  UID  : {user.get('uid')}")
    print(f"  GID  : {user.get('gid')}")
    print(f"  Root : {user.get('is_root')}")
    group_names = [g.get("name") for g in user.get("groups", []) if g.get("name")]
    print(f"  Groups: {', '.join(group_names) if group_names else 'unknown'}")
    print()

    print("=== Environment ===")
    print(f"  Hostname  : {env.get('hostname')}")
    pretty_os = (
        env.get("os_pretty_name")
        or env.get("os_id")
        or env.get("platform_system")
    )
    print(f"  OS        : {pretty_os}")
    print(f"  Kernel    : {env.get('kernel_release')}")
    print(f"  Arch      : {env.get('architecture')}")
    print()

    print("=== Sudo ===")
    if sudo.get("error"):
        print(f"  Error            : {sudo['error']}")
    else:
        print(f"  Binary present   : {sudo.get('binary_present')}")
        print(f"  Has rules        : {sudo.get('has_sudo_rules')}")
        print(f"  Passwordless     : {sudo.get('passwordless_possible')}")
        print(f"  Denied completely: {sudo.get('denied_completely')}")
    print()

    print("=== Cron ===")
    found_files = cron.get("files_metadata", []) or []
    print(f"  Cron files found : {len(found_files)}")
    user_cron = cron.get("user_crontab", {})
    print(f"  User crontab     : {user_cron.get('status', 'unknown')}")
    print()
    
    print("=== SUID ===")
    if suid.get("error"):
        print(f"  Error            : {suid['error']}")
    else:
        found_count = len(suid.get("found", []))
        method = suid.get("method", "unknown")
        print(f"  Files found      : {found_count}")
        print(f"  Method           : {method}")
    print()
    
    print("=== Capabilities ===")
    if caps.get("error"):
        print(f"  Error            : {caps['error']}")
    else:
        print(f"  Files found      : {len(caps.get('found', []))}")
    print()
    
    print("=== Systemd ===")
    if systemd.get("error"):
        print(f"  Error            : {systemd['error']}")
    else:
        print(f"  Units found      : {len(systemd.get('units', []))}")
        print(f"  Writable units   : {len(systemd.get('writable_units', []))}")
        print(f"  Writable binaries: {len(systemd.get('writable_binaries', []))}")
    print()

    print("=== Loot (Files) ===")
    if loot.get("error"):
        print(f"  Error            : {loot['error']}")
    else:
        print(f"  Files found      : {len(loot.get('found', []))}")
    print()

    print("=== Network ===")
    if net.get("error"):
        print(f"  Error            : {net['error']}")
    else:
        print(f"  Listeners        : {len(net.get('listeners', []))}")
        print(f"  Neighbors        : {len(net.get('neighbors', []))}")
    print()

    print("=== Runtime ===")
    container = runtime.get("container", {})
    virt = runtime.get("virtualization", {})
    docker = runtime.get("docker", {})

    print(f"  In container   : {container.get('in_container')}")
    print(f"  Container type : {container.get('container_type')}")
    print(f"  Virt type      : {virt.get('type')}")
    print(f"  Virt is_vm     : {virt.get('is_vm')}")
    print(f"  Docker present : {docker.get('binary_present')}")
    print(f"  Docker socket  : {'exists' if docker.get('socket_exists') else 'missing'}")
    print()

    probe_errors = state.get("probe_errors", {})
    if probe_errors:
        print("=== Probe Errors ===")
        for name, err in probe_errors.items():
            print(f"  {name}: {err}")
        print()


def _print_suggestions(state: dict):
    triggers = state.get("triggers", {}) or {}

    print("=== Suggestions ===")

    if triggers.get("is_root"):
        print("  You are already root. Focus on credential harvesting, lateral movement, and hardening.")
        print()
        return

    suggestions: List[str] = []

    if triggers.get("passwordless_sudo_surface"):
        suggestions.append(
            "[!] Passwordless sudo detected. Recommended: sudo_enum to analyse NOPASSWD rules and GTFOBins-style candidates."
        )
    elif triggers.get("sudo_privesc_surface"):
        suggestions.append(
            "[>] Sudo rules present. Recommended: sudo_enum to parse sudo -l and highlight potential escalation vectors."
        )

    if triggers.get("cron_privesc_surface"):
        suggestions.append(
            "[>] Cron surfaces detected. Recommended: cron_enum to analyse cron configuration and scheduled execution surfaces."
        )

    if triggers.get("docker_escape_surface"):
        suggestions.append(
            "[!] Docker host surface detected. Recommended: docker_enum to analyse Docker daemon access and potential container escape paths."
        )

    if triggers.get("container_escape_surface"):
        suggestions.append(
            "[>] Running inside a container. Future module: container_context_module."
        )

    if triggers.get("path_hijack_surface"):
        suggestions.append(
            "[>] PATH hijack surfaces detected. Recommended: path_enum to analyse writable or user-controlled PATH segments."
        )
        
    if triggers.get("systemd_files_present"):
        suggestions.append(
            "[>] Systemd present. Recommended: systemd_enum to analyse services for writable units or binaries."
        )

    if not suggestions:
        suggestions.append(
            "[-] No strong privesc surfaces detected. Consider deeper review or more probes."
        )

    for s in suggestions:
        print("  " + s)

    print()


# ========================= Analysis -> Report =========================


def _append_analysis_sections_to_report(state: dict, report: Report) -> None:
    analysis = state.get("analysis") or {}
    if not analysis:
        return

    # Stable ordering: known surfaces first, then any others.
    preferred_order = ["sudo", "docker", "cron", "systemd", "path", "suid", "caps", "loot", "net"] # <--- Added net
    ordered_keys: List[str] = []

    for k in preferred_order:
        if k in analysis:
            ordered_keys.append(k)

    for k in sorted(analysis.keys()):
        if k not in ordered_keys:
            ordered_keys.append(k)

    for key in ordered_keys:
        entry = analysis.get(key) or {}
        heading = entry.get("heading") or f"{key.title()} Analysis"
        body_lines = entry.get("summary_lines") or []

        if body_lines:
            report.add_section(heading, body_lines)


# ========================= Offensive Chains -> Report =========================


def _append_offensive_chains_to_report(state: dict, report: Report) -> None:
    """
    Collect offensive primitives, build chains, and report them.
    Includes the new 'Exploit Cheat Sheet' section which prints to STDOUT.
    """
    primitives: List[Primitive] = state.get("offensive_primitives") or []

    if not primitives:
        report.add_section(
            "Offensive Attack Chains",
            [
                "No offensive primitives were reported by modules.",
                "Either the host is relatively hardened, or current modules are still conservative.",
            ],
        )
        return

    chains = build_attack_chains(primitives)
    
    # === FIX: Pass chains to Report for Mermaid Visualization ===
    report.add_attack_chains(chains)
    # ============================================================

    if not chains:
        report.add_section(
            "Offensive Attack Chains",
            [
                "Offensive primitives were discovered, but no meaningful attack chains could be constructed.",
            ],
        )
        return

    summary_text = summarize_chains(chains)

    lines: List[str] = []
    lines.append("Nullpeas offensive chaining engine analysed all discovered offensive primitives.")
    lines.append("Below are the most realistic and impactful attack chains identified on this host.")
    lines.append("")
    lines.append("### Offensive Summary")
    lines.append("")
    for line in summary_text.splitlines():
        if line.strip():
            lines.append(line)
    lines.append("")
    lines.append("### Detailed Attack Chains")
    lines.append("")

    # --- Chain Details ---
    for idx, chain in enumerate(chains, start=1):
        lines.append(f"#### Chain {idx}: {chain.goal}")
        lines.append(f"- Chain ID       : `{chain.chain_id}`")
        lines.append(f"- Goal           : `{chain.goal}`")
        lines.append(f"- Priority       : {chain.priority}")
        lines.append(f"- Classification : {chain.classification}")
        lines.append(f"- Exploitability : {chain.exploitability}")
        lines.append(f"- Stability      : {chain.stability}")
        lines.append(f"- Noise profile  : {chain.noise}")
        lines.append("")
        lines.append(f"**Offensive reality:** {chain.offensive_truth}")
        lines.append("")
        lines.append("**Steps:**")
        for step in chain.steps:
            pid = step.get("primitive_id")
            desc = step.get("description", "").strip() or "Unnamed step"
            lines.append(f"- `{pid}` -> {desc}")
        lines.append("")

        if chain.dependent_surfaces:
            surfaces = ", ".join(sorted(chain.dependent_surfaces))
            lines.append(f"**Surfaces involved:** {surfaces}")
            lines.append("")

        lines.append(
            f"**Confidence:** {chain.confidence.score}/10 ({chain.confidence.reason})"
        )
        lines.append("")

    report.add_section("Offensive Attack Chains", lines)

    # ===: Exploit Cheat Sheet (Report + STDOUT) ===
    cheat_sheet_lines = []
    has_exploits = False

    for chain in chains:
        cmds = getattr(chain, "exploit_commands", [])
        if cmds:
            has_exploits = True
            cheat_sheet_lines.append(f"**Chain: {chain.goal} (ID: {chain.chain_id})**")
            for cmd in cmds:
                cheat_sheet_lines.append(f"```bash\n{cmd}\n```")
            cheat_sheet_lines.append("")

    # 1. Add to Report
    if cheat_sheet_lines:
        report.add_section(
            "☠️ Exploit Cheat Sheet",
            [
                "Copy-pasteable commands derived from high-confidence chains.",
                "⚠️  Use with caution. Understand what you are executing.",
                ""
            ] + cheat_sheet_lines
        )

    # 2. Print to Terminal (Instant Gratification)
    if has_exploits:
        print("\n" + "="*60)
        print(" 🔥 EXPLOIT CHEAT SHEET (Generated High-Confidence) 🔥")
        print("="*60)
        for chain in chains:
            cmds = getattr(chain, "exploit_commands", [])
            if cmds:
                print(f"\n[+] Goal: {chain.goal}")
                for cmd in cmds:
                    print(f"    $ {cmd}")
        print("="*60 + "\n")


# ========================= Interactive Modules =========================


def _interactive_modules(state: dict, report: Report):
    """
    Simple interactive CLI with TTY detection.
    """
    triggers = state.get("triggers", {}) or {}

    if triggers.get("is_root"):
        return

    modules = get_available_modules(triggers)
    if not modules:
        return

    # === FIX: Auto-Run for Reverse Shells ===
    if not sys.stdin.isatty():
        print("[*] Non-interactive shell detected (no TTY).")
        print("[*] Automatically running all applicable modules based on triggers...")
        for mod in modules:
            print(f"Running module: {mod['key']} - {mod['description']}")
            mod["run"](state, report)
        return

    # === Normal Interactive Mode ===
    print("=== Modules ===")
    for idx, mod in enumerate(modules, start=1):
        print(f"  {idx}) {mod['key']} - {mod['description']}")
    print("  0) Skip all")
    print()
    print("Enter:")
    print("  - A single number (e.g. 1)")
    print("  - Multiple numbers (e.g. 1,3 or 1 3)")
    print("  - 'a' or 'all' to run all modules")
    print("  - 0 or empty input to skip")
    print()

    try:
        choice_raw = input("Select modules: ").strip().lower()
    except EOFError:
        print("Input error. Skipping modules.")
        return

    # Skip on 0 or empty
    if choice_raw in ("", "0", "skip"):
        print("Skipping modules.")
        return

    # Run all
    if choice_raw in ("a", "all"):
        selected_modules = modules[:]
    else:
        # Parse comma or space separated list
        tokens = choice_raw.replace(",", " ").split()
        indices: List[int] = []
        for token in tokens:
            if not token.isdigit():
                continue
            idx = int(token)
            if 1 <= idx <= len(modules):
                indices.append(idx)

        if not indices:
            print("No valid module selections detected. Skipping modules.")
            return

        # Deduplicate while preserving order
        seen_keys = set()
        selected_modules = []
        for idx in indices:
            mod = modules[idx - 1]
            key = mod["key"]
            if key in seen_keys:
                continue
            seen_keys.add(key)
            selected_modules.append(mod)

    # Run selected modules
    for mod in selected_modules:
        print(f"Running module: {mod['key']} - {mod['description']}")
        mod["run"](state, report)


# ========================= Main =========================


def main():
    state = _run_all_probes_threaded()
    _build_triggers(state)

    save_state(state)

    _print_summary(state)
    _print_suggestions(state)

    # Build report object up front
    report = Report(title="Nullpeas Privilege Escalation Analysis")

    # Run interactive modules
    _interactive_modules(state, report)

    # 1) Analysis sections
    _append_analysis_sections_to_report(state, report)

    # 2) Offensive chaining engine section
    _append_offensive_chains_to_report(state, report)

    if report.sections:
        path = report.write()
        print(f"[+] Report written to: {path}")


if __name__ == "__main__":
    main()
