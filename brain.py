#!/usr/bin/env python3

"""
Nullpeas main entrypoint.

- Runs probes (threaded)
- Derives triggers
- Prints summary + suggestions
- Optionally runs medium-level analysis modules interactively
- Writes a Markdown report to cache/
"""

from concurrent.futures import ThreadPoolExecutor, as_completed

from nullpeas.core.cache import save_state
from nullpeas.core.report import Report

from nullpeas.probes.users_groups_probe import run as run_users_groups_probe
from nullpeas.probes.env_probe import run as run_env_probe
from nullpeas.probes.sudo_probe import run as run_sudo_probe
from nullpeas.probes.cron_probe import run as run_cron_probe
from nullpeas.probes.runtime_probe import run as run_runtime_probe

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
        ("env",          run_env_probe),
        ("sudo",         run_sudo_probe),
        ("cron",         run_cron_probe),
        ("runtime",      run_runtime_probe),
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

    container = runtime.get("container", {}) or {}
    virt = runtime.get("virtualization", {}) or {}
    docker = runtime.get("docker", {}) or {}

    triggers = {}

    triggers["is_root"] = bool(user.get("is_root"))
    triggers["in_sudo_group"] = bool(user.get("in_sudo_group"))
    triggers["in_docker_group"] = bool(user.get("in_docker_group"))
    triggers["in_lxd_group"] = bool(user.get("in_lxd_group"))

    triggers["sudo_rules_present"] = bool(sudo.get("has_sudo_rules"))
    triggers["sudo_passwordless_possible"] = bool(sudo.get("passwordless_possible"))
    triggers["sudo_denied_completely"] = bool(sudo.get("denied_completely"))

    files_meta = cron.get("files_metadata") or []
    triggers["cron_files_present"] = len(files_meta) > 0
    user_cron_status = (cron.get("user_crontab") or {}).get("status")
    triggers["user_crontab_present"] = (user_cron_status == "ok")

    triggers["in_container"] = bool(container.get("in_container"))
    triggers["container_type"] = container.get("container_type")
    triggers["virt_type"] = virt.get("type")
    triggers["virt_is_vm"] = virt.get("is_vm")
    triggers["docker_cli_present"] = bool(docker.get("binary_present"))
    triggers["docker_socket_present"] = bool(docker.get("socket_exists"))

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

    state["triggers"] = triggers


# ========================= Output =========================

def _print_summary(state: dict):
    user = state.get("user", {})
    env = state.get("env", {})
    sudo = state.get("sudo", {})
    cron = state.get("cron", {})
    runtime = state.get("runtime", {})

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
    pretty_os = env.get("os_pretty_name") or env.get("os_id") or env.get("platform_system")
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

    suggestions = []

    if triggers.get("passwordless_sudo_surface"):
        suggestions.append(
            "[!] Passwordless sudo detected. Recommended: sudo_enum_module "
            "to analyse NOPASSWD rules and GTFOBins-style candidates."
        )
    elif triggers.get("sudo_privesc_surface"):
        suggestions.append(
            "[>] Sudo rules present. Recommended: sudo_enum_module to parse sudo -l "
            "and highlight potential escalation vectors."
        )

    if triggers.get("cron_privesc_surface"):
        suggestions.append(
            "[>] Cron surfaces detected. Future module: cron_analysis_module."
        )

    if triggers.get("docker_escape_surface"):
        suggestions.append(
            "[>] Docker host surface detected. Future module: docker_surface_module."
        )

    if triggers.get("container_escape_surface"):
        suggestions.append(
            "[>] Running inside a container. Future module: container_context_module."
        )

    if not suggestions:
        suggestions.append(
            "[-] No strong privesc surfaces detected. Consider deeper review or more probes."
        )

    for s in suggestions:
        print("  " + s)

    print()


# ========================= Interactive Modules =========================

def _interactive_modules(state: dict, report: Report):
    """
    Simple interactive CLI:
    - Ask the registry which modules are applicable based on triggers
    - Let the operator pick one
    - Run it and append to the report
    """
    triggers = state.get("triggers", {}) or {}

    if triggers.get("is_root"):
        return

    modules = get_available_modules(triggers)
    if not modules:
        return

    print("=== Modules ===")
    for idx, mod in enumerate(modules, start=1):
        print(f"  {idx}) {mod['key']} - {mod['description']}")
    print("  0) Skip")
    print()

    choice = input("Select a module: ").strip()

    if not choice.isdigit():
        print("Skipping modules.")
        return

    num = int(choice)
    if num == 0 or num > len(modules):
        print("Skipping modules.")
        return

    mod = modules[num - 1]
    print(f"Running module: {mod['key']} - {mod['description']}")
    mod["run"](state, report)



# ========================= Main =========================

def main():
    state = _run_all_probes_threaded()
    _build_triggers(state)

    save_state(state)

    _print_summary(state)
    _print_suggestions(state)

    report = Report(title="Nullpeas Privilege Escalation Analysis")
    _interactive_modules(state, report)

    if report.sections:
        path = report.write()
        print(f"[+] Report written to: {path}")


if __name__ == "__main__":
    main()
