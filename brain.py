#!/usr/bin/env python3

"""
Nullpeas main entrypoint.

- Creates the initial state dict
- Runs all enabled probes (threaded)
- Saves state to cache
- Prints a short human-readable summary
"""

from concurrent.futures import ThreadPoolExecutor, as_completed

from nullpeas.core.cache import save_state

from nullpeas.probes.users_groups_probe import run as run_users_groups_probe
from nullpeas.probes.env_probe import run as run_env_probe
from nullpeas.probes.sudo_probe import run as run_sudo_probe
from nullpeas.probes.cron_probe import run as run_cron_probe
from nullpeas.probes.runtime_probe import run as run_runtime_probe


def _run_probe_isolated(name, func):
    """
    Run a probe in isolation with its own local state dict.

    Returns:
        (probe_name, local_state_dict, error_string_or_None)
    """
    local_state = {}
    error = None

    try:
        func(local_state)
    except Exception as e:
        error = str(e)

    return name, local_state, error


def _run_all_probes_threaded() -> dict:
    """
    Run all probes in parallel and merge their local states into a single state dict.
    """
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
                # This should be rare because _run_probe_isolated already catches,
                # but we guard anyway.
                probe_errors[name] = f"unhandled probe exception: {e}"
                continue

            # Merge the local_state into the global state.
            # Probes are expected to use unique top-level keys (e.g. "user", "env").
            state.update(local_state)

            if error:
                probe_errors[probe_name] = error

    if probe_errors:
        state["probe_errors"] = probe_errors

    return state


def _print_summary(state: dict):
    """
    Minimal, low-noise summary for the operator.
    This is *not* the detailed output; that lives in the JSON cache.
    """
    user = state.get("user", {})
    env = state.get("env", {})
    sudo = state.get("sudo", {})
    cron = state.get("cron", {})
    runtime = state.get("runtime", {})

    # User summary
    print("=== User ===")
    print(f"  Name : {user.get('name')}")
    print(f"  UID  : {user.get('uid')}")
    print(f"  GID  : {user.get('gid')}")
    print(f"  Root : {user.get('is_root')}")
    group_names = [g.get("name") for g in user.get("groups", []) if g.get("name")]
    print(f"  Groups: {', '.join(group_names) if group_names else 'unknown'}")
    print()

    # Env summary
    print("=== Environment ===")
    print(f"  Hostname  : {env.get('hostname')}")
    pretty_os = env.get("os_pretty_name") or env.get("os_id") or env.get("platform_system")
    print(f"  OS        : {pretty_os}")
    print(f"  Kernel    : {env.get('kernel_release')}")
    print(f"  Arch      : {env.get('architecture')}")
    print()

    # Sudo summary
    print("=== Sudo ===")
    if sudo.get("error"):
        print(f"  Error            : {sudo['error']}")
    else:
        print(f"  Binary present   : {sudo.get('binary_present')}")
        print(f"  Has rules        : {sudo.get('has_sudo_rules')}")
        print(f"  Passwordless     : {sudo.get('passwordless_possible')}")
        print(f"  Denied completely: {sudo.get('denied_completely')}")
    print()

    # Cron summary
    print("=== Cron ===")
    found_files = cron.get("files_metadata", []) or []
    print(f"  Cron files found : {len(found_files)}")
    user_cron = cron.get("user_crontab", {})
    print(f"  User crontab     : {user_cron.get('status', 'unknown')}")
    print()

    # Runtime summary
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

    # Probe-level errors (if any)
    probe_errors = state.get("probe_errors", {})
    if probe_errors:
        print("=== Probe Errors ===")
        for name, err in probe_errors.items():
            print(f"  {name}: {err}")
        print()

    # Probe-level errors (if any)
    probe_errors = state.get("probe_errors", {})
    if probe_errors:
        print("=== Probe Errors ===")
        for name, err in probe_errors.items():
            print(f"  {name}: {err}")
        print()


def main():
    # Run probes in parallel and get merged state
    state = _run_all_probes_threaded()

    # Persist state to cache
    save_state(state)

    # Print a compact, human summary
    _print_summary(state)


if __name__ == "__main__":
    main()
