#!/usr/bin/env python3

from nullpeas.core.cache import save_state
from nullpeas.probes.users_groups_probe import run as run_users_groups_probe
from nullpeas.probes.env_probe import run as run_env_probe

def main() -> None:
    state: dict = {}

    # Base probes
    run_users_groups_probe(state)
    run_env_probe(state)

    save_state(state)

    user = state.get("user", {})
    env = state.get("env", {})

    print("[+] Probe completed.")
    print(f"    User: {user.get('name', 'unknown')}")
    print(f"    UID: {user.get('uid', 'unknown')}")
    print(f"    Groups: {', '.join(user.get('groups', [])) or 'unknown'}")
    print(f"    Hostname: {env.get('hostname', 'unknown')}")
    print(f"    OS: {env.get('platform_system', 'unknown')} {env.get('platform_release', '')}")

if __name__ == "__main__":
    main()
