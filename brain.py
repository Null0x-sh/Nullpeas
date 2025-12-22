#!/usr/bin/env python3

from nullpeas.core.cache import save_state
from nullpeas.probes.users_groups_probe import run as run_users_groups_probe

def main() -> None:
    state: dict = {}
    run_users_groups_probe(state)
    save_state(state)

    user = state.get("user", {})
    print("[+] Probe completed.")
    print(f"  User: {user.get('name', 'unknown')}")
    print(f"  UID: {user.get('uid', 'unknown')}")
    print(f"  Groups: {', '.join(user.get('groups', [])) or 'unknown'}")

if __name__ == "__main__":
    main()
