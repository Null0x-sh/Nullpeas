#!/usr/bin/env python3

from nullpeas.core.cache import save_state
from nullpeas.probes.users_groups_probe import run as run_users_groups_probe
from nullpeas.probes.env_probe import run as run_env_probe
from nullpeas.probes.sudo_probe import run as run_sudo_probe
from nullpeas.probes.cron_probe import run as run_cron_probe



def main() -> None:
    state: dict = {}

    # Base probes
    run_users_groups_probe(state)
    run_env_probe(state)
    run_sudo_probe(state)
    run_cron_probe(state)

    save_state(state)

    user = state.get("user", {})
    env = state.get("env", {})

    print("[+] Probe completed.")
    print(f"    User: {user.get('name', 'unknown')}")
    print(f"    UID: {user.get('uid', 'unknown')}")
    print(f"    Groups: {', '.join(user.get('groups', [])) or 'unknown'}")
    print(f"    Hostname: {env.get('hostname', 'unknown')}")
    print(f"    OS: {env.get('platform_system', 'unknown')} {env.get('platform_release', '')}")
    
    sudo_info = state.get("sudo", {})

    if sudo_info.get("error"):
        print(f"    Sudo: Error - {sudo_info['error']}")
    elif sudo_info.get("has_sudo"):
        print("    Sudo: Potential sudo privileges detected")
    elif sudo_info.get("needs_password"):
        print("    Sudo: Requires password (no NOPASSWD detected)")
    else:
        print("    Sudo: No usable sudo privileges")

    cron_info = state.get("cron", {})

    if not cron_info:
        print("    Cron: No data")
    else:
        if cron_info.get("user_crontab") and "no user crontab" not in cron_info["user_crontab"].lower():
            print("    Cron: User crontab present")
        else:
            print("    Cron: No user crontab")

    if cron_info.get("found_files"):
        print("    Cron: System cron entries detected")
    else:
        print("    Cron: No system cron entries found or accessible")



if __name__ == "__main__":
    main()
