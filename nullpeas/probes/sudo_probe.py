from nullpeas.core.exec import run_command


def run(state: dict):
    sudo_info = {
        "binary_present": False,
        "return_code": None,
        "raw_stdout": "",
        "raw_stderr": "",

        # High-level interpretation
        "denied_completely": False,
        "rules_listed": False,
        "has_nopasswd_rule": False,

        # Final interpretation flags
        "has_sudo_rules": False,
        "passwordless_possible": False,
        
        # === NEW FLAG ===
        "auth_required": False,  # True if we need a password to see rules

        # Errors
        "error": None,
    }

    # Use centralised runner with non-interactive flag
    # exec.py ensures LC_ALL=C so we can rely on English error messages
    res = run_command(["sudo", "-n", "-l"], timeout=5)

    # 1. Check if binary is missing
    if res["binary_missing"]:
        sudo_info["error"] = res["error"] or "sudo binary not found on system"
        state["sudo"] = sudo_info
        return
    
    # If we are here, binary exists, regardless of exit code
    sudo_info["binary_present"] = True
    sudo_info["return_code"] = res["return_code"]
    sudo_info["raw_stdout"] = res["stdout"]
    sudo_info["raw_stderr"] = res["stderr"]

    # 2. Check for Timeout
    if res["timed_out"]:
        sudo_info["error"] = "sudo -l timed out after 5 seconds"
        state["sudo"] = sudo_info
        return

    # 3. Analyze Exit Codes (The Fix)
    # sudo -n returns exit code 1 if a password is required.
    # We should NOT treat this as a fatal error.
    if res["return_code"] == 1:
        # Check stderr for standard password prompt indicators
        err_lower = res["stderr"].lower()
        if "password" in err_lower or "interaction" in err_lower:
            sudo_info["auth_required"] = True
            sudo_info["error"] = "Password required (sudo -n check). Rules hidden."
            # We continue processing because we might still see *some* output, 
            # though usually it's empty on auth failure.
    
    # If it's some other non-zero exit code (like configuration error), handle generic error
    elif res["return_code"] != 0:
        sudo_info["error"] = f"sudo returned non-zero exit code: {res['return_code']}"

    # 4. Parse Output (Standard Logic)
    stdout = res["stdout"]
    stderr = res["stderr"]
    combined = (stdout + "\n" + stderr).lower()

    # --- Hard denials
    if "may not run sudo" in combined or "not allowed to run sudo" in combined:
        sudo_info["denied_completely"] = True

    # --- Detect any listed rules
    for line in stdout.splitlines():
        line_strip = line.strip()
        # Basic detection of rule lines
        if line_strip.startswith("(") and ")" in line_strip:
            sudo_info["rules_listed"] = True

            if "nopasswd" in line_strip.lower():
                sudo_info["has_nopasswd_rule"] = True

    # --- Final computed meaning
    sudo_info["has_sudo_rules"] = (
        sudo_info["binary_present"]
        and sudo_info["rules_listed"]
        and not sudo_info["denied_completely"]
    )

    sudo_info["passwordless_possible"] = sudo_info["has_nopasswd_rule"]

    state["sudo"] = sudo_info
