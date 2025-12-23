from typing import Dict, Any, List, Optional, Set, Tuple
import re

from nullpeas.core.exec import run_command
from nullpeas.core.report import Report
from nullpeas.core.guidance import build_guidance, FindingContext
from nullpeas.core.offensive_schema import (
    Primitive,
    PrimitiveConfidence,
    OffensiveValue,
    new_primitive_id,
)
from nullpeas.modules import register_module


# Simple hints that explain why certain binaries are interesting under sudo.
GTF0BINS_SUDO_HINTS: Dict[str, List[str]] = {
    "vim": [
        "Interactive editor that can run external commands and open subshell like contexts.",
        "Can read and write files with the privileges granted by sudo.",
    ],
    "less": [
        "Interactive pager that can integrate with helpers or external tools.",
        "Advanced usage can lead to execution of external programs with elevated privileges.",
    ],
    "find": [
        "File finder that can execute other programs as part of its normal operation.",
        "Execution hooks can be abused when running under sudo.",
    ],
    "python": [
        "Full interpreter that can execute operating system commands and manipulate files.",
        "Running the interpreter under sudo grants a powerful privileged environment.",
    ],
    "python3": [
        "Full interpreter that can execute operating system commands and manipulate files.",
        "Running the interpreter under sudo grants a powerful privileged environment.",
    ],
    "tar": [
        "Archive tool that can read and write files, sometimes with execution hooks.",
        "Can be abused to overwrite or create privileged files.",
    ],
    "bash": [
        "Shell that provides a direct privileged execution environment when allowed under sudo.",
    ],
    "sh": [
        "Shell that provides a direct privileged execution environment when allowed under sudo.",
    ],
    "docker": [
        "Container management tool that can often be leveraged to escape into the host when misconfigured.",
    ],
    "systemctl": [
        "Service and platform control tool that can manage systemd units and privileged services.",
    ],
}


# Direct mapping from binary name to GTFOBins URL, used as an external reference only.
GTF0BINS_URLS: Dict[str, str] = {
    "vim": "https://gtfobins.github.io/gtfobins/vim/",
    "vi": "https://gtfobins.github.io/gtfobins/vi/",
    "nano": "https://gtfobins.github.io/gtfobins/nano/",
    "ed": "https://gtfobins.github.io/gtfobins/ed/",
    "less": "https://gtfobins.github.io/gtfobins/less/",
    "more": "https://gtfobins.github.io/gtfobins/more/",
    "man": "https://gtfobins.github.io/gtfobins/man/",
    "python": "https://gtfobins.github.io/gtfobins/python/",
    "python3": "https://gtfobins.github.io/gtfobins/python/",
    "perl": "https://gtfobins.github.io/gtfobins/perl/",
    "ruby": "https://gtfobins.github.io/gtfobins/ruby/",
    "lua": "https://gtfobins.github.io/gtfobins/lua/",
    "find": "https://gtfobins.github.io/gtfobins/find/",
    "tar": "https://gtfobins.github.io/gtfobins/tar/",
    "awk": "https://gtfobins.github.io/gtfobins/awk/",
    "rsync": "https://gtfobins.github.io/gtfobins/rsync/",
    "bash": "https://gtfobins.github.io/gtfobins/bash/",
    "sh": "https://gtfobins.github.io/gtfobins/sh/",
    "docker": "https://gtfobins.github.io/gtfobins/docker/",
    "systemctl": "https://gtfobins.github.io/gtfobins/systemctl/",
}


# Capability categories describe what a binary can realistically do in an escalation context.
GTF0BINS_CAPABILITIES: Dict[str, Set[str]] = {
    "vim": {"editor_escape", "shell_spawn", "file_read", "file_write"},
    "vi": {"editor_escape", "shell_spawn", "file_read", "file_write"},
    "nano": {"editor_escape", "file_read", "file_write"},
    "ed": {"editor_escape", "file_read", "file_write"},

    "less": {"pager_escape", "shell_spawn", "file_read"},
    "more": {"pager_escape", "file_read"},
    "man": {"pager_escape", "file_read"},

    "python": {"interpreter", "shell_spawn", "file_read", "file_write"},
    "python3": {"interpreter", "shell_spawn", "file_read", "file_write"},
    "perl": {"interpreter", "shell_spawn", "file_read", "file_write"},
    "ruby": {"interpreter", "shell_spawn", "file_read", "file_write"},
    "lua": {"interpreter", "shell_spawn", "file_read", "file_write"},

    "find": {"exec_hook", "shell_spawn", "file_write"},
    "tar": {"file_read", "file_write"},
    "awk": {"exec_hook"},
    "rsync": {"exec_hook", "file_write"},

    "bash": {"shell_spawn"},
    "sh": {"shell_spawn"},

    "docker": {"platform_control"},
    "systemctl": {"platform_control"},
}


def _command_basename(cmd: str) -> str:
    """
    Extract the basename of the sudo allowed command.
    For example:
      /usr/bin/vim -> vim
      /bin/bash -c 'something' -> bash
    """
    if not cmd:
        return ""
    parts = cmd.strip().split()
    if not parts:
        return ""
    first = parts[0]
    return first.rsplit("/", 1)[-1]


def _parse_sudo_rules(raw_stdout: str) -> List[Dict[str, Any]]:
    """
    Simple parser for sudo -l like output captured by the sudo probe.

    This is intentionally conservative. It aims to capture:
      - whether a rule is NOPASSWD
      - the raw command part
      - the raw line for reporting
      - whether the rule looks like an ALL rule

    Example lines:
      (root) NOPASSWD: /usr/bin/vim
      (ALL : ALL) ALL
      (root) ALL: ALL
    """
    rules: List[Dict[str, Any]] = []

    for line in raw_stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Heuristic: lines that start with "(" often contain rule info.
        if not stripped.startswith("("):
            continue

        # Basic flags.
        nopasswd = "NOPASSWD:" in stripped or "NOPASSWD" in stripped
        denied = "DENIED" in stripped.upper()

        # Extract runas spec inside the first parentheses, if any.
        runas_spec: Optional[str] = None
        m = re.match(r"^([^)]+)\s*(.*)$", stripped)
        rest = stripped
        if m:
            runas_spec = m.group(1).strip()
            rest = m.group(2).strip()

        # Extract the command portion after the first colon, if present.
        cmd_part = rest
        if ":" in rest:
            # e.g. "NOPASSWD: /usr/bin/vim" or "ALL: ALL"
            after_colon = rest.split(":", 1)[1].strip()
            cmd_part = after_colon if after_colon else ""

        command = cmd_part
        upper_cmd = command.strip().upper()

        is_all_rule = upper_cmd in {"ALL", "ALL ALL"}

        rules.append(
            {
                "raw": stripped,
                "nopasswd": nopasswd,
                "denied": denied,
                "command": command,
                "runas_spec": runas_spec,
                "is_all_rule": is_all_rule,
            }
        )

    return rules


def _verify_binary_available(name: str) -> Dict[str, Any]:
    """
    Check if a binary is available in PATH and if a simple version/help call succeeds.

    This stays quiet and does not use sudo.
    """
    result: Dict[str, Any] = {
        "name": name,
        "exists_in_path": False,
        "resolved_path": None,
        "version_check_ok": False,
    }

    if not name:
        return result

    resolved = run_command(f"command -v {name}")
    if not resolved:
        resolved = run_command(f"which {name}")

    if resolved:
        resolved = resolved.strip()
        result["exists_in_path"] = True
        result["resolved_path"] = resolved

        # Try a harmless version/help probe.
        for arg in ["--version", "-V", "-h", "--help"]:
            code, _ = run_command(f"{resolved} {arg}", get_exit_code=True)
            if code == 0:
                result["version_check_ok"] = True
                break

    return result


def _risk_categories_for_rule(
    nopasswd: bool,
    base: str,
    is_all_rule: bool,
) -> Set[str]:
    """
    Assign high level risk categories based on the rule and binary.
    These drive scoring and reporting, but do not generate exploits.
    """
    cats: Set[str] = set()

    if is_all_rule:
        if nopasswd:
            cats.add("sudo_global_nopasswd_all")
        else:
            cats.add("sudo_global_all")
        return cats

    if not base:
        return cats

    # Editors
    if base in {"vim", "vi", "nano", "ed"}:
        cats.add("sudo_editor_nopasswd" if nopasswd else "sudo_editor_rule")

    # Interpreters
    if base in {"python", "python3", "perl", "ruby", "lua"}:
        cats.add("sudo_interpreter_nopasswd" if nopasswd else "sudo_interpreter_rule")

    # Service / platform control
    if base in {"systemctl"}:
        cats.add("sudo_service_control")
    if base in {"docker"}:
        cats.add("sudo_platform_control")

    # Exec-hook style tools
    if base in {"find", "awk", "rsync", "tar"}:
        cats.add("sudo_exec_hook_tool")

    return cats


def _severity_for_rule(
    nopasswd: bool,
    binary_info: Dict[str, Any],
    has_gtfobins_hint: bool,
    capabilities: Set[str],
    is_all_rule: bool,
    risk_categories: Set[str],
) -> Tuple[float, str]:
    """
    Numeric severity scoring + band.

    - Global NOPASSWD: ALL => 10.0 (Critical)
    - NOPASSWD + dangerous capabilities (shell, interpreter, platform_control) => high
    - Presence of escalation-prone capabilities or GTFOBins hint => medium+
    - Otherwise low.
    """
    # Global ALL style.
    if is_all_rule and nopasswd:
        return 10.0, "Critical"

    exists = binary_info.get("exists_in_path", False)

    # Base severity components (0.0–1.0)
    auth_factor = 1.0 if nopasswd else 0.4
    scope_factor = 0.8 if is_all_rule else 0.5

    class_factor = 0.0
    if {"shell_spawn", "interpreter", "platform_control"} & capabilities:
        class_factor = 1.0
    elif capabilities:
        class_factor = 0.6
    elif has_gtfobins_hint:
        class_factor = 0.5

    # If binary does not exist, tone down slightly.
    existence_factor = 1.0 if exists else 0.6

    # Risk categories can boost slightly.
    cat_boost = 0.0
    if "sudo_editor_nopasswd" in risk_categories or "sudo_interpreter_nopasswd" in risk_categories:
        cat_boost = 0.2

    severity_raw = (
        0.25 * auth_factor
        + 0.20 * scope_factor
        + 0.40 * class_factor
        + 0.15 * existence_factor
        + cat_boost
    )
    # clamp 0.0–1.0
    severity_raw = max(0.0, min(1.0, severity_raw))
    score = round(severity_raw * 10.0, 1)

    if score >= 8.5:
        band = "Critical"
    elif score >= 6.5:
        band = "High"
    elif score >= 3.5:
        band = "Medium"
    else:
        band = "Low"

    return score, band


def _confidence_for_rule(
    binary_info: Dict[str, Any],
    is_all_rule: bool,
) -> Tuple[float, str]:
    """
    Confidence that this rule is actually usable on this host.

    Very simple initial model:
    - ALL-style rules: high confidence
    - Otherwise based on existence and version check.
    """
    if is_all_rule:
        return 9.5, "High"

    exists = binary_info.get("exists_in_path", False)
    version_ok = binary_info.get("version_check_ok", False)

    if exists and version_ok:
        return 8.0, "High"
    if exists:
        return 6.0, "Medium"

    return 3.0, "Low"


def _title_for_sudo_chain(binary: Optional[str], risk_categories: Set[str]) -> str:
    if "sudo_global_nopasswd_all" in risk_categories:
        return "sudo -> full passwordless root access"
    if binary:
        return f"sudo -> {binary} -> elevated actions"
    return "sudo-based privilege escalation surface"


def _build_attack_chains(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Build high level attack chain descriptions per relevant sudo finding.

    Chains now delegate all narrative guidance (navigation, offensive/defensive,
    impact, references) to the shared guidance engine.
    """
    chains: List[Dict[str, Any]] = []

    for f in findings:
        severity_band = f["severity_band"]
        if severity_band not in {"Critical", "High", "Medium"}:
            continue

        rule = f["raw_rule"]
        binary = f["binary"]
        caps = f.get("capabilities", set()) or set()
        risk_categories = f.get("risk_categories", set()) or set()
        nopasswd = f["nopasswd"]
        gtfobins_url = f.get("gtfobins_url")

        ctx: FindingContext = {
            "surface": "sudo",
            "rule": rule,
            "binary": binary,
            "capabilities": caps,
            "risk_categories": risk_categories,
            "severity_band": severity_band,
            "severity_score": f["severity_score"],
            "nopasswd": nopasswd,
            "gtfobins_url": gtfobins_url,
            "metadata": {
                "binary_info": f["binary_info"],
            },
        }

        guidance = build