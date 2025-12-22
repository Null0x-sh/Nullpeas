from typing import Dict, Any, List, Optional

from nullpeas.core.exec import run_command
from nullpeas.core.report import Report
from nullpeas.modules import register_module



# Minimal GTFOBins-style mapping.
# We don't execute anything; we just tell the operator *what* is possible.
GTF0BINS_SUDO_HINTS = {
    "vim": [
        "Vim can be used to spawn a shell via commands like:",
        "  :! /bin/sh",
        "or in some cases:",
        "  :set shell=/bin/sh | shell",
    ],
    "vi": [
        "Vi/Vim can be used for shell escape:",
        "  :! /bin/sh",
    ],
    "less": [
        "Less can often spawn a shell:",
        "  !/bin/sh",
    ],
    "more": [
        "More sometimes allows shell escape:",
        "  !/bin/sh",
    ],
    "tar": [
        "Tar can be abused via --checkpoint/--checkpoint-action to execute commands.",
        "See GTFOBins for tar + sudo privesc patterns.",
    ],
    "python": [
        "Python can spawn a shell:",
        "  python -c 'import os; os.system(\"/bin/sh\")'",
    ],
    "python3": [
        "Python3 can spawn a shell:",
        "  python3 -c 'import os; os.system(\"/bin/sh\")'",
    ],
    "find": [
        "Find can execute commands:",
        "  find . -exec /bin/sh \\; -quit",
    ],
    "bash": [
        "Bash can of course spawn an interactive shell:",
        "  bash -p",
    ],
    "sh": [
        "sh can be used directly as a shell.",
    ],
}


def _parse_sudo_rules(raw_output: str) -> List[Dict[str, Any]]:
    """
    Parse sudo -l stdout into a list of rule dicts:
      {
        "raw": full line,
        "as_user": "...",
        "flags": "...",
        "command": "/usr/bin/vim",
        "nopasswd": True/False,
      }
    Heuristic but good enough for analysis.
    """
    rules: List[Dict[str, Any]] = []

    for line in raw_output.splitlines():
        l = line.strip()
        if not l:
            continue

        # Typical sudo rules:
        #   (root) NOPASSWD: /usr/bin/vim
        #   (ALL : ALL) ALL
        if not l.startswith("(") or ")" not in l:
            continue

        rule: Dict[str, Any] = {
            "raw": l,
            "as_user": None,
            "flags": None,
            "command": None,
            "nopasswd": False,
        }

        try:
            user_part, rest = l.split(")", 1)
            user_part = user_part.lstrip("(").strip()
            rest = rest.strip()
            rule["as_user"] = user_part

            if ":" in rest:
                flags_part, cmd_part = rest.split(":", 1)
                flags_part = flags_part.strip()
                cmd_part = cmd_part.strip()
                rule["flags"] = flags_part
                rule["command"] = cmd_part or None
            else:
                rule["flags"] = rest
                rule["command"] = None

            if rule["flags"] and "nopasswd" in rule["flags"].lower():
                rule["nopasswd"] = True

        except ValueError:
            # If parsing fails, keep raw only
            rule["flags"] = None
            rule["command"] = None

        rules.append(rule)

    return rules


def _command_basename(cmd: Optional[str]) -> str:
    # Extract the "vim" from "/usr/bin/vim arg1 arg2"
    if not cmd:
        return ""
    first = cmd.strip().split()[0]
    return first.split("/")[-1]


def _verify_binary_available(bin_name: str) -> Dict[str, Any]:
    """
    Scoped, quiet verification that a GTFO candidate is actually present
    and executable in this environment.

    This is "medium" enumeration: a couple of safe extra commands, nothing noisy.
    """
    info: Dict[str, Any] = {
        "name": bin_name,
        "exists_in_path": False,
        "resolved_path": None,
        "version_check_ok": False,
    }

    if not bin_name:
        return info

    # Check presence in PATH
    which_res = run_command(["which", bin_name], timeout=3)
    if which_res["ok"] and which_res["stdout"]:
        info["exists_in_path"] = True
        info["resolved_path"] = which_res["stdout"].splitlines()[0].strip()
    else:
        return info

    # Light-touch version check to confirm it runs at all
    # We don't care about the exact version string, just that it executes.
    version_res = run_command([bin_name, "--version"], timeout=2)
    if version_res["ok"] or version_res["stdout"] or version_res["stderr"]:
        info["version_check_ok"] = True

    return info


def _severity_for_rule(
    nopasswd: bool, bin_info: Dict[str, Any], has_gtfobins_hint: bool
) -> str:
    """
    Very simple severity heuristic:
      - high: NOPASSWD + binary confirmed + GTFOBins hint present
      - medium: NOPASSWD + binary confirmed, but no specific hint OR
                sudo rule present + binary confirmed
      - low: everything else
    """
    exists = bin_info.get("exists_in_path") and bin_info.get("version_check_ok")

    if nopasswd and exists and has_gtfobins_hint:
        return "high"

    if exists and (nopasswd or has_gtfobins_hint):
        return "medium"

    return "low"


def run(state: dict, report: Report):
    """
    Medium-level sudo analysis module.

    - Uses existing sudo probe output (no extra sudo -l calls).
    - Parses rules for NOPASSWD and GTFOBins-like candidates.
    - Quietly verifies candidate binaries exist and can execute.
    - Assigns a simple severity level to each finding.
    - Writes a human-readable section to the report.
    """
    sudo = state.get("sudo", {}) or {}
    raw_stdout = sudo.get("raw_stdout") or ""

    if not raw_stdout:
        report.add_section(
            "Sudo Analysis",
            [
                "No sudo output available in state. Either sudo is missing,",
                "denied, or the sudo probe did not run.",
            ],
        )
        return

    rules = _parse_sudo_rules(raw_stdout)

    if not rules:
        report.add_section(
            "Sudo Analysis",
            [
                "sudo -l output was available but no rules could be parsed.",
                "This may indicate a denial-only response or an unusual sudo configuration.",
            ],
        )
        return

    findings: List[Dict[str, Any]] = []

    for r in rules:
        cmd = r.get("command")
        base = _command_basename(cmd)
        gtfobins_hint = GTF0BINS_SUDO_HINTS.get(base)
        bin_info = _verify_binary_available(base) if base else {
            "name": base,
            "exists_in_path": False,
            "resolved_path": None,
            "version_check_ok": False,
        }
        severity = _severity_for_rule(r.get("nopasswd", False), bin_info, gtfobins_hint is not None)

        findings.append(
            {
                "raw_rule": r["raw"],
                "nopasswd": r.get("nopasswd", False),
                "binary": base or None,
                "binary_info": bin_info,
                "has_gtfobins_hint": gtfobins_hint is not None,
                "gtfobins_hint_lines": gtfobins_hint or [],
                "severity": severity,
            }
        )

    # Build report lines
    lines: List[str] = []

    lines.append("This section analyses the existing sudo -l output collected by Nullpeas.")
    lines.append("No additional sudo -l invocations were made by this module.")
    lines.append("It performed limited extra checks (which/--version) to confirm binaries exist and can run.")
    lines.append("")

    # Raw rules overview
    lines.append("### Parsed sudo rules")
    for f in findings:
        lines.append(f"- {f['raw_rule']}")
    lines.append("")

    # High/medium/low groups
    def _group(sev: str) -> List[Dict[str, Any]]:
        return [f for f in findings if f["severity"] == sev]

    high = _group("high")
    med = _group("medium")
    low = _group("low")

    if high:
        lines.append("### High-confidence escalation surfaces")
        lines.append("")
        lines.append("These rules likely allow a direct or near-direct shell or privileged action:")
        lines.append("")
        for f in high:
            bi = f["binary_info"]
            lines.append(f"- `{f['raw_rule']}`")
            lines.append(f"  - Binary            : {f['binary']}")
            lines.append(f"  - Resolved path     : {bi.get('resolved_path')}")
            lines.append(f"  - Binary available  : {bi.get('exists_in_path')}")
            lines.append(f"  - Executes cleanly  : {bi.get('version_check_ok')}")
            lines.append(f"  - NOPASSWD          : {f['nopasswd']}")
            if f["has_gtfobins_hint"]:
                lines.append("  - Potential GTFOBins technique(s):")
                for hint in f["gtfobins_hint_lines"]:
                    lines.append(f"    {hint}")
            lines.append(
                "  - Note: Nullpeas does not execute these commands for you. "
                "You must run any escalation attempts manually."
            )
            lines.append("")
        lines.append("")

    if med:
        lines.append("### Medium-confidence surfaces")
        lines.append("")
        lines.append(
            "These rules and binaries look promising but may require more manual validation, "
            "credentials, or environment-specific tweaks:"
        )
        lines.append("")
        for f in med:
            bi = f["binary_info"]
            lines.append(f"- `{f['raw_rule']}`")
            lines.append(f"  - Binary            : {f['binary']}")
            lines.append(f"  - Resolved path     : {bi.get('resolved_path')}")
            lines.append(f"  - Binary available  : {bi.get('exists_in_path')}")
            lines.append(f"  - Executes cleanly  : {bi.get('version_check_ok')}")
            lines.append(f"  - NOPASSWD          : {f['nopasswd']}")
            if f["has_gtfobins_hint"]:
                lines.append("  - GTFOBins guidance available in this module for this binary.")
            else:
                lines.append("  - No specific GTFOBins hint in this module; consider manual GTFOBins lookup.")
            lines.append("")
        lines.append("")

    if low:
        lines.append("### Low-confidence or unverified surfaces")
        lines.append("")
        lines.append(
            "These entries either point to binaries that are not clearly available, "
            "have no known GTFOBins pattern in this module, or look less promising for direct escalation."
        )
        lines.append("")
        for f in low:
            bi = f["binary_info"]
            lines.append(f"- `{f['raw_rule']}`")
            lines.append(f"  - Binary            : {f['binary']}")
            lines.append(f"  - Resolved path     : {bi.get('resolved_path')}")
            lines.append(f"  - Binary available  : {bi.get('exists_in_path')}")
            lines.append(f"  - Executes cleanly  : {bi.get('version_check_ok')}")
            lines.append(f"  - NOPASSWD          : {f['nopasswd']}")
            lines.append("")
        lines.append("")

    report.add_section("Sudo Analysis", lines)
