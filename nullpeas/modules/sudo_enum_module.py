from typing import Dict, Any, List, Optional, Set

from nullpeas.core.exec import run_command
from nullpeas.core.report import Report
from nullpeas.modules import register_module


# Simple hints that explain why certain binaries are interesting under sudo.
GTF0BINS_SUDO_HINTS: Dict[str, List[str]] = {
    "vim": [
        "Interactive editor that can run external commands and open subshell like contexts.",
        "Can read and write files with the privileges granted by sudo."
    ],
    "less": [
        "Interactive pager that can integrate with helpers or external tools.",
        "Advanced usage can lead to execution of external programs with elevated privileges."
    ],
    "find": [
        "File finder that can execute other programs as part of its normal operation.",
        "Execution hooks can be abused when running under sudo."
    ],
    "python": [
        "Full interpreter that can execute operating system commands and manipulate files.",
        "Running the interpreter under sudo grants a powerful privileged environment."
    ],
    "python3": [
        "Full interpreter that can execute operating system commands and manipulate files.",
        "Running the interpreter under sudo grants a powerful privileged environment."
    ],
    "tar": [
        "Archive tool that can read and write files, sometimes with execution hooks.",
        "Can be abused to overwrite or create privileged files."
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


# Navigation guidance is high level text that helps operators know where inside a tool
# they should be looking, without supplying exploit payloads.
NAVIGATION_GUIDANCE: Dict[str, List[str]] = {
    "editor_escape": [
        "This is an editor running with elevated privileges.",
        "Look for features that run external commands, open subshell like contexts, or load helpers.",
        "Explore scripting, macros, or plugin systems that may execute system actions."
    ],
    "pager_escape": [
        "This is a pager or viewer running with elevated privileges.",
        "Explore interactive features that go beyond simple scrolling.",
        "Look for ways to launch helpers, open editors, or otherwise leave the standard viewing mode."
    ],
    "interpreter": [
        "This is a full language runtime running with elevated privileges.",
        "Look for APIs that execute operating system commands or manipulate files.",
        "Any script executed here inherits the privileges granted by sudo."
    ],
    "exec_hook": [
        "This tool can execute other programs as part of its normal usage.",
        "Execution hooks or callbacks will run with the privileges granted by sudo.",
        "Abuse potential often lives in parameters that tell the tool what to run per file or per match."
    ],
    "shell_spawn": [
        "This binary can act very similar to a shell or can lead to a shell like execution context.",
        "Once a privileged shell like environment is reached, typical post escalation actions are possible."
    ],
    "file_write": [
        "This tool can write or overwrite files with elevated privileges.",
        "Writing to configuration files, service definitions, or key material can lead to persistence or further compromise."
    ],
    "file_read": [
        "This tool can read files that are normally restricted to privileged users.",
        "Sensitive configuration, key material, or credentials may be accessible from this context."
    ],
    "platform_control": [
        "This tool controls core services or platform level resources.",
        "Operations here may allow starting privileged services, containers, or other components that lead to host compromise."
    ],
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
      - whether the rule looks like a denial or ALL rule

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

        # Basic fields
        nopasswd = "NOPASSWD:" in stripped or "NOPASSWD" in stripped
        denied = "DENIED" in stripped.upper()

        # Extract the command portion after the last colon if present.
        cmd_part = stripped
        if ":" in stripped:
            cmd_part = stripped.split(":", 1)[1].strip()

        # Some rules may end up as just "ALL"
        command = cmd_part if cmd_part else ""

        rules.append(
            {
                "raw": stripped,
                "nopasswd": nopasswd,
                "denied": denied,
                "command": command,
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
        result["exists_in_path"] = True
        result["resolved_path"] = resolved.strip()

        # Try a harmless version/help probe.
        for arg in ["--version", "-V", "-h", "--help"]:
            code, _ = run_command(f"{resolved} {arg}", get_exit_code=True)
            if code == 0:
                result["version_check_ok"] = True
                break

    return result


def _severity_for_rule(
    nopasswd: bool,
    binary_info: Dict[str, Any],
    has_gtfobins_hint: bool,
    capabilities: Set[str],
    is_all_rule: bool,
) -> str:
    """
    Rough severity scoring.

    This is not meant to be perfect, just sensible:
      - NOPASSWD: ALL -> critical
      - NOPASSWD + shell spawn / interpreter / platform control -> high
      - NOPASSWD + other interesting caps or GTFO hint -> medium
      - everything else -> low
    """
    if is_all_rule and nopasswd:
        return "critical"

    exists = binary_info.get("exists_in_path", False)

    if nopasswd and exists:
        if "shell_spawn" in capabilities or "interpreter" in capabilities or "platform_control" in capabilities:
            return "high"
        if capabilities or has_gtfobins_hint:
            return "medium"

    if exists and (capabilities or has_gtfobins_hint):
        return "medium"

    return "low"


def _build_navigation_guidance(capabilities: Set[str]) -> List[str]:
    lines: List[str] = []
    seen: Set[str] = set()

    for cap in sorted(capabilities):
        guidance_lines = NAVIGATION_GUIDANCE.get(cap) or []
        for line in guidance_lines:
            if line not in seen:
                seen.add(line)
                lines.append(line)

    return lines


def _build_attack_chains(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Build high level attack chain descriptions per relevant sudo finding.

    Chains describe how an attacker could move from current user to a more privileged
    context using the rule, and how a defender could break that chain. They do not
    contain exploit payloads or one liners.
    """
    chains: List[Dict[str, Any]] = []

    for f in findings:
        severity = f["severity"]
        if severity not in {"critical", "high", "medium"}:
            continue

        rule = f["raw_rule"]
        binary = f["binary"]
        caps = f.get("capabilities", set()) or set()
        bin_info = f["binary_info"]
        nopasswd = f["nopasswd"]

        # Special case for NOPASSWD: ALL style rules.
        if binary is None and f.get("is_all_rule"):
            chains.append(
                {
                    "title": "sudo -> full passwordless root access",
                    "rule": rule,
                    "binary": None,
                    "severity": severity,
                    "capabilities": {"shell_spawn", "file_read", "file_write", "platform_control"},
                    "offensive_steps": [
                        "Confirm that sudo is usable from the current user and that this rule applies.",
                        "Use sudo to invoke a preferred shell or administrative tool with elevated privileges.",
                        "From the elevated context, perform further actions such as reading or modifying sensitive files, "
                        "changing configuration, or establishing persistence, subject to engagement scope."
                    ],
                    "defensive_actions": [
                        "Identify why a NOPASSWD: ALL style rule exists and whether it is still required.",
                        "Replace NOPASSWD: ALL with tightly scoped command specific rules where possible.",
                        "Where feasible, remove NOPASSWD so that privileged actions require authentication.",
                        "Introduce monitoring and alerting for broad sudo usage and regularly review sudoers configuration."
                    ],
                    "impact": [
                        "Effective full root level capabilities from the affected account.",
                        "High potential for system wide compromise and stealthy persistence if left unaddressed."
                    ],
                }
            )
            continue

        if not binary:
            continue

        title = f"sudo -> {binary} -> elevated actions"

        prereq_binary_desc = (
            "Binary is present in PATH and responds to basic version or help probes."
            if bin_info.get("exists_in_path") and bin_info.get("version_check_ok")
            else "Binary appears to be present but may require manual validation on this host."
        )

        offensive_steps: List[str] = []

        # Basic offensive chain structure.
        offensive_steps.append(
            "From the compromised user, confirm that sudo is available and that this rule applies."
        )

        if nopasswd:
            offensive_steps.append(
                "Use sudo to run this allowed binary without needing a password."
            )
        else:
            offensive_steps.append(
                "Use sudo to run this allowed binary, providing credentials if engagement rules allow."
            )

        offensive_steps.append(
            "Within the elevated execution context of this binary, explore features that align with its capabilities "
            "to achieve privileged goals. For example, this may involve running system commands, reading sensitive files, "
            "or writing to configuration or service files, depending on the binary."
        )

        offensive_steps.append(
            "From that privileged context, perform post escalation actions such as data access, configuration inspection, "
            "or further lateral movement, within the bounds of the engagement."
        )

        defensive_actions: List[str] = [
            "Review why this binary is allowed under sudo for this user or group.",
            "If only a narrow operation is required, replace general purpose tools with tightly scoped helpers.",
        ]

        if nopasswd:
            defensive_actions.append(
                "Remove NOPASSWD where possible so that privileged actions require explicit authentication."
            )

        defensive_actions.append(
            "Log and monitor sudo usage of powerful interactive tools, interpreters, or platform control binaries."
        )

        impact: List[str] = []
        if "shell_spawn" in caps or "interpreter" in caps:
            impact.append(
                "Likely ability to obtain a shell like or fully programmable privileged execution context."
            )
        if "file_read" in caps:
            impact.append(
                "Potential to read files normally restricted to higher privileged users."
            )
        if "file_write" in caps:
            impact.append(
                "Potential to modify configuration, service, or other important files with elevated privileges."
            )
        if "platform_control" in caps:
            impact.append(
                "Ability to control services, containers, or platform components that may lead to host compromise."
            )
        if not impact:
            impact.append(
                "Meaningful elevated operations may be possible depending on how this binary is used in the environment."
            )

        chains.append(
            {
                "title": title,
                "rule": rule,
                "binary": binary,
                "severity": severity,
                "capabilities": caps,
                "offensive_steps": offensive_steps,
                "defensive_actions": defensive_actions,
                "impact": impact,
            }
        )

    return chains


@register_module(
    key="sudo_enum",
    description="Analyse sudo -l output, capabilities, and potential attack chains",
    required_triggers=["sudo_privesc_surface"],
)
def run(state: dict, report: Report):
    """
    In depth sudo analysis module.

    - Uses existing sudo probe output (no extra sudo -l calls).
    - Parses rules for NOPASSWD and GTFOBins like candidates.
    - Assigns capability categories for known binaries.
    - Quietly verifies candidate binaries exist and can execute basic probes.
    - Builds high level attack chains with offensive and defensive viewpoints.
    - Writes human readable sections into the report.
    """
    sudo = state.get("sudo", {}) or {}
    raw_stdout = sudo.get("raw_stdout") or ""

    if not raw_stdout:
        report.add_section(
            "Sudo Analysis",
            [
                "No sudo output available in state. Either sudo is missing, denied, or the sudo probe did not run.",
            ],
        )
        return

    rules = _parse_sudo_rules(raw_stdout)

    if not rules:
        report.add_section(
            "Sudo Analysis",
            [
                "sudo -l output was available but no rules could be parsed.",
                "This may indicate a denial only response or an unusual sudo configuration.",
            ],
        )
        return

    findings: List[Dict[str, Any]] = []

    for r in rules:
        cmd = r.get("command", "") or ""
        raw_rule = r["raw"]
        nopasswd = r.get("nopasswd", False)

        # Identify ALL style rules where no specific binary is listed.
        is_all_rule = cmd.strip().upper() == "ALL" or cmd.strip().upper() == "ALL ALL"

        base = _command_basename(cmd) if not is_all_rule else ""
        gtfobins_hint = GTF0BINS_SUDO_HINTS.get(base)
        capabilities = GTF0BINS_CAPABILITIES.get(base, set()) if base else set()

        if base:
            bin_info = _verify_binary_available(base)
        else:
            bin_info = {
                "name": base,
                "exists_in_path": False,
                "resolved_path": None,
                "version_check_ok": False,
            }

        severity = _severity_for_rule(
            nopasswd=nopasswd,
            binary_info=bin_info,
            has_gtfobins_hint=(gtfobins_hint is not None),
            capabilities=capabilities,
            is_all_rule=is_all_rule,
        )

        findings.append(
            {
                "raw_rule": raw_rule,
                "nopasswd": nopasswd,
                "binary": base or None,
                "binary_info": bin_info,
                "has_gtfobins_hint": gtfobins_hint is not None,
                "gtfobins_hint_lines": gtfobins_hint or [],
                "capabilities": capabilities,
                "severity": severity,
                "is_all_rule": is_all_rule,
            }
        )

    # Build main analysis section.
    lines: List[str] = []

    lines.append("This section analyses the existing sudo -l output collected by Nullpeas.")
    lines.append("No additional sudo -l invocations were made by this module.")
    lines.append("It performed limited extra checks (command lookup and simple version/help probes) to confirm binaries exist and can run.")
    lines.append("")

    lines.append("### Parsed sudo rules")
    for f in findings:
        lines.append(f"- {f['raw_rule']}")
    lines.append("")

    def _group(sev: str) -> List[Dict[str, Any]]:
        return [f for f in findings if f["severity"] == sev]

    critical = _group("critical")
    high = _group("high")
    med = _group("medium")
    low = _group("low")

    if critical:
        lines.append("### Critical sudo surfaces")
        lines.append("")
        for f in critical:
            bi = f["binary_info"]
            lines.append(f"- `{f['raw_rule']}`")
            lines.append(f"  - Interpreted as a broad or highly privileged rule (for example NOPASSWD: ALL).")
            lines.append(f"  - Binary            : {f['binary']}")
            lines.append(f"  - Resolved path     : {bi.get('resolved_path')}")
            lines.append(f"  - Binary available  : {bi.get('exists_in_path')}")
            lines.append(f"  - NOPASSWD          : {f['nopasswd']}")
            lines.append("")
        lines.append("")

    if high:
        lines.append("### High confidence escalation surfaces")
        lines.append("")
        for f in high:
            bi = f["binary_info"]
            caps = f["capabilities"]
            lines.append(f"- `{f['raw_rule']}`")
            lines.append(f"  - Binary            : {f['binary']}")
            lines.append(f"  - Resolved path     : {bi.get('resolved_path')}")
            lines.append(f"  - Binary available  : {bi.get('exists_in_path')}")
            lines.append(f"  - Executes cleanly  : {bi.get('version_check_ok')}")
            lines.append(f"  - NOPASSWD          : {f['nopasswd']}")
            if caps:
                lines.append(f"  - Capabilities      : {', '.join(sorted(caps))}")
            if f["has_gtfobins_hint"]:
                lines.append("  - Known to have privilege escalation patterns documented publicly.")
            lines.append("")
        lines.append("")

    if med:
        lines.append("### Medium confidence surfaces")
        lines.append("")
        for f in med:
            bi = f["binary_info"]
            caps = f["capabilities"]
            lines.append(f"- `{f['raw_rule']}`")
            lines.append(f"  - Binary            : {f['binary']}")
            lines.append(f"  - Resolved path     : {bi.get('resolved_path')}")
            lines.append(f"  - Binary available  : {bi.get('exists_in_path')}")
            lines.append(f"  - Executes cleanly  : {bi.get('version_check_ok')}")
            lines.append(f"  - NOPASSWD          : {f['nopasswd']}")
            if caps:
                lines.append(f"  - Capabilities      : {', '.join(sorted(caps))}")
            lines.append("")
        lines.append("")

    if low:
        lines.append("### Low confidence or unverified surfaces")
        lines.append("")
        for f in low:
            bi = f["binary_info"]
            caps = f["capabilities"]
            lines.append(f"- `{f['raw_rule']}`")
            lines.append(f"  - Binary            : {f['binary']}")
            lines.append(f"  - Resolved path     : {bi.get('resolved_path')}")
            lines.append(f"  - Binary available  : {bi.get('exists_in_path')}")
            lines.append(f"  - Executes cleanly  : {bi.get('version_check_ok')}")
            lines.append(f"  - NOPASSWD          : {f['nopasswd']}")
            if caps:
                lines.append(f"  - Capabilities      : {', '.join(sorted(caps))}")
            lines.append("")
        lines.append("")

    report.add_section("Sudo Analysis", lines)

    # Build attack chains section.
    chains = _build_attack_chains(findings)
    if chains:
        chain_lines: List[str] = []
        chain_lines.append(
            "This section describes high level attack chains based on the sudo configuration."
        )
        chain_lines.append(
            "Nullpeas does not execute these chains. They describe what could be done by an operator "
            "or attacker, and how defenders can respond."
        )
        chain_lines.append("")

        for c in chains:
            caps = c.get("capabilities", set()) or set()
            binary = c.get("binary")

            chain_lines.append(f"### {c['title']}")
            chain_lines.append("")
            chain_lines.append("Rule:")
            chain_lines.append(f"- `{c['rule']}`")
            chain_lines.append("")
            chain_lines.append(f"Severity:")
            chain_lines.append(f"- {c['severity']}")
            chain_lines.append("")
            if binary:
                chain_lines.append("Binary:")
                chain_lines.append(f"- {binary}")
                chain_lines.append("")

            if caps:
                chain_lines.append("Capabilities:")
                chain_lines.append(f"- {', '.join(sorted(caps))}")
                chain_lines.append("")

            nav_guidance = _build_navigation_guidance(caps)
            if nav_guidance:
                chain_lines.append("Navigation guidance (for operators):")
                for line in nav_guidance:
                    chain_lines.append(f"- {line}")
                chain_lines.append("")

            chain_lines.append("High level offensive path (for red teams and threat modelling):")
            chain_lines.append("")
            for idx, step in enumerate(c["offensive_steps"], start=1):
                chain_lines.append(f"{idx}. {step}")
            chain_lines.append("")
            chain_lines.append(
                "Note: Nullpeas does not execute any of the above. These steps describe possible operator behaviour."
            )
            chain_lines.append("")

            chain_lines.append("Defensive remediation path (for blue teams):")
            chain_lines.append("")
            for idx, action in enumerate(c["defensive_actions"], start=1):
                chain_lines.append(f"{idx}. {action}")
            chain_lines.append("")

            chain_lines.append("Potential impact if left unresolved:")
            for imp in c["impact"]:
                chain_lines.append(f"- {imp}")
            chain_lines.append("")

            # References
            refs: List[str] = []
            if binary and binary in GTF0BINS_SUDO_HINTS:
                refs.append(f"GTFOBins entry for {binary}: https://gtfobins.github.io/gtfobins/{binary}/")

            if refs:
                chain_lines.append("References:")
                for ref in refs:
                    chain_lines.append(f"- {ref}")
                chain_lines.append("")

        report.add_section("Sudo Attack Chains", chain_lines)
