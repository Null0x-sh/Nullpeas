from typing import Dict, Any, List, Optional, Set, Tuple
import re

from nullpeas.core.exec import run_command
from nullpeas.core.report import Report
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
    "tee": [
        "Can write to arbitrary files; when run as root it can overwrite sensitive files.",
    ],
    "cat": [
        "Can read sensitive files; may leak credentials or secrets when run as root.",
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
    "tee": "https://gtfobins.github.io/gtfobins/tee/",
    "cat": "https://gtfobins.github.io/gtfobins/cat/",
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
    "tee": {"file_write"},
    "cat": {"file_read"},

    "bash": {"shell_spawn"},
    "sh": {"shell_spawn"},

    "docker": {"platform_control"},
    "systemctl": {"platform_control"},
}


def _command_basename(cmd: str) -> str:
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
    """
    rules: List[Dict[str, Any]] = []

    for line in raw_stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith("("):
            continue

        nopasswd = "NOPASSWD:" in stripped or "NOPASSWD" in stripped
        denied = "DENIED" in stripped.upper()

        runas_spec: Optional[str] = None
        m = re.match(r"^\(([^)]+)\)\s*(.*)$", stripped)
        rest = stripped
        if m:
            runas_spec = m.group(1).strip()
            rest = m.group(2).strip()

        cmd_part = rest
        if ":" in rest:
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
    Check if a binary is available in PATH and if a simple version/help
    call succeeds, using the structured run_command API.
    """
    result: Dict[str, Any] = {
        "name": name,
        "exists_in_path": False,
        "resolved_path": None,
        "version_check_ok": False,
    }

    if not name:
        return result

    rc = run_command(f"command -v {name}", shell=True)
    resolved = (rc.get("stdout") or "").strip()

    if not resolved:
        rc = run_command(f"which {name}", shell=True)
        resolved = (rc.get("stdout") or "").strip()

    if not resolved:
        return result

    result["exists_in_path"] = True
    result["resolved_path"] = resolved

    for arg in ["--version", "-V", "-h", "--help"]:
        probe = run_command(f"{resolved} {arg}", shell=True)
        if probe.get("ok") or probe.get("return_code") == 0:
            result["version_check_ok"] = True
            break

    return result


def _risk_categories_for_rule(
    nopasswd: bool,
    base: str,
    is_all_rule: bool,
) -> Set[str]:
    cats: Set[str] = set()

    if is_all_rule:
        if nopasswd:
            cats.add("sudo_global_nopasswd_all")
        else:
            cats.add("sudo_global_all")
        return cats

    if not base:
        return cats

    if base in {"vim", "vi", "nano", "ed"}:
        cats.add("sudo_editor_nopasswd" if nopasswd else "sudo_editor_rule")

    if base in {"python", "python3", "perl", "ruby", "lua"}:
        cats.add("sudo_interpreter_nopasswd" if nopasswd else "sudo_interpreter_rule")

    if base in {"systemctl"}:
        cats.add("sudo_service_control")
    if base in {"docker"}:
        cats.add("sudo_platform_control")

    if base in {"find", "awk", "rsync", "tar"}:
        cats.add("sudo_exec_hook_tool")

    if base in {"tee", "tar", "rsync"}:
        cats.add("sudo_file_write_surface")
    if base in {"cat"}:
        cats.add("sudo_file_read_surface")

    return cats


def _analyze_arguments(command: str, base: str) -> Set[str]:
    risks: Set[str] = set()
    if not command:
        return risks

    if "*" in command or "?" in command:
        risks.add("wildcard_glob")

    if ">>" in command or " > " in command:
        risks.add("redirect_write")

    sensitive_tokens = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/root/",
        "/home/",
        ".ssh/",
        "authorized_keys",
        "/var/log/",
    ]
    if any(tok in command for tok in sensitive_tokens):
        risks.add("sensitive_target")

    dynamic_tokens = ["$HOME", "$USER", "%h", "%u", "~", "$("]
    if any(tok in command for tok in dynamic_tokens):
        risks.add("dynamic_path")

    if base in {"vim", "vi", "nano", "ed", "tee", "tar", "rsync"} and "sensitive_target" in risks:
        risks.add("sensitive_file_edit_surface")

    return risks


def _severity_for_rule(
    nopasswd: bool,
    binary_info: Dict[str, Any],
    has_gtfobins_hint: bool,
    capabilities: Set[str],
    is_all_rule: bool,
    risk_categories: Set[str],
    arg_risks: Set[str],
) -> Tuple[float, str]:
    if is_all_rule and nopasswd:
        return 10.0, "Critical"

    exists = binary_info.get("exists_in_path", False)

    auth_factor = 1.0 if nopasswd else 0.4
    scope_factor = 0.8 if is_all_rule else 0.5

    class_factor = 0.0
    if {"shell_spawn", "interpreter", "platform_control"} & capabilities:
        class_factor = 1.0
    elif capabilities:
        class_factor = 0.6
    elif has_gtfobins_hint:
        class_factor = 0.5

    arg_factor = 0.0
    if "sensitive_file_edit_surface" in arg_risks:
        arg_factor = 0.3
    elif "sensitive_target" in arg_risks:
        arg_factor = 0.2
    elif "wildcard_glob" in arg_risks:
        arg_factor = 0.1

    existence_factor = 1.0 if exists else 0.6

    cat_boost = 0.0
    if "sudo_editor_nopasswd" in risk_categories or "sudo_interpreter_nopasswd" in risk_categories:
        cat_boost += 0.2
    if "sudo_platform_control" in risk_categories:
        cat_boost += 0.1

    severity_raw = (
        0.22 * auth_factor
        + 0.18 * scope_factor
        + 0.35 * class_factor
        + 0.10 * existence_factor
        + 0.10 * arg_factor
        + cat_boost
    )
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
    Lean chain objects: just enough for the report to render a small
    "Sudo Attack Chains" section without any guidance engine.
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

        chains.append(
            {
                "title": _title_for_sudo_chain(binary, risk_categories),
                "rule": rule,
                "binary": binary,
                "severity_band": severity_band,
                "severity_score": f["severity_score"],
                "capabilities": caps,
            }
        )

    return chains


# ========================= Offensive Primitive Mapping =========================

def _offensive_classification_from_band(severity_band: str) -> str:
    if severity_band == "Critical":
        return "catastrophic"
    if severity_band == "High":
        return "severe"
    if severity_band == "Medium":
        return "useful"
    return "niche"


def _primitive_type_for_finding(f: Dict[str, Any]) -> Optional[str]:
    binary = f["binary"]
    caps: Set[str] = f.get("capabilities", set()) or set()
    nopasswd = f["nopasswd"]
    is_all_rule = f["is_all_rule"]
    runas_spec = (f.get("runas_spec") or "").lower() if f.get("runas_spec") else ""
    run_as = "root" if ("root" in runas_spec or "all" in runas_spec or not runas_spec) else runas_spec
    arg_risks: Set[str] = f.get("arg_risks", set()) or set()

    if is_all_rule and nopasswd:
        return "root_shell_primitive"

    if nopasswd and "platform_control" in caps and run_as == "root" and binary == "docker":
        return "docker_host_takeover"

    if "shell_spawn" in caps or "interpreter" in caps:
        if run_as == "root":
            if nopasswd:
                return "root_shell_primitive"
            return "arbitrary_command_execution"
        else:
            return "arbitrary_command_execution"

    if "file_write" in caps:
        if "sensitive_file_edit_surface" in arg_risks or "sensitive_target" in arg_risks:
            return "arbitrary_file_write_primitive"
        return "file_write_surface"

    if "exec_hook" in caps:
        return "arbitrary_command_execution"

    if "platform_control" in caps:
        return "platform_control_primitive"

    return "sudo_exec_surface"


def _primitive_from_finding(state: Dict[str, Any], f: Dict[str, Any]) -> Optional[Primitive]:
    user = state.get("user", {}) or {}

    severity_band = f["severity_band"]
    severity_score = f["severity_score"]
    binary = f["binary"]
    caps: Set[str] = f.get("capabilities", set()) or set()
    risk_categories: Set[str] = f.get("risk_categories", set()) or set()
    nopasswd = f["nopasswd"]
    is_all_rule = f["is_all_rule"]
    arg_risks: Set[str] = f.get("arg_risks", set()) or set()
    runas_spec_raw = f.get("runas_spec") or ""
    runas_spec = runas_spec_raw.lower()
    run_as = "root" if ("root" in runas_spec or "all" in runas_spec or not runas_spec) else runas_spec
    raw_rule = f["raw_rule"]
    confidence_score = f["confidence_score"]
    confidence_band = f["confidence_band"]
    gtfobins_url = f.get("gtfobins_url")

    primitive_type = _primitive_type_for_finding(f)
    if not primitive_type:
        return None

    origin_user = user.get("name") or "current_user"

    if primitive_type in {"root_shell_primitive", "docker_host_takeover"} and nopasswd:
        exploitability = "trivial"
    elif primitive_type in {"root_shell_primitive", "arbitrary_file_write_primitive"}:
        exploitability = "moderate"
    elif primitive_type in {"arbitrary_command_execution", "platform_control_primitive"}:
        exploitability = "moderate"
    else:
        exploitability = "advanced" if severity_band in {"Medium", "High"} else "theoretical"

    if primitive_type in {"root_shell_primitive", "docker_host_takeover"}:
        stability = "safe"
    elif primitive_type in {"arbitrary_command_execution", "arbitrary_file_write_primitive"}:
        stability = "moderate"
    else:
        stability = "moderate"

    noise = "low"

    classification = _offensive_classification_from_band(severity_band)

    confidence = PrimitiveConfidence(
        score=confidence_score,
        reason=f"Derived from sudo rule: {raw_rule} (band: {confidence_band})",
    )

    offensive_value = OffensiveValue(
        classification=classification,
        why=(
            f"Sudo rule '{raw_rule}' grants '{primitive_type}' capability when abused. "
            f"Severity {severity_score}/10 ({severity_band}), "
            f"confidence {confidence_score}/10 ({confidence_band})."
        ),
    )

    context: Dict[str, Any] = {
        "rule": raw_rule,
        "binary": binary,
        "run_as": run_as,
        "nopasswd": nopasswd,
        "is_all_rule": is_all_rule,
        "capabilities": sorted(caps),
        "risk_categories": sorted(risk_categories),
        "arg_risks": sorted(arg_risks),
        "severity_band": severity_band,
        "severity_score": severity_score,
        "confidence_band": confidence_band,
        "confidence_score": confidence_score,
    }

    conditions: Dict[str, Any] = {
        "requires_password": not nopasswd,
        "requires_root_target": run_as == "root",
    }

    cross_refs: Dict[str, List[str]] = {
        "gtfobins": [gtfobins_url] if gtfobins_url else [],
        "cves": [],
        "documentation": [],
    }

    defensive_impact: Dict[str, Any] = {
        "misconfiguration_summary": (
            "Sudo configuration exposes a high-value escalation surface. "
            "If abused, this could undermine local privilege boundaries."
        )
    }

    primitive = Primitive(
        id=new_primitive_id("sudo", primitive_type),
        surface="sudo",
        type=primitive_type,
        run_as=run_as,
        origin_user=origin_user,
        exploitability=exploitability,  # type: ignore[arg-type]
        stability=stability,            # type: ignore[arg-type]
        noise=noise,                    # type: ignore[arg-type]
        confidence=confidence,
        offensive_value=offensive_value,
        context=context,
        conditions=conditions,
        integration_flags={"root_goal_candidate": primitive_type in {"root_shell_primitive", "docker_host_takeover"}},
        cross_refs=cross_refs,
        defensive_impact=defensive_impact,
        module_source="sudo_enum",
        probe_source="sudo",
    )

    return primitive


# ========================= MODULE ENTRYPOINT =========================

@register_module(
    key="sudo_enum",
    description="Analyse sudo -l output, capabilities, and potential attack chains",
    required_triggers=["sudo_privesc_surface"],
)
def run(state: dict, report: Report):
    sudo_state = state.get("sudo", {}) or {}
    raw_stdout = sudo_state.get("raw_stdout")

    if not raw_stdout:
        report.add_section(
            "Sudo Analysis",
            [
                "No sudo -l output was captured by the probes.",
                "Either sudo is not present, not configured, or the probe could not run.",
            ],
        )
        return

    parsed_rules = _parse_sudo_rules(raw_stdout)

    if not parsed_rules:
        report.add_section(
            "Sudo Analysis",
            [
                "Sudo appears to be present, but no usable rule entries were parsed from sudo -l output.",
                "This may indicate a minimal configuration or an environment where sudo does not grant additional privileges.",
            ],
        )
        return

    findings: List[Dict[str, Any]] = []

    for r in parsed_rules:
        if r.get("denied"):
            # Skip DENIED entries; they don't represent usable surfaces.
            continue

        raw_rule = r["raw"]
        nopasswd = r["nopasswd"]
        is_all_rule = r["is_all_rule"]
        runas_spec = r.get("runas_spec")
        command = r.get("command", "") or ""
        base = _command_basename(command)

        if base:
            binary_info = _verify_binary_available(base)
        else:
            binary_info = {
                "name": base,
                "exists_in_path": False,
                "resolved_path": None,
                "version_check_ok": False,
            }

        capabilities = GTF0BINS_CAPABILITIES.get(base, set())
        risk_categories = _risk_categories_for_rule(nopasswd, base, is_all_rule)
        arg_risks = _analyze_arguments(command, base)
        gtfobins_url = GTF0BINS_URLS.get(base)
        has_gtfobins_hint = bool(gtfobins_url or GTF0BINS_SUDO_HINTS.get(base))

        severity_score, severity_band = _severity_for_rule(
            nopasswd=nopasswd,
            binary_info=binary_info,
            has_gtfobins_hint=has_gtfobins_hint,
            capabilities=capabilities,
            is_all_rule=is_all_rule,
            risk_categories=risk_categories,
            arg_risks=arg_risks,
        )

        confidence_score, confidence_band = _confidence_for_rule(
            binary_info=binary_info,
            is_all_rule=is_all_rule,
        )

        findings.append(
            {
                "raw_rule": raw_rule,
                "nopasswd": nopasswd,
                "is_all_rule": is_all_rule,
                "runas_spec": runas_spec,
                "command": command,
                "binary": base or None,
                "binary_info": binary_info,
                "capabilities": capabilities,
                "risk_categories": risk_categories,
                "arg_risks": arg_risks,
                "gtfobins_url": gtfobins_url,
                "has_gtfobins_hint": has_gtfobins_hint,
                "severity_score": severity_score,
                "severity_band": severity_band,
                "confidence_score": confidence_score,
                "confidence_band": confidence_band,
            }
        )

    if not findings:
        report.add_section(
            "Sudo Analysis",
            [
                "Sudo -l output did not yield any actionable rules for this user.",
                "No escalation-prone sudo surfaces were identified by this module.",
            ],
        )
        return

    # ---------- Report: Sudo Analysis ----------
    total_rules = len(findings)
    nopasswd_rules = [f for f in findings if f["nopasswd"]]
    global_nopasswd_all_present = any(
        "sudo_global_nopasswd_all" in f["risk_categories"] for f in findings
    )

    lines: List[str] = []
    lines.append("This section analyses sudo configuration as reported by sudo -l for the current user.")
    lines.append("It focuses on escalation-prone rules, capability classes, and how realistic they are to abuse in practice.")
    lines.append("")
    lines.append("### Sudo rule summary")
    lines.append(f"- Total parsed rules             : {total_rules}")
    lines.append(f"- Rules with NOPASSWD            : {len(nopasswd_rules)}")
    lines.append(f"- Global NOPASSWD ALL present    : {global_nopasswd_all_present}")
    lines.append("")

    high_impact = [
        f for f in findings if f["severity_band"] in {"Critical", "High"}
    ]

    if high_impact:
        lines.append("### High impact sudo surfaces")
        for f in high_impact:
            band = f["severity_band"]
            score = f["severity_score"]
            rule = f["raw_rule"]
            binary = f["binary"] or ("ALL" if f["is_all_rule"] else "unknown")
            lines.append(f"- [{band} {score}/10] Rule: {rule} (binary: {binary})")
        lines.append("")
    else:
        lines.append("### High impact sudo surfaces")
        lines.append("- None classified as High or Critical by the current scoring model.")
        lines.append("")

    report.add_section("Sudo Analysis", lines)

    # ---------- Report: Sudo Attack Chains (short, local only) ----------
    chains = _build_attack_chains(findings)
    if chains:
        chain_lines: List[str] = []
        chain_lines.append(
            "This section describes high level attack chains based on sudo configuration and allowed commands."
        )
        chain_lines.append(
            "Nullpeas does not execute sudo-based payloads or alter /etc/sudoers. It explains how operators or attackers might reason about these surfaces, and how defenders can respond."
        )
        chain_lines.append("")

        for idx, chain in enumerate(chains, start=1):
            chain_lines.append(f"### Chain {idx}: {chain['title']}")
            chain_lines.append("")
            chain_lines.append("Rule:")
            chain_lines.append(f"- {chain['rule']}")
            chain_lines.append("")
            chain_lines.append("Severity:")
            chain_lines.append(f"- {chain['severity_band']} ({chain['severity_score']}/10)")
            chain_lines.append("")
            caps = chain.get("capabilities") or set()
            if caps:
                chain_lines.append("Capabilities:")
                chain_lines.append(f"- {', '.join(sorted(caps))}")
                chain_lines.append("")

        report.add_section("Sudo Attack Chains", chain_lines)

    # ---------- Offensive primitives for chaining engine ----------
    for f in findings:
        primitive = _primitive_from_finding(state, f)
        if primitive:
            state.setdefault("offensive_primitives", []).append(primitive)
