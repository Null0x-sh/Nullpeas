# nullpeas/core/guidance.py

from typing import Dict, Any, List, Optional, Set, Literal, TypedDict


SeverityBand = Literal["Critical", "High", "Medium", "Low", "Info"]


class FindingContext(TypedDict, total=False):
    """
    Normalised context that any module (sudo, cron, docker, etc.) can pass
    to the guidance engine.

    Required fields differ a bit per surface, but this gives us a stable
    shape and keeps modules from hardcoding prose.
    """
    surface: str                      # e.g. "sudo", "cron", "docker"
    rule: str                         # raw rule or main descriptor
    binary: Optional[str]
    capabilities: Set[str]            # "shell_spawn", "file_write", ...
    risk_categories: Set[str]         # "sudo_editor_nopasswd", ...
    severity_band: SeverityBand
    severity_score: float
    nopasswd: bool
    gtfobins_url: Optional[str]
    metadata: Dict[str, Any]          # module-specific extras


class GuidanceResult(TypedDict, total=False):
    """
    Render-agnostic guidance: modules can stuff this into their reports
    however they like, but they don't own the text.
    """
    navigation: List[str]
    operator_research: List[str]
    offensive_steps: List[str]
    defensive_actions: List[str]
    impact: List[str]
    references: List[str]


# Global policy for what to show by severity band.
REPORT_POLICY: Dict[str, Set[SeverityBand]] = {
    "show_offensive_for": {"Critical", "High", "Medium"},
    "show_defensive_for": {"Critical", "High", "Medium"},
    "show_operator_research_for": {"Critical", "High"},
    "show_impact_for": {"Critical", "High", "Medium"},
    "show_navigation_for": {"Critical", "High", "Medium"},
}


def build_guidance(context: FindingContext) -> GuidanceResult:
    """
    Entry point used by modules.

    - Looks at surface (sudo/cron/docker/etc.).
    - Delegates to a surface-specific builder.
    - Applies REPORT_POLICY so modules don't decide what to print.
    """
    surface = context.get("surface", "generic")

    if surface == "sudo":
        raw = _build_sudo_guidance(context)
    else:
        # Fallback: no guidance for unknown surfaces yet.
        raw = GuidanceResult(
            navigation=[],
            operator_research=[],
            offensive_steps=[],
            defensive_actions=[],
            impact=[],
            references=[],
        )

    # Apply reporting policy (drop blocks we don't want for this severity).
    band: SeverityBand = context.get("severity_band", "Low")  # type: ignore[assignment]
    filtered: GuidanceResult = {}

    if band in REPORT_POLICY["show_navigation_for"]:
        if raw.get("navigation"):
            filtered["navigation"] = raw["navigation"]

    if band in REPORT_POLICY["show_operator_research_for"]:
        if raw.get("operator_research"):
            filtered["operator_research"] = raw["operator_research"]

    if band in REPORT_POLICY["show_offensive_for"]:
        if raw.get("offensive_steps"):
            filtered["offensive_steps"] = raw["offensive_steps"]

    if band in REPORT_POLICY["show_defensive_for"]:
        if raw.get("defensive_actions"):
            filtered["defensive_actions"] = raw["defensive_actions"]

    if band in REPORT_POLICY["show_impact_for"]:
        if raw.get("impact"):
            filtered["impact"] = raw["impact"]

    if raw.get("references"):
        filtered["references"] = raw["references"]

    return filtered


# ---------------------------------------------------------------------------
# SUDO-SPECIFIC GUIDANCE
# ---------------------------------------------------------------------------

def _build_sudo_guidance(context: FindingContext) -> GuidanceResult:
    """
    Sudo-specific guidance builder.

    Uses:
      - capabilities
      - risk_categories
      - nopasswd
      - gtfobins_url
    and turns them into human-readable guidance.
    """
    caps: Set[str] = context.get("capabilities", set()) or set()
    risk_categories: Set[str] = context.get("risk_categories", set()) or set()
    binary: Optional[str] = context.get("binary")
    nopasswd: bool = context.get("nopasswd", False)
    gtfobins_url: Optional[str] = context.get("gtfobins_url")
    metadata: Dict[str, Any] = context.get("metadata", {}) or {}

    # For global NOPASSWD: ALL we usually want custom semantics handled
    # in the module, not here. If you pass a special risk category we
    # just don't try to be clever.
    if "sudo_global_nopasswd_all" in risk_categories:
        return GuidanceResult(
            # No nav: there is no single binary.
            navigation=[],
            operator_research=[
                "Enumerate which existing tools on this host can edit privileged configuration, manage services, or provide interactive shells under sudo.",
                "For each such tool, check whether it has publicly documented sudo-abuse patterns (for example via GTFOBins or vendor documentation).",
                "Map those patterns to high value targets on this host: sensitive data locations, service definitions, scheduled tasks, and identity/access control paths.",
            ],
            offensive_steps=[
                "Confirm that sudo is usable from the current user and that this broad rule applies.",
                "Use sudo to invoke a preferred shell or administrative tool with elevated privileges.",
                "From the elevated context, perform further actions such as reading or modifying sensitive files, changing configuration, or establishing persistence, subject to engagement scope.",
            ],
            defensive_actions=[
                "Identify why a NOPASSWD: ALL style rule exists and whether it is still required.",
                "Replace NOPASSWD: ALL with tightly scoped command specific rules where possible.",
                "Where feasible, remove NOPASSWD so that privileged actions require authentication.",
                "Introduce monitoring and alerting for broad sudo usage and regularly review sudoers configuration.",
            ],
            impact=[
                "Effective full root level capabilities from the affected account.",
                "High potential for system wide compromise and stealthy persistence if left unaddressed.",
            ],
            references=[],
        )

    # Standard sudo rule (specific binary / class)
    navigation = _sudo_navigation_from_capabilities(caps)
    operator_research = _sudo_operator_research(
        binary=binary,
        risk_categories=risk_categories,
        gtfobins_url=gtfobins_url,
    )
    offensive_steps = _sudo_offensive_from_nopasswd(nopasswd)
    defensive_actions = _sudo_defensive_from_risk(
        risk_categories=risk_categories,
        nopasswd=nopasswd,
        metadata=metadata,
    )
    impact = _sudo_impact_from_capabilities(caps)
    references: List[str] = []
    if gtfobins_url and binary:
        references.append(
            f"GTFOBins entry for {binary}: {gtfobins_url} (documented sudo-abuse patterns)."
        )

    return GuidanceResult(
        navigation=navigation,
        operator_research=operator_research,
        offensive_steps=offensive_steps,
        defensive_actions=defensive_actions,
        impact=impact,
        references=references,
    )


def _sudo_navigation_from_capabilities(caps: Set[str]) -> List[str]:
    lines: List[str] = []

    if "editor_escape" in caps:
        lines.extend(
            [
                "This editor is running with elevated privileges.",
                "Look for features that run external commands, open subshell like contexts, or load helpers.",
                "Explore scripting, macros, or plugin systems that may execute system actions.",
            ]
        )

    if "pager_escape" in caps:
        lines.extend(
            [
                "This pager or viewer is running with elevated privileges.",
                "Explore interactive features that go beyond simple scrolling.",
                "Look for ways to launch helpers, open editors, or otherwise leave the standard viewing mode.",
            ]
        )

    if "interpreter" in caps:
        lines.extend(
            [
                "This is a full language runtime running with elevated privileges.",
                "Look for APIs that execute operating system commands or manipulate files.",
                "Any script executed here inherits the privileges granted by sudo.",
            ]
        )

    if "exec_hook" in caps:
        lines.extend(
            [
                "This tool can execute other programs as part of its normal usage.",
                "Execution hooks or callbacks will run with the privileges granted by sudo.",
                "Abuse potential often lives in parameters that tell the tool what to run per file or per match.",
            ]
        )

    if "shell_spawn" in caps:
        lines.extend(
            [
                "This binary can act similar to a shell or can lead to a shell-like execution context.",
                "Once a privileged shell-like environment is reached, typical post escalation actions are possible.",
            ]
        )

    if "file_write" in caps:
        lines.extend(
            [
                "This tool can write or overwrite files with elevated privileges.",
                "Writing to configuration files, service definitions, or key material can lead to persistence or further compromise.",
            ]
        )

    if "file_read" in caps:
        lines.extend(
            [
                "This tool can read files that are normally restricted to privileged users.",
                "Sensitive configuration, key material, or credentials may be accessible from this context.",
            ]
        )

    if "platform_control" in caps:
        lines.extend(
            [
                "This tool controls core services or platform level resources.",
                "Operations here may allow starting privileged services, containers, or other components that lead to host compromise.",
            ]
        )

    # De-duplicate, preserve order.
    se
