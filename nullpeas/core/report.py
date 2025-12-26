from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any, Optional, Iterable
import datetime
import json


class Report:
    """
    Nullpeas unified reporting engine.

    Responsibilities:
    - Accept traditional module sections (text reporting) for backwards compatibility.
    - Accept structured offensive primitives.
    - Accept structured attack chains from the chaining engine.
    - Render clean, operator-focused Markdown with Visual Maps (Mermaid).
    - Export structured JSON for tooling / automation.
    """

    def __init__(
        self,
        title: str = "Nullpeas Local Privilege Escalation Assessment",
        output_dir: str = "cache",
    ):
        self.title = title
        self.output_dir = Path(output_dir)

        # Human-readable document sections from modules (legacy).
        self.sections: List[Dict[str, Any]] = []

        # Structured intelligence.
        self.primitives: List[Dict[str, Any]] = []
        self.attack_chains: List[Dict[str, Any]] = []

    # ----------------------------------------------------------------------
    # Alternate constructor for state-driven usage
    # ----------------------------------------------------------------------

    @classmethod
    def from_state(
        cls,
        state: Dict[str, Any],
        title: str = "Nullpeas Local Privilege Escalation Assessment",
        output_dir: str = "cache",
    ) -> "Report":
        """
        Convenience constructor: ingest primitives and chains directly from state.
        """
        r = cls(title=title, output_dir=output_dir)

        for p in state.get("offensive_primitives", []) or []:
            r.add_primitive(p)

        for c in state.get("attack_chains", []) or []:
            r.add_attack_chain(c)

        return r

    # ----------------------------------------------------------------------
    # Public API – TEXT REPORTING (legacy module sections)
    # ----------------------------------------------------------------------

    def add_section(self, heading: str, body_lines: List[str]):
        self.sections.append(
            {
                "heading": heading,
                "body_lines": body_lines or [],
            }
        )

    def add_finding(
        self,
        heading: str,
        summary: str,
        details: Optional[List[str]] = None,
    ):
        lines = [summary]
        if details:
            lines.append("")
            lines.extend(details)
        self.add_section(heading, lines)

    # ----------------------------------------------------------------------
    # Public API – OFFENSIVE PRIMITIVES
    # ----------------------------------------------------------------------

    def add_primitive(self, primitive: Any):
        """
        Accepts a Primitive dataclass OR dict.
        """
        if hasattr(primitive, "__dict__"):
            primitive = primitive.__dict__
        self.primitives.append(primitive)

    def add_primitives(self, prims: Iterable[Any]):
        for p in prims:
            self.add_primitive(p)

    # ----------------------------------------------------------------------
    # Public API – ATTACK CHAINS
    # ----------------------------------------------------------------------

    def add_attack_chain(self, chain: Any):
        """
        Accepts an AttackChain dataclass OR dict.
        """
        if hasattr(chain, "__dict__"):
            chain = chain.__dict__
        self.attack_chains.append(chain)

    def add_attack_chains(self, chains: Iterable[Any]):
        for c in chains:
            self.add_attack_chain(c)

    # ----------------------------------------------------------------------
    # MARKDOWN RENDERING
    # ----------------------------------------------------------------------

    def _render_header(self) -> List[str]:
        ts = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"

        return [
            f"# {self.title}",
            "",
            f"_Generated: {ts}_",
            "",
            "---",
            "",
        ]

    def _render_sections(self) -> List[str]:
        """
        Legacy module sections.
        """
        if not self.sections:
            return []

        lines: List[str] = []
        for section in self.sections:
            lines.append(f"## {section['heading']}")
            lines.append("")
            lines.extend(section["body_lines"])
            lines.append("")
        return lines

    # ------------------------ Visualizer (Mermaid) -------------------------

    def _render_mermaid(self) -> List[str]:
        """
        Generates a visual graph of the attack chains using Mermaid.js syntax.
        Updated in v2.0 to support SUID and Trap/Hijack visualization.
        """
        if not self.attack_chains:
            return []

        lines = ["## Visual Attack Map", "", "```mermaid", "graph TD"]
        
        # === Style definitions ===
        # Standard Primitive (Blue)
        lines.append("    classDef primitive fill:#e1f5fe,stroke:#01579b,stroke-width:2px;")
        # Root Goal (Red)
        lines.append("    classDef rootGoal fill:#ffcdd2,stroke:#b71c1c,stroke-width:4px;")
        # File Writes (Yellow)
        lines.append("    classDef fileWrite fill:#fff9c4,stroke:#fbc02d,stroke-width:2px;")
        # Persistence (Green)
        lines.append("    classDef persistence fill:#e8f5e9,stroke:#1b5e20,stroke-width:2px;")
        # SUID Binaries (Purple) - NEW
        lines.append("    classDef suid fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px;")
        # Traps / Path Hijacking (Orange) - NEW
        lines.append("    classDef trap fill:#ffe0b2,stroke:#e65100,stroke-width:2px;")

        for idx, chain in enumerate(self.attack_chains, start=1):
            goal = chain.get("goal", "Goal")
            
            # Create a subgraph for each chain
            chain_label = f"Chain {idx}: {goal.replace('_', ' ').title()}"
            lines.append(f"    subgraph C{idx} [{chain_label}]")
            lines.append(f"    direction TB")
            
            steps = chain.get("steps", [])
            previous_node = f"Start_{idx}((Start))"
            
            for i, step in enumerate(steps):
                desc = step.get("description", "Action") or "Step"
                
                # Unique Node ID
                node_id = f"C{idx}_S{i}"
                
                # === Styling Logic ===
                style_class = "primitive"
                desc_lower = desc.lower()
                
                if "root" in goal: 
                    # If this is the FINAL step of a root chain, it might be the trigger
                    if i == len(steps) - 1:
                        pass # Keep logic below to decide specific type
                        
                if "write" in desc_lower or "modify" in desc_lower: 
                    style_class = "fileWrite"
                elif "persistence" in desc_lower: 
                    style_class = "persistence"
                elif "suid" in desc_lower: 
                    style_class = "suid"
                elif "hijack" in desc_lower or "trap" in desc_lower or "interception" in desc_lower:
                    style_class = "trap"
                
                # Sanitize label (escape quotes if needed, limit length)
                clean_desc = desc.replace('"', "'")
                label = f"{clean_desc[:40]}..." if len(clean_desc) > 40 else clean_desc
                
                lines.append(f"    {node_id}[\"{label}\"]:::{style_class}")
                lines.append(f"    {previous_node} --> {node_id}")
                previous_node = node_id
                
            # End node
            lines.append(f"    {previous_node} --> End_{idx}((({goal})))")
            lines.append("    end")
            
        lines.append("```")
        lines.append("")
        return lines

    # ------------------------ Attack Chain Rendering -----------------------

    def _render_attack_chains_summary(self) -> List[str]:
        if not self.attack_chains:
            return []

        lines: List[str] = []
        lines.append("## Offensive Attack Chains")
        lines.append("")
        lines.append(
            "Nullpeas models local privilege escalation paths from discovered primitives. "
            "Chains are not executed; they exist for operator planning and defensive review."
        )
        lines.append("")

        total = len(self.attack_chains)
        # Sort: lowest priority number first
        def _sort_key(c: Dict[str, Any]):
            return (
                c.get("priority", 999),
                {"catastrophic": 0, "severe": 1, "useful": 2, "niche": 3}.get(
                    c.get("classification", "niche"), 3
                ),
            )

        sorted_chains = sorted(self.attack_chains, key=_sort_key)
        top = sorted_chains[0]

        lines.append("### Offensive Summary")
        lines.append("")
        lines.append("Nullpeas Offensive Chain Summary")
        lines.append(f"Top Chain:")
        lines.append(f" - Goal: {top.get('goal', 'unknown')}")
        lines.append(f" - Exploitability: {top.get('exploitability', 'unknown')}")
        lines.append(f" - Stability: {top.get('stability', 'unknown')}")
        lines.append(f" - Noise: {top.get('noise', 'unknown')}")

        offensive_truth = top.get("offensive_truth") or top.get("summary")
        if offensive_truth:
            lines.append(f" - Truth: {offensive_truth}")

        lines.append(f"Total Chains Identified: {total}")
        lines.append("")
        return lines

    def _render_attack_chains_detail(self) -> List[str]:
        if not self.attack_chains:
            return []

        lines: List[str] = []
        lines.append("### Detailed Attack Chains")
        lines.append("")

        for idx, c in enumerate(self.attack_chains, start=1):
            chain_id = c.get("chain_id", f"chain_{idx}")
            goal = c.get("goal", "unknown")
            classification = c.get("classification", "niche")
            exploitability = c.get("exploitability", "unknown")
            stability = c.get("stability", "unknown")
            noise = c.get("noise", "unknown")
            priority = c.get("priority", "?")

            offensive_truth = c.get("offensive_truth") or c.get("summary")

            lines.append(f"#### Chain {idx}: {goal}")
            lines.append(f"- Chain ID       : `{chain_id}`")
            lines.append(f"- Goal           : `{goal}`")
            lines.append(f"- Priority       : {priority}")
            lines.append(f"- Classification : {classification}")
            lines.append(f"- Exploitability : {exploitability}")
            lines.append(f"- Stability      : {stability}")
            lines.append(f"- Noise profile  : {noise}")
            lines.append("")

            if offensive_truth:
                lines.append(f"**Offensive reality:** {offensive_truth}")
                lines.append("")

            # Steps
            steps = c.get("steps") or []
            if steps:
                lines.append("**Steps:**")
                for step in steps:
                    pid = step.get("primitive_id") or step.get("id") or "primitive"
                    desc = step.get("description") or step.get("label") or ""
                    if desc:
                        lines.append(f"- `{pid}` → {desc}")
                    else:
                        lines.append(f"- `{pid}`")
                lines.append("")

            # === RENDER EXPLOIT COMMANDS (Action Engine) ===
            exploit_commands = c.get("exploit_commands") or []
            if exploit_commands:
                lines.append("**⚠️  Exploit Commands:**")
                lines.append("```bash")
                for cmd in exploit_commands:
                    lines.append(cmd)
                lines.append("```")
                lines.append("")
            # ===============================================

            # Surfaces
            surfaces = c.get("dependent_surfaces") or c.get("surfaces") or []
            if surfaces:
                lines.append("**Surfaces involved:** " + ", ".join(sorted(set(surfaces))))
                lines.append("")

            # Confidence
            conf = c.get("confidence") or {}
            if conf:
                score = conf.get("score")
                reason = conf.get("reason")
                lines.append("**Confidence:**")
                if score is not None:
                    lines.append(f"- {score}/10")
                if reason:
                    lines.append(f"- {reason}")
                lines.append("")

            lines.append("")
        return lines

    def _render_attack_chains(self) -> List[str]:
        if not self.attack_chains:
            return []

        lines: List[str] = []
        lines.extend(self._render_attack_chains_summary())
        lines.extend(self._render_attack_chains_detail())
        return lines

    # ------------------------ Primitive Rendering --------------------------

    def _render_primitives(self) -> List[str]:
        if not self.primitives:
            return []

        lines: List[str] = []
        lines.append("## Offensive Primitives")
        lines.append("")
        lines.append(
            "These are individual local privilege escalation or control opportunities identified on the host."
        )
        lines.append(
            "They are structured for analysis and chaining only; Nullpeas does not execute them."
        )
        lines.append("")

        for p in self.primitives:
            primitive_id = p.get("id", "primitive")
            primitive_type = p.get("type", "unknown_type")

            lines.append(f"### {primitive_id} ({primitive_type})")
            lines.append("")

            lines.append(f"**Surface:** `{p.get('surface', 'unknown')}`")
            lines.append(f"**Run as:** `{p.get('run_as', 'unknown')}`")
            lines.append(f"**Exploitability:** `{p.get('exploitability', 'unknown')}`")
            lines.append(f"**Stability:** `{p.get('stability', 'unknown')}`")
            lines.append(f"**Noise:** `{p.get('noise', 'unknown')}`")

            conf = p.get("confidence", {}) or {}
            score = conf.get("score", "?")
            reason = conf.get("reason")
            lines.append(f"**Confidence:** {score}/10")
            if reason:
                lines.append(f"- {reason}")

            val = p.get("offensive_value", {}) or {}
            if val:
                lines.append("")
                lines.append("**Offensive value:**")
                classification = val.get("classification")
                why = val.get("why")
                if classification:
                    lines.append(f"- Classification: {classification}")
                if why:
                    lines.append(f"- Rationale: {why}")

            ctx = p.get("context") or {}
            if ctx:
                lines.append("")
                lines.append("**Context:**")
                for k, v in ctx.items():
                    lines.append(f"- {k}: {v}")

            # Also render affected resource if available
            affected = p.get("affected_resource")
            if affected:
                 lines.append(f"- **Affected Resource:** {affected}")

            lines.append("")
        return lines

    # ----------------------------------------------------------------------
    # JSON EXPORT
    # ----------------------------------------------------------------------

    def export_json(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "generated_utc": datetime.datetime.utcnow().isoformat(timespec="seconds")
            + "Z",
            "sections": self.sections,
            "primitives": self.primitives,
            "attack_chains": self.attack_chains,
        }

    # ----------------------------------------------------------------------
    # WRITE OUTPUT
    # ----------------------------------------------------------------------

    def write_markdown(self, filename: str = "nullpeas_report.md") -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / filename

        content_lines: List[str] = []
        content_lines.extend(self._render_header())
        
        # === Render Visual Map ===
        content_lines.extend(self._render_mermaid())
        
        content_lines.extend(self._render_sections())
        content_lines.extend(self._render_attack_chains())
        content_lines.extend(self._render_primitives())

        path.write_text("\n".join(content_lines), encoding="utf-8")
        return path

    def write_json(self, filename: str = "nullpeas_report.json") -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / filename
        path.write_text(json.dumps(self.export_json(), indent=2), encoding="utf-8")
        return path

    def write_all(self) -> Dict[str, Path]:
        """
        Convenience helper: write both Markdown and JSON.
        """
        md_path = self.write_markdown()
        json_path = self.write_json()
        return {"markdown": md_path, "json": json_path}

    def write(self, filename: str = "nullpeas_report.md") -> Path:
        """
        Legacy shim: write only Markdown.
        """
        return self.write_markdown(filename)