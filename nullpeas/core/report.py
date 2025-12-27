from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any, Optional, Iterable, Set, Tuple
import datetime
import json
from dataclasses import asdict, is_dataclass

class Report:
    """
    Nullpeas unified reporting engine.
    
    v3.0 Update:
    - Normalized Surface Titles (sudo, docker, etc.).
    - Human-readable Goal Labels in diagrams.
    - Confidence scores visible in visual map headers.
    - Severity Emojis in summary tables.
    - High-contrast Trap styling.
    """

    def __init__(
        self,
        title: str = "Nullpeas Local Privilege Escalation Assessment",
        output_dir: str = "cache",
    ):
        self.title = title
        self.output_dir = Path(output_dir)
        self.sections: List[Dict[str, Any]] = []
        self.primitives: List[Dict[str, Any]] = []
        self.attack_chains: List[Dict[str, Any]] = []

    @classmethod
    def from_state(cls, state: Dict[str, Any], title: str = "Nullpeas Assessment", output_dir: str = "cache") -> "Report":
        r = cls(title=title, output_dir=output_dir)
        for p in state.get("offensive_primitives", []) or []:
            r.add_primitive(p)
        for c in state.get("attack_chains", []) or []:
            r.add_attack_chain(c)
        return r

    def add_section(self, heading: str, body_lines: List[str]):
        self.sections.append({"heading": heading, "body_lines": body_lines or []})

    def add_finding(self, heading: str, summary: str, details: Optional[List[str]] = None):
        lines = [summary]
        if details:
            lines.append("")
            lines.extend(details)
        self.add_section(heading, lines)

    def add_primitive(self, primitive: Any):
        if is_dataclass(primitive): primitive = asdict(primitive)
        elif hasattr(primitive, "__dict__"): primitive = primitive.__dict__
        self.primitives.append(primitive)

    def add_attack_chain(self, chain: Any):
        if is_dataclass(chain): chain = asdict(chain)
        elif hasattr(chain, "__dict__"): chain = chain.__dict__
        self.attack_chains.append(chain)

    def add_attack_chains(self, chains: Iterable[Any]):
        for c in chains:
            self.add_attack_chain(c)

    # ----------------------------------------------------------------------
    # RENDERING LOGIC
    # ----------------------------------------------------------------------

    def _render_header(self) -> List[str]:
        ts = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"
        return [f"# {self.title}", "", f"_Generated: {ts}_", "", "---", ""]

    def _render_sections(self) -> List[str]:
        if not self.sections: return []
        lines = []
        for section in self.sections:
            lines.append(f"## {section['heading']}")
            lines.append("")
            lines.extend(section["body_lines"])
            lines.append("")
        return lines

    def _normalize_surface(self, surfaces: List[str]) -> str:
        """Helper to get a clean, human-readable primary surface name."""
        if "sudo" in surfaces: return "sudo"
        if "docker" in surfaces: return "docker"
        if "systemd" in surfaces: return "systemd"
        if "cron" in surfaces: return "cron"
        if "path" in surfaces: return "path"
        if "network" in surfaces: return "network"
        return surfaces[0] if surfaces else "generic"

    def _select_diverse_chains(self, limit: int = 5) -> List[Dict[str, Any]]:
        """
        Selects top chains but ensures visual diversity by normalizing surface types.
        """
        if not self.attack_chains:
            return []

        # 1. Sort by Priority then Severity
        def _sort_key(c: Dict[str, Any]):
            class_score = {
                "catastrophic": 0, "critical": 1, "severe": 2, 
                "high": 3, "useful": 4, "niche": 5
            }.get(c.get("classification", "niche"), 5)
            return (c.get("priority", 999), class_score)

        sorted_chains = sorted(self.attack_chains, key=_sort_key)
        
        selection = []
        seen_types: Set[Tuple[str, str]] = set() # (goal, normalized_surface)

        # Pass 1: Pick unique (Goal + Normalized Surface) combos
        for c in sorted_chains:
            goal = c.get("goal", "unknown")
            surfaces = c.get("dependent_surfaces", [])
            primary = self._normalize_surface(surfaces)

            key = (goal, primary)
            if key not in seen_types:
                selection.append(c)
                seen_types.add(key)
            
            if len(selection) >= limit:
                break
        
        # Pass 2: Fill remaining slots if we didn't hit limit
        if len(selection) < limit:
            for c in sorted_chains:
                if c not in selection:
                    selection.append(c)
                if len(selection) >= limit:
                    break
        
        return selection

    def _render_mermaid(self) -> List[str]:
        if not self.attack_chains:
            return []

        lines = ["## Visual Attack Map", "", "```mermaid", "graph TD"]

        # === Definitions ===
        lines.append("    %% Node Styles")
        lines.append("    classDef startNode fill:#eeeeee,stroke:#424242,stroke-width:1px;")
        lines.append("    classDef primitive fill:#e1f5fe,stroke:#01579b,stroke-width:2px;")
        
        # Primitive Subtypes
        lines.append("    classDef fileWrite fill:#fff9c4,stroke:#fbc02d,stroke-width:2px;")
        lines.append("    classDef suid fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px;")
        # Trap: Red-Orange + Thicker Border
        lines.append("    classDef trap fill:#ffccbc,stroke:#bf360c,stroke-width:3px;") 
        lines.append("    classDef service fill:#e8eaf6,stroke:#3f51b5,stroke-width:2px;")
        lines.append("    classDef loot fill:#b2dfdb,stroke:#00695c,stroke-width:2px;")
        lines.append("    classDef pivot fill:#d1c4e9,stroke:#512da8,stroke-width:2px;")

        # Goal Styles (Semantic)
        lines.append("    classDef goalRoot fill:#ffcdd2,stroke:#b71c1c,stroke-width:4px;")
        lines.append("    classDef goalPrivesc fill:#e1bee7,stroke:#6a1b9a,stroke-width:3px;")
        lines.append("    classDef goalCreds fill:#b2dfdb,stroke:#00695c,stroke-width:3px;")
        lines.append("    classDef goalRecon fill:#eeeeee,stroke:#424242,stroke-width:2px;")
        lines.append("    classDef goalPivot fill:#d1c4e9,stroke:#512da8,stroke-width:3px;")
        lines.append("    classDef goalPersist fill:#c8e6c9,stroke:#2e7d32,stroke-width:3px;")

        # === Graph Construction ===
        limit = min(5, len(self.attack_chains))
        top_chains = self._select_diverse_chains(limit=limit)

        for idx, chain in enumerate(top_chains, start=1):
            raw_goal = chain.get("goal", "unknown")
            surfaces = chain.get("dependent_surfaces", [])
            primary_surface = self._normalize_surface(surfaces)
            conf = chain.get("confidence", {}).get("score", "?")
            
            pretty_goal = raw_goal.replace("_", " ").title()
            
            lines.append(f"    subgraph C{idx} [Chain {idx}: {pretty_goal} via {primary_surface} (Confidence {conf}/10)]")
            lines.append("    direction TB")

            start_id = f"Start_{idx}"
            lines.append(f"    {start_id}((Start)):::startNode")
            previous_id = start_id

            steps = chain.get("steps", []) or []
            for i, step in enumerate(steps):
                desc = step.get("description", "Step")
                node_id = f"C{idx}_S{i}"
                
                d_low = desc.lower()
                style = "primitive"
                
                if "write" in d_low or "modify" in d_low: style = "fileWrite"
                elif "persistence" in d_low: style = "goalPersist"
                elif "suid" in d_low: style = "suid"
                elif any(x in d_low for x in ["hijack", "trap", "wait"]): style = "trap"
                elif any(x in d_low for x in ["systemd", "service", "connect", "mount"]): style = "service"
                elif any(x in d_low for x in ["harvest", "credential", "shadow", "passwd"]): style = "loot"
                elif any(x in d_low for x in ["enumerate", "pivot"]): style = "pivot"

                label = desc.replace('"', "'")
                if len(label) > 50: label = label[:47] + "..."

                lines.append(f"    {node_id}[\"{label}\"]:::{style}")
                lines.append(f"    {previous_id} --> {node_id}")
                previous_id = node_id

            end_style = "goalRecon"
            if raw_goal == "root_compromise": end_style = "goalRoot"
            elif raw_goal == "privilege_escalation": end_style = "goalPrivesc"
            elif raw_goal == "credential_access": end_style = "goalCreds"
            elif raw_goal == "internal_pivot": end_style = "goalPivot"
            elif raw_goal == "persistence": end_style = "goalPersist"

            end_id = f"End_{idx}"
            lines.append(f"    {end_id}((({pretty_goal}))):::{end_style}")
            lines.append(f"    {previous_id} --> {end_id}")
            lines.append("    end")

        lines.append("```")
        lines.append("")
        return lines

    def _render_attack_chains(self) -> List[str]:
        if not self.attack_chains: return []

        def _sort_key(c: Dict[str, Any]):
            class_score = {"catastrophic": 0, "critical": 1, "severe": 2, "high": 3, "useful": 4, "niche": 5}.get(c.get("classification", "niche"), 5)
            return (c.get("priority", 999), class_score)

        sorted_chains = sorted(self.attack_chains, key=_sort_key)
        
        lines = []
        lines.append("## Offensive Attack Chains") 
        lines.append(f"**Total Chains Identified:** {len(sorted_chains)}")
        lines.append("")

        lines.append("### 🔥 Top Priority Chains")
        lines.append("Detailed analysis of the most impactful and realistic paths found.")
        lines.append("")

        for idx, c in enumerate(sorted_chains[:5], start=1):
            goal_raw = c.get("goal", "unknown")
            goal = goal_raw.replace("_", " ").title()
            lines.append(f"#### {idx}. {goal} ({c.get('classification')})")
            lines.append(f"- **Truth:** {c.get('offensive_truth', 'N/A')}")
            
            conf_score = c.get("confidence", {}).get("score", "?")
            lines.append(f"- **Confidence:** {conf_score}/10")
            
            if c.get("steps"):
                lines.append("")
                lines.append("**Attack Path:**")
                lines.append("")
                for i, s in enumerate(c.get("steps", []), start=1):
                    desc = s.get("description", "Step")
                    pid = s.get("primitive_id", "")
                    if pid:
                        lines.append(f"{i}. **{desc}**  (`{pid}`)")
                    else:
                        lines.append(f"{i}. **{desc}**")
                lines.append("")

            cmds = c.get("exploit_commands", [])
            if cmds:
                lines.append("```bash")
                for cmd in cmds: lines.append(cmd)
                lines.append("```")
            lines.append("")
            lines.append("---")
            lines.append("")

        if len(sorted_chains) > 5:
            lines.append("### 📋 Additional Chains")
            lines.append("Summary of other identified vectors.")
            lines.append("")
            lines.append("| ID | Goal | Classification | Exploitability | Primary Vector |")
            lines.append("|---|---|---|---|---|")
            
            for c in sorted_chains[5:]:
                full_id = c.get("chain_id", "")
                cid = full_id.split("_")[-1] if "_" in full_id else full_id[:8]
                
                goal = c.get("goal", "")
                cls = c.get("classification", "")
                exp = c.get("exploitability", "")
                
                sev_icon = {
                    "catastrophic": "☠️", 
                    "critical": "🔥", 
                    "severe": "🚨", 
                    "high": "⚠️", 
                    "useful": "ℹ️"
                }.get(cls, "")

                vec = "Unknown"
                if c.get("steps"):
                    vec = c["steps"][0].get("description", "")[:50]
                
                lines.append(f"| `...{cid}` | {goal} | {sev_icon} {cls} | {exp} | {vec} |")
            
            lines.append("")

        return lines

    def _render_primitives(self) -> List[str]:
        if not self.primitives: return []
        lines = ["## Offensive Primitives (Raw Data)", ""]
        lines.append("| ID | Type | Surface | Confidence |")
        lines.append("|---|---|---|---|")
        for p in self.primitives:
            pid = p.get("id", "")
            ptype = p.get("type", "")
            surf = p.get("surface", "")
            conf = p.get("confidence", {}).get("score", "?")
            lines.append(f"| `{pid}` | {ptype} | {surf} | {conf}/10 |")
        lines.append("")
        return lines

    def export_json(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "generated_utc": datetime.datetime.utcnow().isoformat() + "Z",
            "sections": self.sections,
            "primitives": self.primitives,
            "attack_chains": self.attack_chains,
        }

    def write_markdown(self, filename: str = "nullpeas_report.md") -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / filename
        content = []
        content.extend(self._render_header())
        content.extend(self._render_mermaid())
        content.extend(self._render_attack_chains())
        content.extend(self._render_sections())
        
        path.write_text("\n".join(content), encoding="utf-8")
        return path

    def write_json(self, filename: str = "nullpeas_report.json") -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / filename
        path.write_text(json.dumps(self.export_json(), indent=2), encoding="utf-8")
        return path

    def write(self, filename: str = "nullpeas_report.md") -> Path:
        return self.write_markdown(filename)
    
    def add_primitives(self, prims: Iterable[Any]):
        for p in prims: self.add_primitive(p)