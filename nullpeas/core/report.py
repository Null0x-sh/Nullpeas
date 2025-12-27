from __future__ import annotations
from pathlib import Path
from typing import List, Dict, Any, Optional, Iterable
import datetime
import json
from dataclasses import asdict, is_dataclass

class Report:
    """
    Nullpeas unified reporting engine.
    
    v2.7 Update: "Taxonomy & Visualization Polish"
    - Added 'pivot' classDef for Internal Pivot chains.
    - Updated goal mapping for 'root_compromise'.
    - Improved step styling heuristics for network actions.
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

    def _render_mermaid(self) -> List[str]:
        if not self.attack_chains:
            return []

        lines = ["## Visual Attack Map", "", "```mermaid", "graph TD"]

        # Styles
        lines.append("    classDef primitive fill:#e1f5fe,stroke:#01579b,stroke-width:2px;")
        lines.append("    classDef rootGoal fill:#ffcdd2,stroke:#b71c1c,stroke-width:4px;")
        lines.append("    classDef fileWrite fill:#fff9c4,stroke:#fbc02d,stroke-width:2px;")
        lines.append("    classDef persistence fill:#e8f5e9,stroke:#1b5e20,stroke-width:2px;")
        lines.append("    classDef suid fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px;")
        lines.append("    classDef trap fill:#ffe0b2,stroke:#e65100,stroke-width:2px;")
        lines.append("    classDef service fill:#e8eaf6,stroke:#3f51b5,stroke-width:2px;")
        lines.append("    classDef loot fill:#b2dfdb,stroke:#00695c,stroke-width:2px;")
        lines.append("    classDef pivot fill:#d1c4e9,stroke:#512da8,stroke-width:2px;") # <--- NEW: Purple for Pivot
        lines.append("    classDef startNode fill:#eeeeee,stroke:#424242,stroke-width:1px;")

        # Re-use same sort logic as _render_attack_chains so diagrams and text match
        def _sort_key(c: Dict[str, Any]):
            class_score = {
                "catastrophic": 0,
                "critical": 1,
                "severe": 2,
                "high": 3,
                "useful": 4,
                "niche": 5,
            }.get(c.get("classification", "niche"), 5)
            return (c.get("priority", 999), class_score)

        top_chains = sorted(self.attack_chains, key=_sort_key)[:5]

        for idx, chain in enumerate(top_chains, start=1):
            goal = chain.get("goal", "Goal")
            lines.append(f"    subgraph C{idx} [Chain {idx}: {goal}]")
            lines.append("    direction TB")

            # Start node
            start_node = f"Start_{idx}((Start)):::startNode"
            lines.append(f"    {start_node}")
            previous_node = start_node

            steps = chain.get("steps", []) or []
            for i, step in enumerate(steps):
                desc = step.get("description", "Action") or "Step"
                node_id = f"C{idx}_S{i}"
                d_low = desc.lower()

                # Default style
                style_class = "primitive"

                # Heuristics for step types
                if "write" in d_low or "modify" in d_low:
                    style_class = "fileWrite"
                if "persistence" in d_low:
                    style_class = "persistence"
                if "suid" in d_low:
                    style_class = "suid"
                if "hijack" in d_low or "trap" in d_low:
                    style_class = "trap"
                if "systemd" in d_low or "service" in d_low or "connect" in d_low or "mount" in d_low:
                    style_class = "service"
                if "harvest" in d_low or "credential" in d_low:
                    style_class = "loot"
                if "enumerate" in d_low or "pivot" in d_low:
                    style_class = "pivot"
                if "wait for privileged user" in d_low:
                    style_class = "trap"

                # Truncate labels nicely with ellipsis if needed
                safe_desc = desc.replace('"', "'")
                if len(safe_desc) > 50:
                    label = safe_desc[:47] + "..."
                else:
                    label = safe_desc

                lines.append(f"    {node_id}[\"{label}\"]:::{style_class}")
                lines.append(f"    {previous_node} --> {node_id}")
                previous_node = node_id

            # Goal node styling based on new taxonomy
            end_node = f"End_{idx}((({goal})))"
            
            if goal == "root_compromise": 
                end_node += ":::rootGoal"
            elif goal in ("privilege_escalation", "persistence"):
                end_node += ":::persistence"
            elif goal in ("credential_access", "reconnaissance"):
                end_node += ":::loot"
            elif goal == "internal_pivot":
                end_node += ":::pivot"

            lines.append(f"    {previous_node} --> {end_node}")
            lines.append("    end")

        lines.append("```")
        lines.append("")
        return lines


    def _render_attack_chains(self) -> List[str]:
        if not self.attack_chains: return []

        # Sort: High priority (1) first, then Severe classification
        def _sort_key(c: Dict[str, Any]):
            class_score = {"catastrophic": 0, "critical": 1, "severe": 2, "high": 3, "useful": 4, "niche": 5}.get(c.get("classification", "niche"), 5)
            return (c.get("priority", 999), class_score)

        sorted_chains = sorted(self.attack_chains, key=_sort_key)
        
        lines = []
        lines.append("## Offensive Attack Chains")
        lines.append(f"**Total Chains Identified:** {len(sorted_chains)}")
        lines.append("")

        # --- PART 1: TOP 5 FULL DETAIL ---
        lines.append("### 🔥 Top Critical Chains")
        lines.append("Detailed analysis of the most dangerous paths found.")
        lines.append("")

        for idx, c in enumerate(sorted_chains[:5], start=1):
            goal = c.get("goal", "unknown")
            lines.append(f"#### {idx}. {goal} ({c.get('classification')})")
            lines.append(f"- **Truth:** {c.get('offensive_truth', 'N/A')}")
            
            conf_score = c.get("confidence", {}).get("score", "?")
            lines.append(f"- **Confidence:** {conf_score}/10")
            
            if c.get("steps"):
                lines.append("**Attack Path:**")
                for s in c["steps"]:
                    lines.append(f"1. `{s.get('primitive_id')}` -> {s.get('description')}")
            
            cmds = c.get("exploit_commands", [])
            if cmds:
                lines.append("")
                lines.append("```bash")
                for cmd in cmds: lines.append(cmd)
                lines.append("```")
            lines.append("")
            lines.append("---")
            lines.append("")

        # --- PART 2: COMPACT TABLE FOR THE REST ---
        if len(sorted_chains) > 5:
            lines.append("### 📋 Additional Chains")
            lines.append("Summary of other identified vectors.")
            lines.append("")
            lines.append("| ID | Goal | Classification | Exploitability | Primary Vector |")
            lines.append("|---|---|---|---|---|")
            
            for c in sorted_chains[5:]:
                # Show unique hash suffix
                full_id = c.get("chain_id", "")
                cid = full_id.split("_")[-1] if "_" in full_id else full_id[:8]
                
                goal = c.get("goal", "")
                cls = c.get("classification", "")
                exp = c.get("exploitability", "")
                vec = "Unknown"
                if c.get("steps"):
                    vec = c["steps"][0].get("description", "")[:50]
                
                lines.append(f"| `...{cid}` | {goal} | {cls} | {exp} | {vec} |")
            
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
