from pathlib import Path
from typing import List, Dict, Any
import datetime


class Report:
    """
    Simple report builder for Nullpeas.

    - Modules append sections, findings, and notes.
    - At the end, we write a single Markdown report to cache/.
    """

    def __init__(self, title: str = "Nullpeas Report", output_dir: str = "cache"):
        self.title = title
        self.output_dir = Path(output_dir)
        self.sections: List[Dict[str, Any]] = []

    def add_section(self, heading: str, body_lines: List[str]):
        self.sections.append(
            {
                "heading": heading,
                "body_lines": body_lines,
            }
        )

    def add_finding(self, heading: str, summary: str, details: List[str] | None = None):
        lines = [summary]
        if details:
            lines.append("")
            lines.extend(details)
        self.add_section(heading, lines)

    def _render_markdown(self) -> str:
        lines: List[str] = []
        timestamp = datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z"

        lines.append(f"# {self.title}")
        lines.append("")
        lines.append(f"_Generated: {timestamp}_")
        lines.append("")

        for section in self.sections:
            heading = section["heading"]
            body_lines = section["body_lines"] or []
            lines.append(f"## {heading}")
            lines.append("")
            lines.extend(body_lines)
            lines.append("")

        return "\n".join(lines)

    def write(self, filename: str = "nullpeas_report.md") -> Path:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        path = self.output_dir / filename
        content = self._render_markdown()
        path.write_text(content, encoding="utf-8")
        return path
