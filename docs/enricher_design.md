# Nullpeas Enricher (Offline Report Enrichment Tool)

## Goal

The idea behind the Nullpeas Enricher is simple:

Nullpeas on the target should stay completely offline, safe, audit friendly, and focused on local reasoning only. The Enricher is a separate tool that runs on my own machine and adds external intelligence to the findings without ever touching or communicating from the target host.

This keeps Nullpeas professional and makes it useful without drifting into malware style behaviour or beaconing issues.

---

## How It Fits Into Workflow

1. Run Nullpeas on the target machine
2. Nullpeas generates:
   - cache/nullpeas_report.md (human friendly)
   - cache/nullpeas_report.json (machine readable in future)
3. Copy those reports to my workstation
4. Run the Enricher locally
5. Get a much richer final report with references and learning material

---

## Input Format (JSON Concept)

Nullpeas will eventually output findings in a structured JSON format so enrichment tools can understand them. Rough shape of the data:

```json
{
  "host": {
    "hostname": "example-host",
    "os": "Ubuntu 24.04.3 LTS",
    "kernel": "6.8.0",
    "arch": "x86_64"
  },
  "findings": [
    {
      "surface": "sudo",
      "rule_raw": "(root) NOPASSWD: /usr/bin/vim",
      "binary": "vim",
      "severity": "high",
      "capabilities": [
        "editor_escape",
        "shell_spawn",
        "file_read",
        "file_write"
      ],
      "notes": [
        "Binary found",
        "Executable",
        "Rule grants passwordless execution"
      ]
    }
  ]
}
```

---

## What The Enricher Does

The Enricher will only ever run on my machine, not the target.

It will take the JSON report and enhance it with external references like:

- GTFOBins entries
- CVE or security guidance in the future
- Vendor documentation
- Hardening best practices
- Useful learning resources

Example output idea:

```markdown
### Sudo Finding: (root) NOPASSWD: /usr/bin/vim

Severity: high  
Capabilities: editor_escape, shell_spawn, file_read, file_write  

References:
- GTFOBins:
  https://gtfobins.github.io/gtfobins/vim/
- Sudo security best practices:
  <link>
- Hardening guides:
  <link>
```

---

## Separation Of Concerns

Nullpeas core on the target:

- No outbound network connections
- No DNS lookups
- No calling APIs
- Only local reasoning
- Produces structured findings

Enricher tool on my host:

- Allowed to use internet
- Allowed to hit APIs
- Only operates on exported reports
- Never touches target systems

This avoids any malware adjacent behaviour and keeps the tool respectable.

---

## Possible CLI Shape One Day

```bash
nullpeas-enrich ./nullpeas_report.json > nullpeas_report_enriched.md
```

---

## Design Principles

- Nullpeas core stays offline, ethical, safe, quiet, readable
- Enricher is optional but powerful
- Keeps trust of both red teams and blue teams
- Keeps everything clean and transparent
