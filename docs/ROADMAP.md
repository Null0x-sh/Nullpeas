# Nullpeas Roadmap

## Mission
Build the most **quiet**, **intelligent**, **chain-aware**, and **offensively truthful** local privilege escalation engine available.  
Nullpeas is not “just another enumeration dump.”  
Nullpeas is a **thinking escalation assistant**.

It will:
- Enumerate safely and deliberately
- Interpret findings like a real operator would
- Produce actionable offensive truth instead of noise
- Convert findings into structured offensive primitives
- Chain primitives into realistic attack paths
- Speak in a professional, blunt, and credible tone

---

## Phase 1 — Foundations (Current Work)

### Objective
Establish a strong technical foundation, safe baseline enumeration, serious reporting, and a working offensive chaining engine.

### Deliverables

### Core Engine
- Threaded probing framework  
- Stable state and caching  
- Trigger pipeline  
- Structured intelligence storage  

### Baseline Probes
- Users and Groups  
- System and Environment  
- Sudo  
- Cron  
- Runtime and Containers  

### First Offensive Analysis Modules
- `sudo_enum`
- `cron_enum`
- `docker_enum`

### Offensive Representation Layer
- Offensive primitive schema
- Primitive exploitability model
- Stability model
- OPSEC noise model
- Confidence classification

### Chaining Engine
- Primitive ingestion
- Chain reasoning
- Realistic escalation path construction
- Threat impact classification

### Professional Reporting
- Structured Markdown reports
- Professional tone
- Clear chain narratives
- Honest risk communication including:  
  “this host is realistically at risk” type statements

### Outcome
A stable, professional, quiet, intelligent pre-exploit analysis engine that serious operators can trust.

---

## Phase 2 — Practical Parity With linPEAS

### Objective
Reach meaningful parity in **surface coverage** with linPEAS while being cleaner, quieter, and significantly smarter.

### Modules To Deliver
- SUID and SGID analysis
- PATH hijacking detector
- Linux capabilities abuse detection
- Systemd and service misconfiguration analysis
- Filesystem weakness and privilege misconfig detection
- Container and virtualization awareness expansion
- Credential and secret discovery
- Kernel exploit surface detection (explain-only, never execute)

### Requirements For Every Module
Every module must:
- Enumerate its surface fully but safely
- Interpret findings as an attacker would
- Produce realistic escalation insight
- Emit structured offensive primitives
- Include severity, confidence, OPSEC noise, and stability
- Support chain construction

Modules must not:
- Exploit anything
- Modify system state
- Create persistence
- Be loud without justification
- Understate real risk

### Outcome
Nullpeas becomes capable of replacing linPEAS in serious, professional workflows.

---

## Phase 3 — Offensive Intelligence Evolution

### Objective
Move beyond tools that simply “list things.”  
Nullpeas should **think like a skilled operator**.

### Deliverables
- Advanced attack reasoning
- Contextual system risk interpretation
- Multi-path escalation evaluation
- Lateral movement preparation insight
- Persistence opportunity assessment
- Host takeover realism assessment
- Clear “security posture reality check” reporting

### Future Potential
- JSON output for automation pipelines
- SIEM ingest capability
- Blue team remediation guidance
- Threat emulation mapping
- Operator learning and training mode

### Outcome
Nullpeas becomes a respected offensive reasoning platform, trusted by red teams, valued by defenders, and credible to professionals.

---

## Philosophy Alignment
Nullpeas must always embody:
- Low noise and stealth-first behaviour
- Intelligence and reasoning-driven output
- Chain awareness and offensive realism
- Professional and serious report tone
- Blunt and truthful risk communication

If a system is realistically compromised,  
Nullpeas should say so clearly and responsibly.

---

## Final Vision
Nullpeas will become:
- A trusted red team assessment assistant  
- A decision engine rather than a text dump  
- A tool that turns enumeration into intelligence  
- A modern pre-exploit escalation brain  

Quietly powerful.  
Offensively aligned.  
Professionally serious.