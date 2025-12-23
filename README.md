# Nullpeas

Nullpeas is a modular, reasoning-driven privilege escalation assistant.  
It is built to be quieter, smarter and more educational than traditional large privilege escalation scripts.

![Status](https://img.shields.io/badge/status-active-blue)
![Language](https://img.shields.io/badge/python-3.10+-yellow)
![Purpose](https://img.shields.io/badge/focus-education-green)
![License](https://img.shields.io/badge/License-GPLv3-blue.svg)

---

## Disclaimer

I am currently transitioning into a cybersecurity career and actively learning offensive security, tooling development and software engineering.

Nullpeas is both a passion project and a learning project. Expect evolution, iteration, breaking changes and refinement as I grow.

This tool is not being presented as a completed professional grade product.

Nullpeas is for authorised security testing and education only.  
If you are not legally permitted to test a system, do not run this tool.

---

## What is Nullpeas

Nullpeas is a modular privilege escalation assistant designed to move beyond the traditional giant noisy Bash script that dumps endless output and overwhelms the operator.

Nullpeas focuses on signal over noise:

- Collects structured host intelligence
- Builds and caches shared state
- Activates only relevant analysis modules
- Produces reasoning and context instead of noise
- Guides the operator rather than drowning them in text
- Explains attacker and defender viewpoints
- Supports learning rather than blind exploitation

Nullpeas does not simply report that something might be exploitable. It attempts to explain:

- Why it is risky
- How attackers reason about it
- What to research next
- How defenders should fix it
- Where to read more

The goal is to bridge the gap between:

"This might be exploitable"  
and  
"I understand the attack, defense, risk, and reasoning behind this finding"

---

## Current Status

Nullpeas is now a structured and evolving framework.

- Structured Python project layout
- Probing engine
- Shared cached state
- Trigger logic
- Reasoning and guidance system
- Markdown reporting
- Threaded execution
- Designed to be quieter where appropriate

---

## Implemented Modules

### Sudo Analysis
- Parses sudo -l
- Detects passwordless and dangerous configurations
- Categorises binary risk capability
- Assigns severity and confidence scoring
- Provides attacker reasoning
- Provides defender remediation
- Includes reference learning links

### Docker Platform Risk
- Detects Docker host vs container context
- Identifies Docker socket exposure risk
- Understands platform control boundaries
- Zero touch analysis
- Severity assessment
- Attacker and defender reasoning
- Practical remediation guidance

### Cron Abuse Risk
- Evaluates cron job privilege surfaces
- Detects writable paths
- Identifies privilege boundaries
- Explains escalation logic
- Provides practical guidance

---

## Design Philosophy

### Modular
- Each probe independent
- Each module only runs when relevant

### Smart
- Context aware
- Privilege boundary aware
- Risk focused

### Cache Aware
- Avoids repeating loud operations
- Faster and safer

### Readable
Output should teach, guide and help thinking.  
Not overwhelm.

### Explain First
Nullpeas is not an exploit execution tool.  
Modules do not perform exploitation.  
They explain, teach and guide thinking.

---

## Architecture Overview

```
brain.py        Orchestrator
core/cache.py   Persistent state
core/report.py  Markdown writer
core/guidance.py Reasoning engine

probes/*        Host intelligence collectors
modules/*       Risk analysis logic

cache/state.json
cache/nullpeas_report.md
```

---

## Screenshots and Demo

Coming soon.

Recommended future assets:
- Terminal summary output
- Markdown report excerpt
- Example reasoning block
- Short GIF of running execution to final report

---

## How To Run

```bash
git clone https://github.com/Null0x-sh/Nullpeas
cd Nullpeas
chmod +x brain.py
./brain.py
```

Output report location:

```
cache/nullpeas_report.md
```

---

## Example Behaviour

Nullpeas can:

- Detect sudo privilege surfaces
- Detect Docker escape potential
- Detect cron abuse paths
- Detect containerised environments
- Trigger relevant reasoning modules
- Produce structured Markdown reports

---

## Roadmap

- LXD and LXC analysis
- PATH hijack logic
- Linux capabilities analysis
- Systemd and service misconfiguration logic
- Kernel exploit reasoning only
- OPSEC and stealth improvements
- UX improvements
- CI and automated testing
- Community extension support

---

## Contributing

Contributions, discussion and learning collaboration are welcome.  
This project is part of a personal learning journey and community involvement is encouraged.

---

## Ethics

Nullpeas exists to:

- Teach
- Improve defenders
- Assist authorised red teamers
- Help newcomers learn responsibly

It is not intended for illegal activity or abuse.

---

## Closing

If you reached this point, thank you for taking interest in Nullpeas.  
This project will continue to evolve significantly over time.