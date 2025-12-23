# Nullpeas

Nullpeas is a modular, reasoning-driven Linux privilege escalation assistant.  
It is designed to be quieter, smarter, and more educational than traditional large privilege escalation scripts.

![Status](https://img.shields.io/badge/status-active-blue)
![Language](https://img.shields.io/badge/python-3.10+-yellow)
![Purpose](https://img.shields.io/badge/focus-education-green)
![License](https://img.shields.io/badge/License-GPLv3-blue.svg)

---

## Disclaimer

I am currently transitioning into a cybersecurity career and actively learning offensive security, tooling development, and software engineering.

Nullpeas is both a passion project and a learning project. Expect evolution, iteration, refinement, and occasional breaking changes.

This is not being presented as a finished professional product.

Nullpeas is for authorised security testing and education only.  
If you are not legally permitted to test a system, do not run this tool.

---

## What is Nullpeas

Nullpeas is a modular privilege escalation assistant intended to move beyond traditional noisy enumeration scripts that dump thousands of lines of output and overwhelm the operator.

Nullpeas focuses on signal over noise:

- Collects structured host intelligence
- Builds and caches shared state
- Activates only relevant analysis modules
- Produces reasoning and context instead of blind data
- Guides the operator instead of drowning them in text
- Explains attacker and defender perspectives
- Supports learning rather than blind exploitation

Nullpeas does not simply say “this may be exploitable.” It attempts to explain:

- Why it is risky
- How attackers think about it
- What to research next
- How defenders should fix it
- Where to learn more

The goal is to bridge the gap between:

“This might be exploitable”  
and  
“I understand the attack, the risk, the defensive posture, and the reasoning behind this finding.”

---

## Current Status

Nullpeas is an evolving structured framework.

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
- Parses sudo -l output
- Detects passwordless and dangerous configurations
- Categorises binary capability risk
- Assigns severity and confidence scoring
- Provides attacker reasoning
- Provides defender remediation guidance
- Includes learning references

### Docker Platform Risk
- Detects Docker host vs container context
- Identifies Docker socket exposure risk
- Understands privilege boundaries
- Zero-touch analysis approach
- Severity assessment
- Reasoning for both attacker and defender perspectives
- Practical remediation guidance

### Cron Abuse Risk
- Evaluates cron privilege surfaces
- Detects writable paths
- Identifies escalation potential
- Explains escalation logic
- Provides practical guidance

---

## Design Philosophy

### Modular
- Each probe independent
- Modules only run when relevant

### Smart
- Context aware
- Privilege boundary aware
- Risk focused

### Cache Aware
- Avoids repeating loud operations
- Faster and safer

### Readable
Output should teach, guide, and support clear thinking.  
Not overwhelm.

### Explain First
Nullpeas does not execute exploitation.  
It explains, teaches, and supports reasoning.

---

## Architecture Overview

    brain.py            Orchestrator
    core/cache.py       Persistent state
    core/report.py      Markdown writer
    core/guidance.py    Reasoning engine

    probes/*            Host intelligence collectors
    modules/*           Risk analysis logic

    cache/state.json
    cache/nullpeas_report.md

---

## Screenshots and Demo

Coming soon.

Planned examples:
- Terminal summary
- Markdown report excerpt
- Reasoning block example
- Short execution demo

---

## How To Run

    git clone https://github.com/Null0x-sh/Nullpeas
    cd Nullpeas
    chmod +x brain.py
    ./brain.py

Report output:

    cache/nullpeas_report.md

---

## Example Behaviour

Nullpeas can:

- Detect sudo privilege surfaces
- Detect Docker escape potential
- Detect cron abuse paths
- Detect container environments
- Trigger relevant reasoning modules
- Produce structured Markdown reports

---

## Roadmap

- LXD and LXC analysis
- PATH hijack detection
- Linux capabilities analysis
- Systemd and service misconfiguration logic
- Kernel exploit reasoning only
- OPSEC and stealth improvements
- UX improvements
- CI and automated testing
- Community extension support

---

## Contributing

Contributions, discussion, and learning collaboration are welcome.  
This project is part of a personal learning journey, and community involvement is encouraged.

---

## Ethics

Nullpeas exists to:

- Teach
- Improve defenders
- Assist authorised red teamers
- Help newcomers learn responsibly

It is not intended for illegal activity.

---

## Closing

Thank you for taking interest in Nullpeas.  
This project will continue to evolve significantly over time.