# Nullpeas

**Disclaimer**  
> I am currently transitioning into a cybersecurity career and actively learning offensive security, tooling development and software engineering.  
> Nullpeas is both a passion project **and** a learning project - expect evolution, iteration, breaking changes and constant refinement as I grow.  
> This tool is not being presented as a finished “professional grade” product **yet**.  
> It exists to help me learn deeply and hopefully help others learn alongside me.  

> **Nullpeas is for authorised security testing and education only.  
> If you are not legally permitted to test a system, do not run this tool.**

---

## What is Nullpeas?

Nullpeas is a **modular privilege escalation assistant** designed to move beyond the traditional giant noisy Bash script that dumps endless text and leaves the operator overwhelmed.

Instead, Nullpeas takes a **signal-over-noise** approach:

- Collects structured host intelligence and builds shared state  
- Caches findings instead of repeating loud checks  
- Activates only relevant analysis modules  
- Thinks like an operator and explains risk  
- Produces reasoning, not raw noise  
- Is deliberately quieter where possible  
- Designed to **guide, educate and inform**, not overwhelm  

Nullpeas doesn’t just say *“maybe something interesting here”*.  
It tries to explain:

- **Why** something is risky  
- **How attackers reason about it**  
- **What to research next**  
- **How defenders should fix it**  
- **Where to read more (trusted sources)**  

Goal:
> Bridge the gap between “this might be exploitable” and “I understand the full attack and defense story here”.

---

## Current Status

Nullpeas is now a structured, evolving framework.

- Fully structured Python project  
- Multi-probe discovery engine  
- Shared cached state system  
- Trigger driven module system  
- Markdown reporting  
- Ethical reasoning-first approach  

### Actively Working
✔️ Probing engine  
✔️ Threaded execution  
✔️ Trigger logic  
✔️ Cache system  
✔️ Guidance framework  
✔️ Beautiful structured reports  

---

## Implemented Modules

### Sudo Analysis
- Parses `sudo -l`
- Detects passwordless & dangerous configs
- Classifies binary capability categories
- Scores severity + confidence
- Produces attack-chain reasoning
- Operator guidance + defender remediation
- Reference links

---

### Docker Escape / Platform Risk
- Evaluates Docker daemon trust boundary
- Detects socket exposure & user access
- Understands container vs host context
- Assigns platform_control / container_escape
- Scores severity + confidence
- Produces attack-chain logic
- Defensive remediation guidance
- Zero-touch, no Docker interaction

---

### Cron Scheduled Execution Risk
- Reviews cron configuration
- Detects writable cron paths
- Identifies privilege boundaries
- Explains escalation logic
- Produces attacker + defender reasoning

---

## Design Philosophy

### Modular
- Each probe independent  
- Each module only runs when relevant  

### Smart
- Context aware  
- Privilege boundary aware  
- Risk focused  

### Cache-Aware
- Avoid repeating loud operations  
- Faster + safer  

### Readable
Output should:
- Teach  
- Guide  
- Provide insight  
- Make next actions clear  

### Explain-First
Nullpeas is **not**:
- An exploit dropper  
- A weapon builder  

Nullpeas **is**:
- An analyst  
- A teacher  
- A reasoning companion  

Modules do not execute exploits.  
They do not hand payloads.  

They give:
- Attack-chain logic  
- Research direction  
- Navigation guidance  
- Blue-team remediation  
- Reference learning  

Think:
> “Press X To Pwn — but **YOU** must find X.  
> Nullpeas gives every clue, thought process, and resource needed.”

---

## Architecture (High-Level)

brain.py — orchestrator  
• runs probes  
• builds state  
• derives triggers  
• prints summary  
• runs modules  
• writes Markdown report  

core/cache.py — persistent state  
core/report.py — Markdown writer  
core/guidance.py — central reasoning engine  

probes/* → host intelligence collectors  
modules/* → analysis + reasoning units  

cache/state.json → cached runtime data  

---

## How To Run

Clone the repo and execute:

git clone https://github.com/Null0x-sh/Nullpeas  
cd Nullpeas  
chmod +x brain.py  
./brain.py  

---

## Example Behaviour

Nullpeas can:
- Detect sudo privilege surfaces  
- Detect docker escape potential  
- Detect cron abuse paths  
- Detect containerized environments  
- Provide recommendations  
- Trigger relevant modules  
- Produce final Markdown report in:

cache/nullpeas_report.md

---

## Roadmap

- LXD / LXC privilege surfaces  
- PATH hijack chains  
- Linux capability analysis  
- Service + systemd misconfiguration logic  
- Kernel exploit reasoning (explain-only)  
- Better OPSEC + stealth tuning  
- UX improvements  
- Testing / CI in future  
- Community extension support  

---

## Ethics

Nullpeas exists to:
- Teach  
- Improve defenders  
- Assist authorised red teams  
- Help newcomers learn responsibly  

It is NOT built for illegal activity.  
It is a reasoning + educational framework.

---

If you made it this far welcome 👋  
This project is a journey as I grow in cybersecurity and engineering.  
Expect evolution. Expect improvement. Stay tuned.
