# Nullpeas Offensive Pivot
A design blueprint for evolving Nullpeas into a **low-noise, pre-exploit offensive engine** that builds real attack chains without ever executing them.

---

## Mission Statement
Nullpeas is transitioning from a conservative analytical assistant into a **serious offensive operator tool**:

> A low-noise, intelligent, pre-exploit engine that discovers, models and ranks real attack chains, builds operator-grade offensive understanding, and provides deeply usable reporting — while never actually exploiting the target.

We sit **one step before execution**:
- No exploitation
- No payload dropping
- No persistence creation

Yet:
- **Attack-minded**
- **Chain-aware**
- **Operator-honest**
- **Bluntly realistic**

If a system is basically “game over”, Nullpeas must say it.

---

## Core Offensive Philosophy

### We Are:
- Quiet
- Intelligent
- Chain-oriented
- Operator-focused
- Realistic
- Educational **but** offensive-truth first

### We Are Not:
- A blind dump script
- A corporate vulnerability scanner
- An exploit runner
- A noisy red team toy

Nullpeas should feel like:
> “An exploit engine frozen seconds before impact.”

---

## Dual Personality Model

Nullpeas will support two high-level reasoning modes:

### Mode A — **Conservative / Analytical**
Current default mode:
- risk explanation
- defensive remediation
- calm narrative

### Mode B — **Offensive / Operator**
New offensive brain:
- aggressive attack intelligence
- chain reasoning
- feasibility modelling
- “raised eyebrow, serious tool” vibe

Both modes use the same probes and data,
but interpret them differently.

---

## Core Offensive Architecture

### New Required Components

#### 1️⃣ `chaining_engine.py`
Responsible for:
- collecting exploit primitives from modules
- constructing attack chains
- ranking chains
- assessing:
  - exploitability
  - stability risk
  - OPSEC noise
- feeding offensive reports

This is where Nullpeas becomes **intelligent**.

---

#### 2️⃣ Knowledge Integration Engine
A dedicated module (or internal core component) responsible for linking intelligence to surfaces:

- GTFOBins knowledge
- sudo exploitation patterns
- container escape research
- privilege primitives catalog
- CVE awareness for key escalation surfaces (safe, no exploit code)
- real-world escalation relevance context

Purpose:
- make findings **offensively meaningful**
- turn surfaces into **power**
- differentiate theoretical vs field-proven abuse

Name ideas:
- `intelligence_engine.py`
- `offense_knowledge.py`
- `threat_context.py`

This engine does NOT:
- exploit
- download payloads
- execute code

It purely feeds **intelligence + realism**.

---

## Exploit Primitives

Modules will no longer only produce “findings”.
They will emit **offensive primitives**.

A primitive represents a usable **attacker capability**.

Examples:

- `root_shell_primitive`
- `arbitrary_command_execution`
- `arbitrary_file_write`
- `arbitrary_file_read`
- `service_hijack_primitive`
- `cron_exec_primitive`
- `docker_host_takeover`
- `lxd_escape_primitive`
- `kernel_exploit_surface`
- `credential_loot_primitive`
- `environment_poisoning_primitive`

Each primitive includes:

- surface (sudo, cron, docker, filesystem, etc.)
- who execution becomes
- stability estimate
- noise profile
- exploitability ranking
- context conditions

Primitives feed into the chaining engine.

---

## Offensive Chain Reasoning

Current Nullpeas: evaluates things individually  
Future Nullpeas: **thinks like an attacker**

Chains link primitives for real escalation logic:

### Examples

#### Sudo + PATH
PATH control + sudo env binary
→ trivial arbitrary command execution
→ likely root
→ low noise, very real world

---

#### Sudo File Write + Systemd
sudo → arbitrary file write  
filesystem → writable unit  
systemd → reload  
→ persistent privileged execution
→ serious offensive outcome

---

#### Docker + Host Socket
docker sudo entry OR docker group  
docker surface says host access feasible  
→ immediate host takeover
→ realistically catastrophic

---

#### Cron + Writable Script
cron executes as root  
filesystem says writable  
→ delayed but guaranteed execution

---

Chains must include:
- achievable **goal** (root shell, persistence, lateral movement)
- feasibility
- realism
- priority

---

## Offensive Scoring Model

Offensive Nullpeas evaluates like operators:

### Exploitability
- Trivial
- Moderate
- Advanced
- Theoretical

### Stability Risk
- Safe
- Potential disruption
- Crash possible
- Dangerous

### Noise / OPSEC
- Silent
- Likely unnoticed
- Noticeable
- Alert risk

This is something linPEAS does NOT do.
This is a strategic competitive advantage.

---

## Reporting: Still Our Killer Feature

Offensive Mode report retains:
- beautiful structure
- Markdown clarity
- actionable intelligence

But tone changes:

- Real attacker truth
- Brutally honest
- Direct
- Professional but not timid

### Offensive Report Layout

1) **Offensive Summary**
- Is this host basically lost?
- Most realistic path to root
- Count of trivial chains

2) **Top Attack Chains**
Each includes:
- Goal
- Steps
- Exploitability / Noise / Stability
- Offensive narrative
- Blue Team takeaway

3) **Primitive Inventory**
Table of discovered offensive powers.

4) **Reflection for Defenders**
Because ethics still matters.

---

## Stealth Guarantee

Even in offensive brain mode:

- No exploitation
- No privilege tampering
- No persistence
- No noisy tests
- No forced execution probes

Nullpeas remains:
- quiet
- surgical
- disciplined

Reasoning replaces loudness.

---

## Required Development Plan

### Phase 1 — Core Framework
- [ ] Create `chaining_engine.py`
- [ ] Create offensive knowledge module
- [ ] Define Primitive Schema
- [ ] Define Chain Model
- [ ] Implement offensive scoring model

---

### Phase 2 — Module Integration
- [ ] Update sudo module to emit primitives
- [ ] Update cron module
- [ ] Update docker module
- [ ] Add additional surfaces as needed

---

### Phase 3 — Offensive Report
- [ ] Build new offensive report block
- [ ] Support dual-mode narrative
- [ ] Add ranking and summary logic

---

### Phase 4 — Trust Building
- [ ] EXTREME clarity that Nullpeas does not exploit
- [ ] Professional write-up explaining design ethics
- [ ] Encourage Red + Blue team adoption

---

## Vision Summary

Nullpeas will become:
- Quiet like a ghost
- Intelligent like a senior operator
- Honest like a red team veteran
- Useful like a consulting deliverable
- Respectable in offensive world
- Trusted in defensive world

Nullpeas evolves into the **tool we wish existed**:
A pre-exploit brain capable of real offensive reasoning and chain orchestration,
without crossing the execution line.

This is our offensive future.