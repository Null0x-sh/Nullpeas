# Nullpeas Future Module Coverage
This document defines **what all future Nullpeas modules must eventually cover** in order to rival (and surpass) linPEAS in practical offensive capability — while retaining Nullpeas core traits:

- Low noise and stealth-first
- Intelligence and reasoning-driven
- Chain-capable
- Professional and report-usable
- Offensive truth, not corporate caution

Current modules are **too conservative**.  
Future modules must assume an **attacker mindset** first.

---

## Philosophy for Coverage
Coverage is the reason linPEAS dominates.

Nullpeas modules must aggressively enumerate every realistic local privilege escalation surface, BUT:

- Without blasting the host
- Without dumping everything blindly
- Without being afraid to call a system “basically owned”
- With the ability to translate findings into **exploit primitives**
- With enough structure to fuel the chaining engine

If linPEAS finds it, Nullpeas must:
1) Know it exists
2) Interpret it better
3) Place it in an attack chain
4) Present it like a real operator would think

---

# Required Coverage Categories

Nullpeas modules must eventually cover and reason deeply about:

---

## 1️⃣ Sudo & Privileged Command Surfaces
Already started, but must eventually include:

- Full sudoers semantics
- NOPASSWD detection
- restricted binary analysis
- wildcards and argument-based abuses
- GTFOBins offensive mapping
- SETENV / environment abuse
- user-controlled paths
- sudo version CVE awareness
- direct chain relevance

Output must include offensive primitives like:
- `root_shell_primitive`
- `arbitrary_command_execution`
- `arbitrary_file_write_primitive`

Status: In progress  
Goal: Offensive, chain-aware, brutally honest

---

## 2️⃣ SUID / SGID Escalation Surfaces
Must enumerate and reason like linPEAS but cleaner:

- list privileged SUID / SGID binaries
- detect exploitable SUIDs
- GTFOBins awareness
- dangerous legacy binaries
- non-standard privilege boundaries
- writable SUID chain escalation
- binary validation and existence checks
- distinguish:
  - “instant root shell”
  - “file write primitive”
  - “indirect escalation”

Output primitives:
- `suid_shell_spawn`
- `suid_file_write`
- `suid_environment_abuse`

Must explain:
- reliability
- OPSEC noise
- realism

---

## 3️⃣ PATH Hijacking & Execution Flow Abuse
Critical for serious offensive parity:

Must detect:
- writable directories in PATH
- PATH order weaknesses
- predictable PATH hijack chains
- PATH combined with sudo
- shadowed binaries

Should identify clear attacker opportunities:
- execution replacement
- privilege inheritance chaining

Output primitives:
- `path_hijack_primitive`
- `binary_shadow_primitive`

---

## 4️⃣ Capabilities Abuse
Linux capabilities are serious escalation surfaces.

Must cover:
- CAP_SYS_ADMIN heavy abuse awareness
- dangerous capability assignments
- practical escalation mapping
- real-world exploitability signals

Output primitives:
- `capability_privilege_boundary_break`
- `capability_shell_primitive`
- `capability_platform_control`

Must be explained offensively, not academically.

---

## 5️⃣ Cron / Scheduled Execution Abuse
Must be far more serious than conservative checks:

Detect:
- root cron jobs
- writable cron scripts
- writable cron execution paths
- user-owned cron executables
- timing feasibility
- stealth value

Output primitives:
- `cron_exec_primitive`
- `cron_timed_execution`
- `cron_persistence_primitive`

Offensive expectations:
- delayed but guaranteed execution paths
- persistence evaluation

---

## 6️⃣ Systemd / Services Misconfiguration
Must understand:

- writable systemd units
- service privilege boundaries
- execution order
- reload/restart feasibility
- realistic exploitation practicality

Output primitives:
- `service_hijack_primitive`
- `persistent_root_execution`

Combined with sudo / filesystem leads to lethal chains.

---

## 7️⃣ Docker / Containers / Virtualization Escape
Must realistically evaluate:

- docker group membership
- socket access
- sudo + docker access
- LXC / LXD escape feasibility
- container vs host awareness
- break out risk assessment

This is often:
> “Basically root”

Output primitives:
- `docker_host_takeover`
- `lxd_escape_primitive`
- `container_breakout_surface`

Noise, reliability, and real-world severity must be explicitly stated.

---

## 8️⃣ Filesystem Weakness & Misconfig Privileges
Must discover offensive opportunities:

- world-writable sensitive files
- writable configuration files
- shadow-adjacent abuse opportunities
- log file privilege pivot
- library preload paths
- socket exploitation pivots

Output primitives:
- `arbitrary_file_write`
- `privileged_file_overwrite`
- `library_hijack_surface`

Must integrate with sudo / cron / systemd / PATH.

---

## 9️⃣ Kernel Exploit Surfaces (Explain-Only)
Nullpeas will:

- detect exploitable kernel ranges
- map to known escalation vectors
- distinguish realistic from fantasy
- never run exploits

Output primitives:
- `kernel_exploit_surface`

But will honestly say:

- stability risk
- potential system crash
- noise level
- reality of modern mitigations

---

## 🔟 Credential & Secret Prize Hunting
Must discover exploitable advantages:

- SSH keys exposure
- readable private keys
- cached credentials
- auth tokens

Output primitives:
- `credential_loot`
- `pivot_potential`

This is critical for lateral movement and staging chains.

---

# Coverage Expectations Per Module
Every future module must:

### Must Do
- enumerate its surface as completely as safely possible
- identify potential offensive exploitation primitives
- calculate:
  - exploitability
  - stability risk
  - OPSEC noise
- feed primitives to chaining engine
- provide dual narrative:
  - blunt offensive truth
  - defender remediation

### Must NOT Do
- execute exploits
- modify system state
- create persistence
- deploy payloads
- be loud for no reason

---

# Alignment With Offensive Engine
Every module ultimately exists to support:

- `chaining_engine.py`
- offensive reporting engine

Meaning modules must output intelligence in a structured way that can combine realistically into:

- root shell chains
- persistence chains
- privilege boundary breaks
- takeover scenarios
- “this host is basically lost” results

---

# Ultimate Goal
Nullpeas should become:

- trusted by red teamers
- valued by defenders
- respected professionally
- chain-oriented
- brutally honest
- quietly powerful
- offensively aligned
- without ever actually deploying an exploit

This coverage path ensures Nullpeas eventually becomes a viable primary offensive assessment engine, not just a “nice assistant.”

We are no longer conservative.

Nullpeas is evolving into the **pre-exploit brain we wish existed**.