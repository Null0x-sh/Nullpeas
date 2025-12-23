# Nullpeas Future Module Coverage

This document defines what all future Nullpeas modules must eventually cover in order to rival (and surpass) linPEAS in practical offensive capability, while retaining Nullpeas core traits:

- Low noise and stealth-first
- Intelligence and reasoning-driven
- Chain-capable
- Professional and report-usable
- Offensive truth, not corporate caution

Current modules are intentionally conservative. Future modules must assume an attacker mindset first.

---

## 1. Philosophy for Coverage

Coverage is the reason linPEAS dominates.

Nullpeas modules must aggressively enumerate every realistic local privilege escalation surface, BUT:

- Without blasting the host
- Without dumping everything blindly
- Without being afraid to call a system "basically owned"
- With the ability to translate findings into exploit primitives
- With enough structure to fuel the chaining engine

If linPEAS finds it, Nullpeas must:

- Know it exists
- Interpret it better
- Place it in an attack chain
- Present it like a real operator would think

---

## 2. Required Coverage Categories

Nullpeas modules must eventually cover and reason deeply about the following surfaces.

### 2.1 Sudo and Privileged Command Surfaces

Status: In progress  
Goal: Offensive, chain-aware, brutally honest

Must eventually include:

- Full sudoers semantics
- NOPASSWD detection
- Restricted binary analysis
- Wildcards and argument-based abuses
- GTFOBins offensive mapping
- SETENV and environment abuse
- User-controlled paths
- Sudo version CVE awareness
- Direct chain relevance

Output primitives should include, for example:

- `root_shell_primitive`
- `arbitrary_command_execution`
- `arbitrary_file_write_primitive`

The module must explain:

- Why a given rule is escalation-prone
- How realistic and stable the abuse is
- How it links into other surfaces (PATH, filesystem, interpreters, services)

---

### 2.2 SUID / SGID Escalation Surfaces

Must enumerate and reason like linPEAS, but cleaner and quieter:

- List privileged SUID / SGID binaries
- Detect exploitable SUIDs
- GTFOBins awareness
- Dangerous legacy binaries
- Non-standard privilege boundaries
- Writable SUID-based chain escalation
- Binary validation and existence checks

Output primitives:

- `suid_shell_spawn`
- `suid_file_write`
- `suid_environment_abuse`

Each primitive must describe:

- Reliability (how likely it is to work)
- OPSEC noise (how visible it is)
- Realism (would a real attacker actually use this)

---

### 2.3 PATH Hijacking and Execution Flow Abuse

Critical for serious offensive parity.

Must detect:

- Writable directories in `PATH`
- PATH order weaknesses
- Predictable PATH hijack chains
- PATH issues combined with sudo
- Shadowed binaries

Should identify clear attacker opportunities:

- Execution replacement
- Privilege inheritance chaining

Output primitives:

- `path_hijack_primitive`
- `binary_shadow_primitive`

---

### 2.4 Capabilities Abuse

Linux capabilities are serious escalation surfaces and must not be treated as a niche curiosity.

Must cover:

- `CAP_SYS_ADMIN` heavy abuse awareness
- Dangerous capability assignments
- Practical escalation mapping
- Real-world exploitability signals

Output primitives:

- `capability_privilege_boundary_break`
- `capability_shell_primitive`
- `capability_platform_control`

These must be explained offensively, not academically.

---

### 2.5 Cron and Scheduled Execution Abuse

Must go beyond conservative checks.

Detect:

- Root cron jobs
- Writable cron scripts
- Writable cron execution paths
- User-owned cron executables that affect privileged contexts
- Timing feasibility (how soon and how often)
- Stealth value (how noisy execution is in practice)

Output primitives:

- `cron_exec_primitive`
- `cron_timed_execution`
- `cron_persistence_primitive`

Offensive expectations:

- Delayed but guaranteed execution paths
- Persistence evaluation and quality
- Combination with filesystem and PATH weaknesses

---

### 2.6 Systemd and Service Misconfiguration

Must understand:

- Writable systemd unit files
- Service privilege boundaries
- Execution order and reload / restart feasibility
- Realistic exploitation practicality

Output primitives:

- `service_hijack_primitive`
- `persistent_root_execution`

These must combine with sudo, filesystem