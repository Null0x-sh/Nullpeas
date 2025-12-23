# Nullpeas Module Architecture & Design Standard

This document defines how every Nullpeas module must be designed, behave, reason, and report, now and in the future.

It exists so Nullpeas remains:
- quiet
- intelligent
- chain-capable
- brutally honest
- professional and credible

Nullpeas modules are not scanners.
They are thinking offensive intelligence components.

---

## Core Philosophy

Every module must:

- Think like an operator, not a checklist
- Provide actionable intelligence, not noisy dumps
- Convert findings into offensive primitives
- Fuel the chaining engine
- Speak truthfully about risk
- Maintain ethical and auditable behaviour
- Enable defenders to remediate confidently

If linPEAS lists it, Nullpeas must:
- know it
- interpret it better
- place it in an attack chain
- explain it like a real operator

---

## Scope and Safety Boundaries

Modules DO:
- enumerate carefully and safely
- analyse deeply
- reason like an attacker
- classify capability and exploitation realism
- produce structured offensive primitives
- provide navigation guidance
- provide defensive remediation guidance
- support professional reporting

Modules DO NOT:
- exploit
- modify system state
- spawn shells
- brute force
- inject payloads
- behave like malware
- provide ready exploit commands

Nullpeas is a pre-exploit offensive brain, not a weapon.

---

## Module Responsibilities

Every module must:

1. Safely enumerate its surface
2. Extract structured intelligence
3. Classify capabilities
4. Assign risk categories
5. Score severity and confidence
6. Generate offensive primitives
7. Feed the chaining engine
8. Produce human-readable intelligence
9. Provide remediation guidance
10. Maintain a serious and professional tone

If a module does not do all ten, it is not finished.

---

## Inputs and Integration

Modules consume structured probe data from state.

Examples:
- state["sudo"]
- state["cron"]
- state["runtime"]
- state["filesystem"]
- state["services"]

Modules declare required triggers:

@register_module(
  key="sudo_enum",
  required_triggers=["sudo_privesc_surface"]
)

If a surface is unavailable the module must:
- exit cleanly
- explain why
- avoid noisy reporting

---

## Capability Classification

Capabilities define what a finding can realistically do.

Examples:

- shell_spawn
- file_write
- file_read
- platform_control
- scheduled_execution
- service_control
- container_escape
- credential_access
- persistence
- environment_abuse

Capabilities directly influence:
- tone
- severity
- chain logic
- remediation language

---

## Risk Categories

Capabilities describe what something can do.
Risk categories describe why it matters.

Examples:

Sudo
- global_nopasswd_all
- interpreter_nopasswd
- wildcard_path_rule
- env_abuse_risk

Cron
- root_cron_execution
- writable_cron_script
- timed_execution_surface

Docker
- daemon_access
- socket_world_writable
- docker_escape_feasible

Systemd
- writable_unit
- privilege_boundary_break
- persistence_surface

PATH
- writable_path_directory
- execution_hijack_surface

Filesystem
- sensitive_file_write
- shadow_adjacent_surface

Capabilities
- cap_sys_admin_boundary_break
- execution_capability

Kernel
- kernel_exploit_surface

Credentials
- credential_loot_surface

A finding may have multiple risk categories. That is expected.

---

## Severity and Confidence Model

Every finding must contain severity and confidence.

Severity:
- numeric score 0.0–10.0
- band: Low, Medium, High, Critical
- how much power the finding realistically grants

Confidence:
- numeric score 0.0–10.0
- band
- how likely it is actually exploitable

Severity considers:
- privilege level gained
- breadth of control
- stability risk
- exploit realism

Confidence considers:
- binary existence
- environmental dependencies
- whether prerequisites are present
- ambiguity

Nullpeas must confidently and honestly state risk level. No needless fear and no understatements.

---

## Offensive Primitive Output

Modules must output structured offensive primitives for the chaining engine.

Examples:

- root_shell_primitive
- arbitrary_command_execution
- arbitrary_file_write
- docker_host_takeover
- platform_control_primitive
- path_hijack_primitive
- cron_exec_primitive
- service_hijack_primitive
- capability_boundary_break
- kernel_exploit_surface
- credential_loot
- container_escape_surface

Each primitive must include:

- primitive_id
- primitive_type
- severity classification
- exploitability truth
- stability assessment
- OPSEC noise impact
- dependent surfaces
- reasoning text

Nullpeas is honest about exploit reality:

Example truths:
- Exploitability: trivial
- Exploitability: requires manipulation
- Exploitability: advanced
- Exploitability: theoretical

---

## Navigation Guidance

Navigation guidance describes thinking, not commands.

It explains:
- why the surface matters
- what a capable operator would conceptually explore
- what kind of control it implies

It must never:
- list payloads
- give commands
- act as a how-to exploit guide

Tone should be professional, calm, and explanatory.

---

## Defender Remediation Guidance

For meaningful findings, modules must:
- explain what is wrong
- explain why it matters in reality
- provide realistic remediation
- explain what “secure” looks like

Language must:
- be professional
- be direct
- avoid drama

Nullpeas must be credible for blue teams.

---

## Reporting Responsibilities

Modules do not fully render reports. They:
- supply structured findings
- supply intelligence
- supply primitives
- supply reasoning

The reporting engine handles:
- layout
- formatting
- hierarchy
- summaries

---

## Ethical Boundary Policy

Nullpeas modules must never:
- exploit
- provide exploit PoCs
- automate hostile behaviour
- modify systems

Nullpeas exists to:
- educate
- support authorised red teams
- support defenders
- improve security maturity

Nullpeas provides the brain, not the weapon.

---

## Outcome

A correct Nullpeas module is:

- intelligent
- meaningful
- trusted by serious operators
- useful to defenders
- chain-aware
- offensively truthful
- ethically aligned
- quiet and precise

Modules power:
- offensive truth
- realistic escalation understanding
- structured chain reasoning
- serious reporting
- responsible use

Nullpeas is evolving into a pre-exploit offensive decision engine.