## Nullpeas Sudo Advanced Module Design

### Goal

This module is meant to do more than dump `sudo` information.

It should:

- think like an operator,
- reason about escalation chains,
- help juniors understand what is happening,
- still be useful for senior operators and blue teams,
- and always remain ethical and auditable.

The idea is to build **attack chain awareness**, provide **navigation-style guidance**, and clearly explain **remediation**. The module must never automatically exploit or run dangerous actions.

---

### Scope & Safety Philosophy

The `sudo_enum` module:

- **Does**
  - Parse and analyse `sudo -l` output.
  - Identify misconfigurations and escalation *classes*.
  - Assign a severity and a confidence per finding.
  - Link to external references (e.g. GTFOBins) for operator research.
  - Feed structured findings into the central reporting/attack-chain system.

- **Does NOT**
  - Generate exploit one-liners or PoCs.
  - Show shell escapes, LD_PRELOAD tricks, or copy GTFOBins payloads.
  - Run privileged commands on the target.
  - Alter `/etc/sudoers` or any system file.

Nullpeas is a **reasoning and reporting tool**. It educates, guides, and informs – it does not act like malware.

---

### Core Responsibilities

The Sudo Advanced Module is responsible for:

1. **Parsing sudo rules properly**
2. **Resolving binaries cleanly**
3. **Assigning capability categories & risk classes**
4. **Building structured findings**
5. **Scoring severity and confidence**
6. **Building attack chains**
7. **Providing red-team navigation guidance**
8. **Providing blue-team remediation guidance**
9. **Linking to external references (e.g. GTFOBins) safely**
10. **Staying ethical and safe**

All outputs ultimately flow into the central reporting module, which presents:

- offensive actionable context (without PoCs), and  
- defensive remediation paths.

---

### Inputs & Parsing Requirements

**Primary input:**

- `state["sudo"]["raw_stdout"]` – raw output from `sudo -l`.

**Trigger:**

- `sudo_privesc_surface` – set when `sudo -l` data is available.

The parser must handle:

- Single sudo rules
- Multiple commands in one rule
- Wildcards and directory-wide rules (e.g. `/bin/*`, `/home/*/bin/*`)
- Different runas targets (`(root)`, `(ALL)`, specific users)
- `NOPASSWD` vs `PASSWD`
- `Defaults` and `env_keep` lines
- The special case: `(root) NOPASSWD: ALL` and equivalent “ALL” rules

Output of parsing is a list of structured `SudoRule` objects containing:

- raw rule line
- identity (user or `%group`)
- runas target
- whether NOPASSWD applies
- list of command specifications (paths, patterns, arguments)
- any associated options (`Defaults`, `env_keep`, etc.)

If no `sudo -l` output is available, the module should emit a short “No sudo data available” section and exit gracefully.

---

### Binary Resolution

The module can safely:

- Check if a binary exists.
- Resolve its real path (respecting symlinks).
- Optionally run **non-privileged** checks like `binary --version` if useful and safe.

The module must **never**:

- Run binaries via `sudo`.
- Run binaries in ways that could alter system state.
- Run commands that are inherently risky (network changes, service management, etc.).

Binary resolution exists to:

- validate presence (for confidence),
- disambiguate names (e.g. `vim` → `/usr/bin/vim`),
- support environment-aware reasoning.

---

### Capability Categories

Each binary is classified into capability sets that describe what it can realistically do in privilege escalation situations.

Example capability tags:

- `shell_spawn`
- `file_write`
- `file_read`
- `editor_escape`
- `pager_escape`
- `interpreter`
- `service_control`
- `platform_control`
- `backup_tool`
- `devops_tool`
- `monitoring_tool`
- `env_loader_sensitive`

A single binary may have multiple capabilities (e.g. `python` → `interpreter`, `shell_spawn`, `file_read`, `file_write`).

These capabilities feed into:

- risk category assignments,
- severity scoring,
- navigation guidance content.

---

### Risk Categories

Rules are also mapped into higher-level **risk categories**. A single rule may belong to several categories.

Core categories include:

1. **Global NOPASSWD ALL**
   - `(ALL) NOPASSWD: ALL` (user or group)
   - Operationally equivalent to full root.

2. **Dangerous Single Binary**
   - `sudo_editor_nopasswd` (vim, vi, nano, less…)
   - `sudo_interpreter_nopasswd` (python, perl, ruby, node, bash…)
   - `sudo_service_control` (systemctl, service…)
   - `sudo_platform_control` (docker, kubectl, helm, podman…)
   - These are classic escalation instruments when misconfigured.

3. **Wildcards & Directory-Wide Rules**
   - `sudo_wildcard_bin_dir` → `/bin/*`, `/usr/bin/*`, `/usr/sbin/*`
   - `sudo_user_home_bin_dir` → `/home/*/bin/*`
   - `sudo_path_like` → rules that grant sudo to entire directories.

4. **Custom Script / Wrapper**
   - `sudo_custom_script` → scripts under `/usr/local/bin`, `/opt`, etc.

5. **Writable Target / Parent**
   - `sudo_writable_target` → target or parent directory writable by invoking user.

6. **Environment / Loader Abuse**
   - `sudo_env_loader_risk` → `env_keep` on `LD_*`, `PYTHONPATH`, `PERL5LIB`, etc.

7. **Over-Broad Group Rules**
   - `sudo_group_overbroad` → `%sudo` / `%wheel` with `NOPASSWD: ALL` or very broad patterns.

8. **Environment-Specific High-Impact Tools**
   - `sudo_docker_host_control`
   - `sudo_k8s_control`
   - `sudo_devops_control` (ansible/salt/CI agents)
   - `sudo_backup_control`
   - `sudo_monitoring_control`

Risk categories drive:

- how the module describes the issue,
- which navigation guidance is included,
- and how it appears in attack chains.

---

### Findings Structure

Each parsed rule is turned into **one or more structured findings** (per binary / command spec).

A finding should contain at minimum:

- raw sudo rule
- identity (user or group)
- runas target
- binary path and binary name
- whether NOPASSWD applies
- capability tags (from the capability map)
- risk categories (from the risk classifier)
- severity score (0.0–10.0) and band (Low / Medium / High / Critical)
- confidence score (0.0–10.0) and band (Low / Medium / High)
- whether the binary exists & is executable
- any environment notes that affect confidence (e.g. docker.sock present)
- external reference URL(s) (e.g. GTFOBins entry), if applicable

These findings are **data**, not presentation. The reporting layer uses them to build tables and narrative sections.

---

### Severity & Confidence Scoring

Sudo findings are scored along two dimensions:

- **Severity** – potential impact if abused.
- **Confidence** – likelihood this is actually usable on this host.

**Severity inputs (normalised 0.0–1.0 internally):**

- Authentication model (`NOPASSWD` vs `PASSWD`)
- Scope (ALL vs wildcard vs single binary)
- Risk class (editor, interpreter, service/platform control, etc.)
- Privileged file write/replace potential
- Environment/loader risk (`env_keep`, `LD_*` etc.)
- Writability of target / parent directory
- Group-wide impact (e.g. `%wheel`, `%sudo`)

**Confidence inputs:**

- Does the binary actually exist and run?
- Are environment prerequisites present?
  - e.g. `docker` + `docker.sock`
  - `systemctl` + systemd units
  - `kubectl` + kubeconfig
- Any obvious constraints detectable (read-only FS, very locked down layout, etc.)?

The module computes numeric scores (0.0–10.0) and also assigns bands:

- Severity band: `Low`, `Medium`, `High`, `Critical`
- Confidence band: `Low`, `Medium`, `High`

These scores are explained briefly in the report so they are auditable.

---

### GTFOBins External Reference Policy

The module may link directly to **specific GTFOBins entries** for binaries it recognises.

- It maintains a static map: `binary_name -> GTFOBins URL`.
- If `binary_name` is present in this map, the finding gets a `gtfobins_url` field.

**Important constraints:**

- The module does **not** copy, paraphrase, or reconstruct PoCs from GTFOBins.
- It does **not** suggest specific command lines or payloads.
- It only provides a reference link so the operator can research further.

Example report text:

> External reference:  
> GTFOBins entry for `vim`: https://gtfobins.github.io/gtfobins/vim/

This keeps Nullpeas on the ethical edge without crossing into exploit generation.

---

### Attack Chain System

The module builds **logical attack-chain fragments**, not exploit scripts.

Each finding can be expressed as a small chain, for example:

- `current user → sudo (vim NOPASSWD) → privileged file modification`
- `current user → sudo (docker NOPASSWD) → privileged container → host filesystem access`
- `current user → sudo (systemctl NOPASSWD) → service manipulation`

Attack chains are:

- high-level,
- descriptive,
- suitable for reporting.

They are consumed by the central attack-chain/reporting system, which can assemble larger narratives from multiple modules.

---

### Navigation Guidance Packs

Navigation guidance explains **what to explore conceptually inside a tool** – useful for juniors and still helpful for seniors.

The sudo module attaches guidance based on capability classes and risk categories, for example:

#### Editors (vim, vi, nano, ed)

Understand:

- These run with elevated privileges under sudo.
- They can often influence **what** is written and **where**.

Look for:

- Features that execute external commands.
- Scripting or macro systems.
- Subshell capabilities.
- Helper commands that run system tools.

#### Pagers (less, more, man)

Look for:

- Interactive features beyond basic scrolling.
- Ways to leave the normal view into an alternate mode.
- Helper utilities or commands that spawn other processes.
- External integrations (e.g. viewing files, opening editors).

#### Interpreters (python, perl, ruby, lua)

Understand:

- This is a full privileged programming environment.
- It can often:
  - execute system commands,
  - read and write files,
  - interact with the OS.

Look for:

- System execution APIs.
- File read/write APIs.
- Ways to load modules or libraries.

#### Execution Hook Utilities (find, tar, awk, rsync)

Understand:

- These tools execute **other programs** as part of normal operations.
- Under sudo, those hooks may run as root.

Look for:

- Flags that trigger execution hooks (`-exec`, scripts, hooks).
- How those hooks behave under elevated privileges.

#### Platform / Service Tools (docker, systemctl, kubectl, helm)

Understand:

- These control **privileged systems** (containers, services, clusters).
- Running them under sudo often implies host/cluster-level power.

Look for:

- Ability to start/stop or modify services.
- Ability to run workloads with custom configurations.
- Ability to mount or manipulate host resources.

Navigation guidance is written in neutral, explanatory language and never lists literal exploit commands.

---

### Report Output

The module’s output is always routed through the central reporting system.

Expected report content includes:

#### 1. Sudo Misconfiguration Summary

A table that lists:

- Sudo rule (raw)
- Identity (user/group)
- Binary
- Risk categories
- Severity band & score
- Confidence band & score

This gives a quick triage view.

#### 2. Sudo Attack Chains (Detailed Findings)

Each chain / finding should include:

- **Title** (e.g. `NOPASSWD vim as root for user devops`)
- **Sudo rule** (as seen in `sudo -l`)
- **Severity** and a short rationale
- **Capability list** and risk categories
- **Offensive navigation guidance** (conceptual “what to explore”, no PoC)
- **Defensive remediation guidance**
- **Impact explanation** (how this can affect the system in real life)
- **Helpful references** (e.g. GTFOBins URL)

Example wording:

> This rule allows `devops` to run `vim` as root without a password. Vim is a fully interactive editor capable of modifying privileged configuration files and, in many environments, enabling further privileged operations. Misuse of this rule commonly leads to full system compromise.

---

### Safety Boundaries (Explicit)

This module must never:

- run privileged commands,
- spawn shells,
- alter system files,
- attempt to exploit anything,
- integrate with exploit frameworks,
- act like malware or a ready-to-fire exploit kit.

It is a **reasoning and reporting module** only.

---

### Outcome

The end result is a serious, professional-grade sudo analysis module that:

- helps **red teams** plan and prioritise escalation avenues,
- helps **blue teams** identify and fix misconfigurations,
- helps **beginners** understand *why* a rule is dangerous,
- keeps everything ethical, defensible, and enterprise-friendly.
