# Nullpeas Design Specification

> This document describes **how** Nullpeas is intended to work:
> Architecture
> Data flow
> Execution modes
> Decision logic
> Design constraints
>
> It is a living document and will evolve as the project grows over time.

---

## Design Princibles

-**Manual-first**
Operator should always be able to choose exactly what runs.

-**Signal over noise**
Prefer a few high value findings over huge unreadable dumps.

-**Modular**
Probes and modules should be pluggable, small and independent

-**Guided, not fully autonomous**
Nullpeas suggests escalation paths and modules to run dependent on findings; the operator approves  or declines

-**Ethical and transparent**
Built for authorised testing, learning and defensive validation

-**Seperation of concerns**
Cache (machine data) and reports (humand readable output) are seperate.

---

## High level Architecture

### Repository layout (current+planned)
```text
brain.py  #main entrypoint / orchestrator

nullpeas/     # Python package
    __init__.py
core/ 
    __init__.py
    cache.py  # read/write state.json (machine cache)
    # (future) reporting.py, triggers.py, cli.py
probes/
  __init__.py
  users_groups_probe.py # first probe user, uid, groups.
  # (future) env_probe.py, sudo_probe.py, cron_probe.py, docker_probe.py
modules/
   __init__.py # (future)
# (future) docker_escape.py, sudo_escalation.py, cron_abuse.py etc.
cache/
   state.json # runtime cache (generated, not committed)
docs/
ROADMAP.md
DESIGN.md
```
---

## Date flow overview

1. Operator runs Nullpeas
   ```text
   chmod +x brain.py
   ./brain.py
   ```
2. Base probes execute
   - Collect envrionment info (user, uid, groups, OS, kernel, etc)
   - Store structured results into an in-memory state dictionary.

3. State is cached
   - nullpeas.core.cache.save_state(state)
   - Writes cache/state.json with schema_version+data

4. Decision engine (future)
   - Inpspects state and sets triggers for potential escalation paths
   - In guided mode, prompts operator for each trigger.

5. Modules (future)
   - When approved by the operator, depth modules run.
   - They add deeper findings back to state (and eventually reports)

6. Reporting (future)
   - A reporting layers converts state into human-readable Markdown/HTML

---

## State structure

Example (simplified):
```text
{
  "schema_version": 1,
  "state": {
    "user": {
      "name": "codespace",
      "uid": 1000,
      "groups": ["codespace", "docker", "sudo"],
      "raw_id_output": "uid=1000(codespace) gid=1000(codespace) groups=..."
    },
    "env": {
      "hostname": "devbox",
      "os": "Ubuntu",
      "kernel": "5.15.0-xyz",
      "raw_uname": "Linux devbox 5.15.0-xyz ..."
    },
    "triggers": {
      "docker": true,
      "sudo": false,
      "cron": true
    },
    "findings": {
      "docker": [],
      "sudo": [],
      "cron": []
    }
  }
}
```

Key concepts
- schema_version - aalows future backwards compatible changes.
- state["user"] - who we are, uid, groups, raw backing data
- state["env"] - OS/kernel/env context (future)
- state["triggers"] - boolean flags for potential escalation paths.
- state["findings"] - deeper module results keyed by area.

---

### Probes vs Modules

Probes
- Cheap, read only enumeration
- Populate state with context and basic facts
- Should not perform risky or noisy actions.
- Examples
  - users_groups_probe
  - env_probe (hostname, OS, Kernel)
  - sudo_probe (sudo -l)
  - cron_probe (cron paths, permissions)
  - docker_probe (docker group, docker socket, etc)

Interface (conceptual)
```text
def run(state: dict) -> None:
    """Read data from system and mutate state in place."""
```

Modules (future)
- Deeper analysis focused on specific escalation areas.
- Use data from state rather than re-enumerating
- Should explain why something is interesting.
- Examples:
  - docker_escape module
  - sudo_escalation module
  - cron_abuse module
  - path_hijack module
  - kernel_exploitability module

Interface (conceptual):
```text
def is_relevant(state: dict) -> bool:
    """True if this module should be considered based on current state."""

def run(state: dict) -> None:
    """
    Perform deeper checks and append findings into state["findings"][module_name].
    """
```

---


### Execution Modes
Nullpeas is intended to support three main execution styles.

## Manual Mode (Always Available)

Operator explicitly chooses what to run.
Example (future CLI):
```text
nullpeas probe users
nullpeas probe env
nullpeas module docker_escape
```

Characteristics:
- Maximum control
- Useful for stealth and training
- No automatic decision-making

## Guided interactive mode (Primary feature)

Flow:
- Run base probes.
- Evaluate state and set state["triggers"].
- For each active trigger, prompt the operator:
  - explain what was detected
  - ask whether to run a deeper module
- Run the module if user answers y.

Pseudo-flow:
```text
def guided_mode(state: dict) -> None:
    run_base_probes(state)
    compute_triggers(state)

    for name, active in state.get("triggers", {}).items():
        if not active:
            continue

        answer = input(f"[+] Trigger detected ({name}). Run module? (y/n): ")
        if answer.lower().startswith("y"):
            run_module_by_name(name, state)
```
Example user experience:

```text
[+] Potential escalation paths detected

Docker group membership discovered.
Run docker escape investigation module? (y/n): y

Writable cron directories detected.
Run cron abuse investigation module? (y/n): n

Sudo privileges detected.
Run sudo detailed analysis? (y/n): y
```

This mode:
- keeps the operator in control
- reduces noise
- guides less experienced users
- reflects realistic red-team decision-making (I hope)

## Full auto mode

Runs all relevant probes and modules without prompting.

Example (future):
```text
nullpeas auto
```

Characteristics:
- Maximum coverage
- No interactivity
- Best suited for labs and non-stealth scenarios

---

## Cache vs Reports

Cache (cache/state.json)
- Machine-facing.
- JSON only.
- Stable schema.
- Used for:
  - incremental reruns
  - deeper module evaluation
  - automation and scripting
  
Example content was shown in the State Structure section.

Reports (reports/*.md, future)

- Human-facing.
- Markdown first, possibly HTML later.
- Summarized and actionable.

Planned structure (conceptual):
```text
# Nullpeas Report

## Summary

- User: codespace (uid=1000)
- Potential escalation areas:
  - Docker (HIGH)
  - Cron (MEDIUM)

## Findings

### Docker (HIGH)

- User is in `docker` group.
- Docker socket accessible at `/var/run/docker.sock`.
- This typically allows root via container abuse.

Suggested next steps:
- Attempt controlled container escape (ONLY in authorized environments).
- Review Docker daemon configuration.

### Cron (MEDIUM)

- Writable cron path: `/var/spool/cron/crontabs/...`

...
```
Reports are generated from the cached state, not from scratch.

---

## Error Handling & Safety

Probes and modules should never crash the entire tool.
- On failure, they should:
  - log an error into state
  - preserve any partial useful data
  - allow the rest of the tool to continue

Example pattern:
```text
try:
    # risky or external call
except Exception as e:
    state.setdefault("errors", []).append(
        {"probe": "users_groups", "error": str(e)}
    )
    return
```

---

## Coding & Style Guidelines (Initial)

Python 3 only.
- Prefer clear, explicit code over clever one-liners.
- Avoid unnecessary external dependencies where possible.
- Use type hints (Dict[str, Any], list[str], etc.) where helpful.
- Keep probes small and focused.
- Keep modules focused on one escalation area each.
- Add comments (as im learning so i can follow along)

---

## Design Status

This document describes the intended behavior and structure of Nullpeas.
Implementation will follow in iterative steps as outlined in docs/ROADMAP.md.

It’s expected that:
- names may evolve,
- structures may refine,
- and some parts will be updated as experience and feedback accumulate.

The key is to keep the principles stable:
manual control, modularity, guided escalation, and ethical use.

---
