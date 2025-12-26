# Nullpeas Design Specification (v2.0)
**Living Architecture Document**

This document defines the architectural principles, data flow, and decision-making logic of the Nullpeas Reasoning Engine. It reflects the current v2.0 implementation and guides future development.

---

## 1. Core Philosophy

**Nullpeas is not an enumerator. It is an adversarial reasoning engine.**

* **Actionable Intelligence:** We do not print raw data. We print validated attack paths.
* **Adversarial Logic:** We model the system as a graph of relationships (File A -> Service B -> Root), not a list of files.
* **Safety First:** We probe and reason, but we never exploit. We validate feasibility (e.g., `os.access`) without triggering alarms or corrupting state.
* **Zero Ambiguity:** If we say it is vulnerable, we provide the exact command to exploit it.
* **Operator Control:** The tool is an advisor, not an autopilot. The human makes the final decision.

---

## 2. High-Level Architecture

The system is divided into four distinct layers, operating in a strict pipeline.

### Layer 1: The Eyes (Probes)
* **Role:** Fast, read-only data collection.
* **Behavior:** Non-blocking, threaded, safe.
* **Components:** `probes/sudo_probe.py`, `probes/suid_probe.py`, `probes/path_probe.py`.
* **Output:** Raw State (JSON).

### Layer 2: The Cortex (Modules)
* **Role:** Analysis and primitive generation.
* **Behavior:** Parses raw state, identifies specific weaknesses (Primitives).
* **Components:** `modules/sudo_enum.py`, `modules/cron_enum.py`.
* **Output:** Offensive Primitives (Structured Objects).

### Layer 3: The Logic (Chaining Engine)
* **Role:** Connecting the dots.
* **Behavior:** Graph-based reasoning. Links primitives to goals (e.g., File Write + Service Restart = Persistence).
* **Components:** `core/chaining_engine.py`.
* **Output:** Attack Chains.

### Layer 4: The Hands (Action Engine)
* **Role:** Translation to reality.
* **Behavior:** Maps abstract chains to concrete, copy-pasteable commands.
* **Components:** `core/exploit_templates.py`.
* **Output:** Exploit Cheat Sheet.

---

## 3. The Execution Pipeline

1.  **Initialization:**
    * `brain.py` starts.
    * Checks environment (TTY vs Non-TTY).
    * If Non-TTY (Reverse Shell), enters **Auto-Run Mode**.

2.  **Probe Execution (Parallel):**
    * Probes run in a thread pool.
    * Facts are collected: `uid`, `sudo -l`, `find / -perm -4000`, `crontab -l`.
    * **Triggers** are derived (e.g., `is_container`, `has_compiler`).

3.  **Module Activation:**
    * Orchestrator selects modules based on Triggers.
    * Modules digest raw data and emit **Primitives**.
    * *Example:* SUID Probe finds `/usr/bin/vim`. SUID Module identifies it as a GTFOBin and emits `root_shell_primitive`.

4.  **Chaining & Reasoning:**
    * The Engine ingests all Primitives.
    * It evaluates relationships:
        * *Is this writable file used by a service?*
        * *Is this SUID binary known to spawn shells?*
    * It produces **Attack Chains** ranked by probability and impact.

5.  **Action Generation:**
    * For every High-Confidence Chain, the Action Engine looks up the template.
    * It populates the template with dynamic data (paths, usernames).
    * *Result:* `sudo vim -c ':!/bin/sh'`

6.  **Reporting:**
    * **Terminal:** Immediate "Exploit Cheat Sheet" printed to STDOUT.
    * **Markdown:** Detailed report with Mermaid.js visual attack maps.
    * **JSON:** Structured export for automated ingestion.

---

## 4. State Model

State is a singleton dictionary passed through the pipeline. It is never global, but passed explicitly.

```python
state = {
    "user": { ... },       # Who are we?
    "env": { ... },        # Where are we?
    "triggers": { ... },   # What is interesting?
    "analysis": { ... },   # Human-readable summaries
    "offensive_primitives": [ ... ], # The building blocks of attacks
    "attack_chains": [ ... ]         # The full kill-chains
}
```

---

### The "Primitive" Object
The atomic unit of offensive intelligence.

* **Surface:** Where is it? (Sudo, Cron, Path)
* **Type:** What is it? (`file_write`, `shell_spawn`)
* **Context:** Detailed metadata (File paths, permissions)
* **Affected Resource:** Critical for chaining (e.g., `/etc/shadow`)
* **Exploitability:** Trivial vs Theoretical.

---

## 5. Visualizer Specification

The reporting engine utilizes **Mermaid.js** to render attack graphs.

* **Nodes:** Represent Steps or States (Start, File Write, Root).
* **Edges:** Represent Actions or Dependencies.
* **Styling:**
    * **Purple:** SUID/Binary Vectors.
    * **Orange:** Traps/Hijacking Vectors.
    * **Yellow:** File Write Vectors.
    * **Red:** Goal State (Root).

---

## 6. Safety & Ethics

Nullpeas adheres to strict non-destructive constraints.

* **No modification:** We never write to disk (except `cache/`).
* **No exploitation:** We generate commands; we do not run them.
* **Locale Safety:** All probes force `LC_ALL=C` to prevent parsing errors.
* **Resource Safety:** High-intensity probes (like `find`) exclude volatile paths (`/proc`, `/sys`, `/workspaces`).

---

## 7. Future Roadmap (v2.1+)

* **LXD/LXC Analysis:** Deep dive into container capabilities.
* **Systemd Timers:** Analysis of `.timer` units as alternative persistence.
* **Kernel Exploits:** Smart version comparison against known reliable exploits (e.g., DirtyPipe).
* **Capability Analysis:** Parsing `getcap -r /` for subtle capability-based escalation.
