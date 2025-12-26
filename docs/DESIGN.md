# Nullpeas Design Specification
Living Architecture Document

This document explains how Nullpeas is designed, how it thinks, how data flows, and how decisions are made. It reflects current implementation and the future direction. It will evolve as Nullpeas matures.

------------------------------------------------------------
Core Philosophy
------------------------------------------------------------

Nullpeas is not a noisy enumeration dump tool.
It is a privilege escalation reasoning engine.

Manual first  
Operator must always remain in control.

Signal over noise  
Prefer meaningful actionable data over thousands of useless lines.

Structured not chaotic  
Everything should be machine-readable intelligence, not random output.

Explain why something matters  
Impact, exploitability, stability, noise, and truth are always explained.

Chains over single surfaces  
Real escalation often requires combining multiple weaknesses, so Nullpeas must recognise that.

Safe and ethical  
No exploitation. No destructive behaviour. Authorised testing only.

------------------------------------------------------------
High Level Architecture
------------------------------------------------------------

brain.py
  Orchestrator and entrypoint

nullpeas/core
  cache.py              State writer/loader
  report.py             Markdown + JSON reporting
  chaining_engine.py    Multi-surface attack chain engine
  offensive_schema.py   Structured primitive definitions

nullpeas/probes
  users_groups_probe.py
  env_probe.py
  sudo_probe.py
  cron_probe.py
  runtime_probe.py

nullpeas/modules
  sudo_enum_module.py
  cron_enum_module.py
  docker_enum_module.py

cache/
  state.json

Generated output
  cache/nullpeas_report.md

------------------------------------------------------------
Execution Flow
------------------------------------------------------------

1) Probes run
They safely collect facts:
who we are, sudo situation, cron exposure, runtime context, docker, etc.
They populate the in-memory state.

2) Triggers are derived
Based on state we infer escalation surfaces such as:
sudo privilege surface
cron privilege surface
docker escape surface
container escape surface

These are deterministic and conservative.

3) Operator chooses modules
Nullpeas does not automatically run heavy modules unless asked.
User can:
run nothing
run individual modules
run everything applicable

4) Modules perform deep reasoning
Modules do not dump output and do not write reports directly.
Instead they enrich:
state["analysis"]
state["offensive_primitives"]

This separation ensures:
modules analyse
chain engine reasons
report formats

5) Attack chain engine runs
It consumes structured offensive primitives and builds real-world escalation chains.
Not theoretical hype.
Not fantasy chains.
Grounded offensive truth.

6) Reports generated
Markdown and JSON are produced.
Reports should read like a calm, experienced consultant wrote them.

------------------------------------------------------------
State Model
------------------------------------------------------------

Core state areas:
state["user"]
state["env"]
state["triggers"]
state["analysis"]
state["offensive_primitives"]

Offensive primitives are structured escalation intelligence.
They include:
surface
capabilities
exploitability
stability
noise
confidence
classification
context
defensive meaning

They represent escalation reality.

------------------------------------------------------------
Probes vs Modules
------------------------------------------------------------

Probes:
cheap
safe
read-only
fact collectors

Modules:
deep reasoning
surface validation
risk modelling
primitive generation
chain candidates

Modules never exploit and never perform changes.

------------------------------------------------------------
Reporting Engine
------------------------------------------------------------

Reports must stay:
clean
truthful
structured
calm
useful

They include:
environment context
per-surface analysis
offensive primitives
attack chains
confidence and truth statements

Reports should double as training material and incident response clarity.

------------------------------------------------------------
Multi-Surface Attack Chain Engine
------------------------------------------------------------

True privilege escalation often requires combining multiple weaknesses.

Phase 1 goal:
deterministic two-hop chains such as:
writable cron + root execution
docker group + daemon control
sudo editor + privileged file write

Scoring considers:
severity
confidence
exploitability
stability
noise realism

No guessing.
No assumptions.
If uncertainty exists, confidence drops.

Phase 2 introduces:
up to three hop chains
weighted certainty
blocker awareness
smarter analysis

------------------------------------------------------------
Safety Guarantees
------------------------------------------------------------

Nullpeas will never:
modify the system
execute payloads
perform exploitation
inflate claims

If unclear:
confidence drops
impact becomes conservative
truth prioritised

------------------------------------------------------------
Status
------------------------------------------------------------

Nullpeas has evolved beyond just enumeration.
It is now a privilege escalation reasoning platform.

Next areas of maturation:
stability
chain expansion
refined UX
stronger primitive library
continued careful evolution, not hype.