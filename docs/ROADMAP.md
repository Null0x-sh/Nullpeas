# Nullpeas Roadmap

> This roadmap outlines the development direction of Nullpeas.
> It is intentionally transparent so contributors ( and my future self ) understand priorities, intentions and journey of the project.

---

## Project Vision

Nullpeas aims to become a modular, intelligent privilege escalation assisant that
- Reduces noise
- Guides the operator
- Prioritises meaningful findings
- Supports ethical cybersecurity learning, offense and defense.

It should help:
- Learners understand escalation logic
- Operators move effeciently
- Blue teams validate there system hardening.

# Phase 1 - Foundation (CURRENT)
**Goal:** Get a stable, expandable, well structured base platform.

### Completed
- Repository created
- Ethical + learning focused framing
- Clear README + disclaimers
- Python project structure
- Cache system
- Working first probe (User / UID / Groups)
- Debugging + stable execution confirmed
- initial design planning

### In progress / Near term
- Expand base probe set:
  - Enviroment probe (hostname, OS, Kernel, Env vars)
  - Sudo probe ('sudo -l')
  - Cron discovery probe
  - Docker presence probe
- Establish basic trigger system
- Document early architecture (DONE in DESIGN.md)

---

# Phase 2 - Modular intelligence Layer
**Goal:** Move from "data collection" to guided decision support

### Planned
- Implement 'state["triggers"]' structure
- Intro guided interactive mode:
  - Present detected escalation opportunities
  - Ask operator consent before running deeper modules
- Add optional full auto mode
- Add simple reporting output structure
