# Nullpeas

**Disclaimer**
> I am currently transitioning into a cybersecurity career and actively learning offensive security, tooling development and software engineering.
> Nullpeas is a both a passion project and learning project - expect evolution, iteration, and improvement over time
> This tool is not being presented as a "professional grade" product (yet).
> It is an education project built to help me deepen my understanding while hopefully helping others to learn alongside me. 

Nullpeas is a modular privilege escalation assistant designed to replace the big monolithic script approach used by other tools - while still trying to retain what makes those tools great.

My idea is to instead of blasting everything at your target at once and getting a large 10k dump of text Nullpeas will
- Collect structered data ('state')
- Caches findings
- Activates only relevant modules dependent on findings
- Focuses on signal over noise
- Goal is to be quiet and stealthy
- Helps guide the operator rather then overwhelm them.

> Nullpeas is for educational / authorised security testing only
> If your are not legally permitted to test a system do not run Nullpeas on it ever.


Current status
- Project structure is built
- Python based probing engine
- Working cache system
- First probe implemented 

Design philosophy
- Modular - individual probes execute independtly
- Smart - modules only run when relevent triggers exist
- Cache-aware - dont rerun loud expensive checks if we have already got the answer
- Readable - output should make the next move obvious
- Open - built to be extended by the community

How to run
Clone the repo and
chmod +x brain.py
./brain.py

Output example ( when run in github codespace )
- Probe completed
- User: codespace
- UID: 1000
- Groups: docker, sudo .....etc

Cache file written to
-cache/state.json

Architecture (High level)
- brain.py (this is the main orestrator)
- core/cache.py (handles saving / loading later state)
- probes/users_groups_probe.py (first probe)
- cache/state.json (runtime cached output)
