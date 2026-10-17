# ReconForge safety rules (always apply)

- Only authorised, in-scope targets. Scope checks live in backend code (`app/scope.py`, `ScanRun.revalidate`, `ScanRun.scope_filter`). Never bypass them.
- Subprocesses: argv lists via `create_subprocess_exec` only. No `shell=True`, no string-built commands, no unvalidated user values in argv.
- No automatic destructive, DoS, brute-force or intrusive tests. Keep defaults conservative (2 req/s, one target-touching tool at a time).
- Scanner detections are potential findings until an analyst confirms them. No fake data, no invented API responses.
- Never log, render, or ship secrets. Never use innerHTML with data. Tests must not run real scans or use the network.
