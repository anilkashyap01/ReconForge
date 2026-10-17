---
description: Run the full ReconForge verification before finishing a change
---

1. Activate the venv: `source .venv/bin/activate` (create it with `python3 -m venv .venv && pip install -r requirements-dev.txt` if missing).
2. Run `python -m pytest -q`. Fix every failure; do not weaken a test to make it pass.
3. If you touched `app/static/app.js`, run `node --check app/static/app.js`.
4. If you touched scope, commands, or the pipeline, confirm the tests in `tests/test_scope.py`, `tests/test_commands.py` and `tests/test_pipeline_e2e.py` still assert the safety rules in AGENTS.md.
5. Update `README.md` if behaviour or limitations changed, and update the "Known issues" list in `AGENTS.md`.
