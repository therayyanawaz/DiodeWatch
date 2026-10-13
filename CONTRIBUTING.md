# Contributing

Interest in contributing is welcome — note that the project is
**proprietary** (see `LICENSE`): contributions accepted via pull request
grant the repository owner the right to include them under the project
license.

## Development setup

```bash
git clone https://github.com/therayyanawaz/DiodeWatch.git
cd DiodeWatch
bash setup/setup.sh          # or setup\setup.bat on Windows
.venv/bin/python -m pytest tests/ -q
```

## Ground rules

1. **Every claim must trace to code or `results/`.** If you add a number to
   any user-facing surface, add the measurement that produced it.
2. **Run the claim guardrail before committing docs/UI copy changes:**
   `python -m scripts.checks.check_claims`. CI enforces it — unqualified
   maturity or accuracy claims are rejected by design, and the approved /
   banned wording lock lives in
   [docs/competition/readiness.md](docs/competition/readiness.md).
3. **Fail closed.** If a detector channel cannot meet its quality gate on
   new data, it must disable itself and say so — never emit low-confidence
   guesses.
4. **Never fake a zero.** The diode proof must always reflect the real
   enforcement mode of the machine it runs on.
5. **Tests and lint green:** `pytest tests/ -q` and
   `python -m ruff check src/ scripts/ tests/ apps/ waf/` must pass before
   any commit. That is CI's scope verbatim — a narrower list can hide a
   finding CI raises on Linux, which is how one `EXE001` (shebang without
   exec bit) reached the workflow. Note `EXE001` cannot fire on Windows:
   there is no exec bit to miss, so file-mode checks only ever fail in CI.

## Commit style

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `chore:`) with a
body that explains *why*.
