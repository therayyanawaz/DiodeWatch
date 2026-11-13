## What this changes

<!-- One paragraph. Say what a reader of the diff would not guess. -->

## Why

<!-- The failure this prevents, or the capability it adds. If it fixes a bug,
     say how the bug was observed (a test, a real run, a browser). -->

## Evidence

<!-- How you proved it. Paste the command you ran and its result line.
     - tests: `python -m pytest tests/ -q`
     - docs/UI copy: `python -m scripts.checks.check_claims`
     - lint: `python -m ruff check src/ scripts/ tests/ apps/ waf/`
     - UI that can be painted: the panel you read back in a browser -->

```
$ 
```

## Checklist

- [ ] Every number I added to a user-facing surface comes from a measurement in
      this tree (`scripts/checks/check_claims.py` passes).
- [ ] No channel claims more confidence than its quality gate allows, a channel
      that cannot meet its gate disables itself and says so.
- [ ] No zero is printed that the host did not observe.
- [ ] If I touched `frontend/`, I rebuilt and committed the bundle in
      `apps/mission_control/static/`.
- [ ] I did not edit the derived evaluation artifacts by hand.
