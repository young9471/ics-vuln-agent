# Golden protocol cases

`manifest.json` versions the expected lower bounds for known cases; raw pcaps and
findings stay local (never committed). Validate the manifest in CI with:

```bash
python tools/golden_check.py --validate
```

Run the checks against local case data with:

```powershell
python tools/golden_check.py --check --data-root platform/data/protocol_cases
```

or set `PROTOCOL_AGENT_GOLDEN_DATA` to the directory containing `case-<id>/findings.json`.
Missing local data is skipped by default; use `--require-data` to make it fatal.
