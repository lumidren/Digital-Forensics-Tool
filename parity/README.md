# Parity results

Each parity test writes one JSON file here, named `<parser>.json`, with this shape:

```json
{
  "parser": "prefetch",
  "reference": "libscca-python 20240427",
  "samples": ["plaso/winprefetch/CMD.EXE-087B4001.pf", "..."],
  "records_ours": 8,
  "records_reference": 8,
  "fields": {
    "executable_name": {"agree": 8, "total": 8},
    "run_count":       {"agree": 8, "total": 8},
    "last_run_times":  {"agree": 8, "total": 8}
  },
  "notes": "free text: known, explained differences"
}
```

`scripts/parity_report.py` aggregates every file into `docs/PARITY.md`, and CI fails if any
field's agreement ratio drops below the value committed in `parity/baseline.json`.
