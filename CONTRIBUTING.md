# Contributing

Thanks for considering a contribution to `mcp-guard`.

## Development setup

```bash
git clone https://github.com/mcp-guard/mcp-guard
cd mcp-guard
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
python -m pip install -e ".[dev]"
```

## Running checks

```bash
ruff check .
pytest -q
```

## Adding a new rule

1. Pick the next free `MCPGNNN` ID in `src/mcp_guard/constants.py`.
2. Add the rule entry to `RULE_CATALOG` with `id`, `title`, `severity`,
   `category`, `default_recommendation`, and `rationale`.
3. Implement detection in the relevant scanner module
   (`config_scan.py`, `metadata_scan.py`, `code_scan.py`, `secrets.py`,
   or one of the fuzz `detectors`).
4. Add at least one positive test in `tests/`.
5. Document the rule in `docs/rule_catalog.md` (ID, title, severity,
   rationale, detection method, examples, false positives, remediation).
6. If the rule applies to existing example servers, update them so the
   expected finding fires.

## Adding a new fuzz payload category

1. Append payloads to `src/mcp_guard/fuzz/payloads.py`.
2. Wire the category into `src/mcp_guard/fuzz/generator.py` (decide which
   schema shapes generate it).
3. Add or extend a detector in `src/mcp_guard/fuzz/detectors.py`.
4. Add a test that runs the generator against a representative schema
   and asserts the new category appears.

## Style

- Python 3.11+. Use modern syntax (`list[int]`, `str | None`, etc).
- `ruff` is the source of truth for formatting and lint.
- Public functions are typed and have a short docstring describing what
  they detect or do.
- No comments that restate the code. Comments should explain a
  non-obvious *why*.

## Code of conduct

Be kind. Be specific. Critique code, not people.
