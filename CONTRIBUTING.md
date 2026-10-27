# Contributing to Scan

Thanks for helping improve Scan.

## Principles

Changes should preserve Scan's core guarantees: evidence-backed conclusions, explicit coverage accounting, static-first safety, honest uncertainty, and a self-contained continuation state.

## Before opening a pull request

1. Keep changes focused and explain the problem they solve.
2. Update references and validator behavior together when a contract changes.
3. Add or update tests for validator changes and regression fixes.
4. Do not weaken validation simply to make a report pass.
5. Avoid introducing runtime dependencies unless they materially improve the project and the trade-off is documented.
6. Do not include private project data, credentials, or generated reports containing sensitive information.

Run the compatibility, core and benchmark gates:

```bash
python -m unittest discover -s scripts -p "test_*.py" -v
python -m unittest discover -s tests -p "test_*.py" -v
python -m unittest discover -s examples/demo-project/tests -p "test_*.py" -v
scan bench
```

For core or validator changes, also compile the Python sources and verify the synthetic report remains reproducible:

```bash
python -m compileall -q src/scan_core tests
python -m py_compile scripts/validate_report.py scripts/test_validate_report.py scripts/build_demo_report.py
python scripts/build_demo_report.py --check
```

## Pull requests

Describe:

- what changed;
- why it is needed;
- how it was verified;
- any compatibility or schema implications.

If a change modifies the embedded report contract, clearly identify the migration impact rather than silently relabeling older reports.
