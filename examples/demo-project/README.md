# Pocket Ledger — synthetic Scan demo

A deliberately small, fictional CSV totaler used to demonstrate **what Scan can
support from static evidence, and what it cannot**. All order data is invented.

## Contents

- `ledger.py`: reads an `amount` column and prints a two-decimal total.
- `data/orders.csv`: three fictional orders.
- `tests/test_ledger.py`: two happy-path unit tests.
- `pyproject.toml`: package metadata; no third-party dependencies.

Run the toy program (optional):

```bash
python ledger.py data/orders.csv
```

The companion [Scan report](../demo-report.html) is a **worked synthetic
example**, not a claim that an AI agent ran Scan autonomously. It documents
source inspection, evidence locators, a possible float-precision risk, gaps in
input handling, and checks not performed. Opening the report requires no server.

Do not use this toy program for real financial accounting.
