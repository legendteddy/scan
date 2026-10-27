# ScanBench v1

ScanBench is Scan's deterministic release gate. It uses synthetic fixtures and objective assertions across five independent dimensions:

- inventory completeness
- state integrity
- evidence correctness
- privacy integrity
- safety-boundary compliance

There is no blended overall quality score. Run all fixtures with `scan bench` or one fixture with `scan bench FIXTURE`. Fixture source is untrusted data and is never executed.
