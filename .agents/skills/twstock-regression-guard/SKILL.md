---
name: twstock-regression-guard
description: Capture protected hashes and run the complete non-live TWStock regression before and after code changes. Do not use it to skip, delete, or weaken existing tests.
---

# TWStock regression guard

Use `scripts/run_regression_guard.py` with a nonempty pre-change protected
manifest. Normal mode runs pytest with the `not live` marker and reads its JUnit
result. A protected mismatch, missing file, pytest failure or error, empty test
run, all-skipped run, or missing required suite is `REGRESSION_GUARD_FAILED`. The optional
`--baseline` count is an informational reference, not a pass threshold.

`--dry-run` checks protected hashes without running pytest. A clean dry run
reports `REGRESSION_GUARD_DRY_RUN_INTEGRITY_PASSED`, which is not a full
regression pass; a mismatch still fails. The report may be written only to a
path distinct from the manifest and protected files.

Read [the regression contract](references/regression-contract.md) before
interpreting a failure.
