# Regression contract

Capture git status and protected SHA256 values before a change. After the
change, run the complete non-live suite; never turn old tests into skips or
weaken assertions. Compare the same protected paths before and after. A
missing or changed protected file fails in both normal and dry-run mode.

Normal PASS requires pytest exit code 0, a valid JUnit report with at least
one passing test case, zero failures and errors, and an executed test case in
every required suite. Skipped cases alone do not satisfy suite coverage.
The default required suite is `tests`; a trusted pre-change manifest may list
additional `required_suites`, or `--required-suite` may specify them on the
command line. Keep critical suites in that list as coverage needs grow. The
legacy `--baseline` argument is only a count reference; a lower count is
reported as `test_count_below_reference` for review, without overriding pytest
results. Warnings are reported separately.

Dry run only verifies protected-file integrity and never invokes pytest. It
can write a report but cannot overwrite the baseline manifest or any protected
file. Its clean status is `REGRESSION_GUARD_DRY_RUN_INTEGRITY_PASSED`, not the
normal `REGRESSION_GUARD_PASSED` status.
