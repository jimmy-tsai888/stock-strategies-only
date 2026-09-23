# PR validation boundary

`.github/workflows/pr-readonly.yml` runs only for pull requests with
`contents: read`. It copies two reviewed test files and the minimum scripts and
fixtures into a temporary workspace, then directly runs Regression Guard there
with pytest plugin autoload disabled. The temporary workspace contains only
synthetic, portable tests. A separate temporary failing pytest case must make
Regression Guard fail. Neither temporary fixture is committed. This does not
run the full P8/P9 suite, Forward, live market adapters, broker actions, or
clock changes. The versioned protected manifest names a synthetic fixture;
it makes no claim about the separate 104 private protected artifacts.

The workflow installs Gitleaks 8.30.0 from its Linux x64 release archive only
after a pinned SHA256 check, then actually scans the checkout. A temporary
non-production credential must trigger Gitleaks' dedicated finding exit code;
the gate captures scanner output without echoing the fixture. There is no
Gitleaks baseline or ignore file: any finding in the actual PR checkout fails.
The small policy script additionally checks the workflow shape, the synthetic fixture's SHA256,
and credential signatures in checkout text. In a Git checkout it scans tracked
files; outside Git it scans versioned candidate directories and root files.
Sensitive paths, symlinks, unreadable text, and oversized text fail without
printing matched values. This U4 checkout scan does not replace U5 Gitleaks
review of the working tree, history, and candidate PR diff. Remote GitHub CI
has not run in this isolated lane.

The workflow is also pinned to its approved exact byte SHA256 in the policy
script. A change to checkout inputs, even without changing a `run:` command,
fails this local check. A PR can change the workflow and policy together, so
branch protection and independent human review of workflow, policy, and test
allowlist changes are required before relying on this as a merge gate.
