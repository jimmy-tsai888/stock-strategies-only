# Dependabot review policy

`.github/dependabot.yml` asks GitHub to open weekly dependency pull requests for root `uv`, `/web` npm, and root GitHub Actions. It contains no auto-merge or deployment step. The file takes effect only when placed on the repository's default branch.

The `uv` ignore list keeps the current frozen scientific and market-provider dependencies out of automatic update pull requests. GitHub applies an ignore rule to both version and security update pull requests for those packages, so security alerts and fixes for them need a separate manual review. Other dependency pull requests still require non-live CI, regression and protected-artifact checks, and a deliberate merge decision. Review every lockfile change, including transitive changes, against the frozen runtime before acceptance.
