"""Small, dependency-free safety checks for the PR-only validation lane."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path


EXPECTED_WORKFLOW_SHA256 = "ae74a8a30c5989a3838ef323a8269c76ccbdeb8a22cf77dee4f3679a46b81d54"
ACTION_REFS = [
    "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
    "astral-sh/setup-uv@bec219d24cd3e171d82865faccec33120bb574f4",
]
PYTEST_ALLOWLIST = [
    "tests/skills/test_regression_guard_skill.py",
    "tests/ci/test_pr_ci_policy.py",
]
RUN_COMMANDS = [
    "python3 -B .github/scripts/pr_ci_policy.py check-workflow .github/workflows/pr-readonly.yml",
    "python3 -B .github/scripts/pr_ci_policy.py scan-secrets .",
    "python3 -B .github/scripts/pr_ci_policy.py check-manifest .github/fixtures/pr-protected-manifest.json",
    'python3 -B .github/scripts/install_gitleaks.py "$RUNNER_TEMP/twstock-tools/gitleaks"',
    'python3 -B .github/scripts/pr_ci_gate.py gitleaks "$RUNNER_TEMP/twstock-tools/gitleaks" . "$RUNNER_TEMP"',
    "uv lock --check",
    "uv sync --locked --group dev --no-install-project",
    '.venv/bin/python -B .github/scripts/pr_ci_gate.py stage "$RUNNER_TEMP/twstock-pr-guard" "$RUNNER_TEMP/twstock-pr-guard-manifest.json"',
    'PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -B '
    '.agents/skills/twstock-regression-guard/scripts/run_regression_guard.py '
    '--workspace "$RUNNER_TEMP/twstock-pr-guard" --before-manifest "$RUNNER_TEMP/twstock-pr-guard-manifest.json" '
    '--output "$RUNNER_TEMP/twstock-pr-guard-report.json" '
    '--required-suite tests/skills/test_regression_guard_skill.py --required-suite tests/ci/test_pr_ci_policy.py',
    'PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -B '
    '.github/scripts/pr_ci_gate.py negative-pytest "$RUNNER_TEMP"',
]
SECRET_PATTERNS = {
    "aws_access_key": re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    "github_token": re.compile(r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9_]{30,}"),
    "openai_key": re.compile(r"(?<![A-Za-z0-9_-])sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
}
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".woff", ".woff2", ".ttf", ".otf", ".zip", ".gz", ".parquet", ".sqlite3", ".joblib", ".pkl", ".onnx", ".pt", ".pth"}
SENSITIVE_SUFFIXES = {".pem", ".p12", ".pfx", ".key"}
SKIP_DIRS = {".git", ".venv", "node_modules", ".pytest_cache", "__pycache__", ".next"}
VERSIONED_DIRS = {".agents", ".github", "api", "assets", "data_specs", "docs", "marketdata", "stock_strategies", "strategies", "tests", "web", "outputs"}


def check_workflow_text(text: str) -> list[str]:
    issues = []
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != EXPECTED_WORKFLOW_SHA256:
        issues.append("workflow bytes differ from approved SHA256")
    text = text.replace("\r\n", "\n")
    if not text.startswith("name: TWStock PR Read-only\n\non:\n  pull_request:\n\npermissions:\n  contents: read\n\n"):
        issues.append("trigger or token permissions differ from PR-only contents:read")
    if set(re.findall(r"(?m)^([A-Za-z_][A-Za-z_-]*):", text)) != {"name", "on", "permissions", "jobs"}:
        issues.append("unreviewed top-level workflow key present")
    if len(re.findall(r"(?m)^\s*permissions:", text)) != 1 or re.search(r"(?m)^\s+[A-Za-z_-]+:\s*write\s*$", text):
        issues.append("token permissions may exceed read access")
    if "\njobs:\n  pr-validation:\n    runs-on: ubuntu-24.04\n    timeout-minutes: 15\n    steps:\n" not in text:
        issues.append("job shape or runner differs from reviewed PR job")
    uses = re.findall(r"(?m)^\s+uses:\s+([^\s#]+)", text)
    if uses != ACTION_REFS:
        issues.append("action list differs from reviewed full-SHA pins")
    runs = re.findall(r"(?m)^\s+run:\s*(.+)$", text)
    if runs != RUN_COMMANDS:
        issues.append("run commands differ from portable synthetic allowlist")
    if len(re.findall(r"(?m)^\s{6}- name:", text)) != 12:
        issues.append("step count differs from reviewed PR job")
    for required in (
        "persist-credentials: false",
        'version: "0.12.18"',
        'python-version: "3.12"',
        "enable-cache: false",
    ):
        if required not in text:
            issues.append(f"required action setting absent: {required}")
    if re.search(r"(?im)^\s*(?:push|schedule|workflow_dispatch|pull_request_target|workflow_run|repository_dispatch|release|issues):", text):
        issues.append("non-PR trigger present")
    if re.search(r"(?im)^\s*(?:env|if|continue-on-error|secrets|ref|shell|working-directory|container|services|environment|id-token):", text):
        issues.append("unreviewed workflow control or secret input present")
    if "${{" in text or "@main" in text or "@master" in text:
        issues.append("expression or floating action reference present")
    return issues


def check_manifest(path: Path, root: Path) -> list[str]:
    """Check only the versioned synthetic fixture, never local P7/P8/P9 paths."""
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return ["manifest cannot be read as JSON"]
    protected = manifest.get("protected_files") if isinstance(manifest, dict) else None
    if not isinstance(protected, list) or not protected:
        return ["protected_files must be a nonempty list"]
    issues = []
    seen = set()
    root = root.resolve()
    for item in protected:
        if not isinstance(item, dict):
            issues.append("protected entry is not an object")
            continue
        name, expected = item.get("path"), item.get("sha256")
        if not isinstance(name, str) or not name or "\\" in name or ":" in name or Path(name).is_absolute() or ".." in Path(name).parts:
            issues.append("protected path is not a safe repository-relative path")
            continue
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected):
            issues.append(f"invalid SHA256 format for {name}")
            continue
        candidate = root / name
        target = candidate.resolve()
        if not target.is_relative_to(root) or target in seen:
            issues.append(f"duplicate or escaping protected path: {name}")
            continue
        seen.add(target)
        if candidate.is_symlink() or not target.is_file():
            issues.append(f"protected fixture absent or symlink: {name}")
            continue
        try:
            actual = hashlib.sha256(target.read_bytes()).hexdigest()
        except OSError:
            issues.append(f"protected fixture unreadable: {name}")
            continue
        if actual.lower() != expected.lower():
            issues.append(f"protected fixture hash mismatch: {name}")
    suites = manifest.get("required_suites")
    if suites != PYTEST_ALLOWLIST:
        issues.append("required_suites differ from portable pytest allowlist")
    return issues


def scan_secrets(root: Path) -> list[dict[str, str]]:
    findings = []
    root = root.resolve()
    if (root / ".git").exists():
        result = subprocess.run(["git", "ls-files", "-z"], cwd=root, capture_output=True, check=False)
        if result.returncode != 0:
            return [{"path": ".", "rule": "git_file_inventory_failed"}]
        candidates = [root / os.fsdecode(name) for name in result.stdout.split(b"\0") if name]
    else:
        candidates = []
        for directory, dirs, files in os.walk(root):
            base = Path(directory)
            relative_dir = base.relative_to(root)
            dirs[:] = sorted(
                name for name in dirs
                if name not in SKIP_DIRS and (relative_dir != Path(".") or name in VERSIONED_DIRS)
            )
            if relative_dir == Path(".") or relative_dir.parts[0] in VERSIONED_DIRS:
                candidates.extend(base / name for name in sorted(files))
    for path in candidates:
        relative = path.relative_to(root).as_posix()
        if path.name == ".env" or (path.name.startswith(".env.") and path.name not in {".env.example", ".env.local.example"}) or path.suffix.lower() in SENSITIVE_SUFFIXES:
            findings.append({"path": relative, "rule": "sensitive_path"})
            continue
        if path.is_symlink() or not path.is_file():
            findings.append({"path": relative, "rule": "unreadable_text"})
            continue
        if path.suffix.lower() in BINARY_SUFFIXES:
            continue
        if path.stat().st_size > 2_000_000:
            findings.append({"path": relative, "rule": "unscanned_large_text"})
            continue
        try:
            contents = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            findings.append({"path": relative, "rule": "unreadable_text"})
            continue
        for rule, pattern in SECRET_PATTERNS.items():
            if pattern.search(contents):
                findings.append({"path": relative, "rule": rule})
    return findings


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] not in {"check-workflow", "scan-secrets", "check-manifest"}:
        print("usage: pr_ci_policy.py {check-workflow|scan-secrets|check-manifest} PATH", file=sys.stderr)
        return 2
    path = Path(argv[2])
    if argv[1] == "check-workflow":
        issues = check_workflow_text(path.read_bytes().decode("utf-8"))
    elif argv[1] == "scan-secrets":
        issues = scan_secrets(path)
    else:
        issues = check_manifest(path, Path.cwd())
    print(json.dumps({"status": "PASS" if not issues else "FAIL", "issues": issues}, ensure_ascii=False))
    return 0 if not issues else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
