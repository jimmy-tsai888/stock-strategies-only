"""Prepare portable PR tests and check two real-tool negative controls."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
GUARD = ".agents/skills/twstock-regression-guard/scripts/run_regression_guard.py"
SUITES = ("tests/skills/test_regression_guard_skill.py", "tests/ci/test_pr_ci_policy.py")
STAGED_FILES = (
    GUARD,
    *SUITES,
    ".github/scripts/pr_ci_policy.py",
    ".github/scripts/pr_ci_gate.py",
    ".github/scripts/install_gitleaks.py",
    ".github/workflows/pr-readonly.yml",
    ".github/fixtures/pr-protected-manifest.json",
    ".github/fixtures/pr-protected-sample.txt",
)


def stage_portable(target: Path, manifest_path: Path) -> None:
    if target.exists() or manifest_path.exists():
        raise ValueError("portable staging destination already exists")
    target.mkdir(parents=True)
    protected = []
    for relative in STAGED_FILES:
        source = ROOT / relative
        if source.is_symlink() or not source.is_file():
            raise ValueError(f"portable source absent or symlink: {relative}")
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        protected.append({"path": relative, "sha256": hashlib.sha256(destination.read_bytes()).hexdigest()})
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(
        json.dumps({"protected_files": protected, "required_suites": list(SUITES)}, indent=2) + "\n",
        encoding="utf-8",
    )


def check_failing_pytest(temp_root: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="twstock-pr-pytest-negative-", dir=temp_root) as directory:
        root = Path(directory)
        workspace = root / "workspace"
        test = workspace / "tests/test_synthetic_failure.py"
        test.parent.mkdir(parents=True)
        test.write_text("def test_synthetic_failure():\n    assert False\n", encoding="utf-8")
        sentinel = workspace / "sentinel.txt"
        sentinel.write_text("synthetic baseline\n", encoding="utf-8")
        manifest = root / "manifest.json"
        manifest.write_text(
            json.dumps({"protected_files": [{"path": "sentinel.txt", "sha256": hashlib.sha256(sentinel.read_bytes()).hexdigest()}], "required_suites": ["tests/test_synthetic_failure.py"]}),
            encoding="utf-8",
        )
        report = root / "guard-report.json"
        env = os.environ.copy()
        env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        result = subprocess.run(
            [sys.executable, str(ROOT / GUARD), "--workspace", str(workspace), "--before-manifest", str(manifest), "--output", str(report)],
            capture_output=True, text=True, env=env, check=False, timeout=90,
        )
        if not report.is_file():
            raise ValueError("negative pytest guard produced no report")
        outcome = json.loads(report.read_text(encoding="utf-8"))
        if result.returncode != 2 or outcome.get("status") != "REGRESSION_GUARD_FAILED" or outcome.get("pytest_exit_code") != 1 or outcome.get("tests_failed") != 1:
            raise ValueError("negative failing pytest was not blocked as expected")


def _gitleaks_scan(binary: Path, directory: Path, report: Path) -> tuple[int, list[dict[str, object]]]:
    env = os.environ.copy()
    env.pop("GITLEAKS_CONFIG", None)
    env.pop("GITLEAKS_CONFIG_TOML", None)
    result = subprocess.run(
        [str(binary), "dir", str(directory), "--no-banner", "--no-color", "--redact", "--log-level", "error", "--ignore-gitleaks-allow", "--exit-code", "42", "--timeout", "120", "--report-format", "json", "--report-path", str(report)],
        cwd=directory, capture_output=True, text=True, env=env, check=False, timeout=150,
    )
    if not report.is_file():
        raise ValueError("Gitleaks scan did not write a report")
    findings = json.loads(report.read_text(encoding="utf-8"))
    if findings is None:
        findings = []
    if not isinstance(findings, list) or not all(isinstance(item, dict) for item in findings):
        raise ValueError("Gitleaks report has invalid structure")
    return result.returncode, findings


def check_gitleaks(binary: Path, checkout: Path, temp_root: Path) -> dict[str, int]:
    binary = binary.resolve()
    checkout = checkout.resolve()
    for name in (".gitleaks.toml", ".gitleaksignore"):
        if (checkout / name).exists():
            raise ValueError("unreviewed Gitleaks configuration or ignore file")
    version = subprocess.run([str(binary), "version"], capture_output=True, text=True, check=False, timeout=15)
    if version.returncode != 0 or version.stdout.strip() != "8.30.0":
        raise ValueError("Gitleaks version differs from reviewed 8.30.0")
    with tempfile.TemporaryDirectory(prefix="twstock-pr-gitleaks-", dir=temp_root) as directory:
        private = Path(directory)
        checkout_code, checkout_findings = _gitleaks_scan(binary, checkout, private / "checkout-report.json")
        if checkout_code != 0 or checkout_findings:
            raise ValueError("Gitleaks checkout scan found a leak or failed")
        synthetic = private / "synthetic-checkout"
        synthetic.mkdir()
        fixture = synthetic / "nonproduction-fixture.txt"
        fake = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
        fixture.write_text("aws_access_key_id = " + fake + "\n", encoding="utf-8")
        synthetic_code, synthetic_findings = _gitleaks_scan(binary, synthetic, private / "synthetic-report.json")
        if synthetic_code != 42 or not synthetic_findings:
            raise ValueError("Gitleaks did not block a new synthetic credential")
    return {"checkout_findings": 0, "synthetic_new_findings_blocked": len(synthetic_findings)}


def main(argv: list[str]) -> int:
    try:
        if len(argv) == 4 and argv[1] == "stage":
            stage_portable(Path(argv[2]), Path(argv[3]))
            result = {"status": "PASS", "check": "portable_stage", "suite_count": len(SUITES)}
        elif len(argv) == 3 and argv[1] == "negative-pytest":
            check_failing_pytest(Path(argv[2]))
            result = {"status": "PASS", "check": "failing_pytest_blocked"}
        elif len(argv) == 5 and argv[1] == "gitleaks":
            counts = check_gitleaks(Path(argv[2]), Path(argv[3]), Path(argv[4]))
            result = {"status": "PASS", "check": "gitleaks_checkout_and_synthetic_negative", **counts}
        else:
            print("usage: pr_ci_gate.py {stage TARGET MANIFEST|negative-pytest TEMP|gitleaks BINARY CHECKOUT TEMP}", file=sys.stderr)
            return 2
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "FAIL", "reason": type(exc).__name__}), file=sys.stderr)
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
