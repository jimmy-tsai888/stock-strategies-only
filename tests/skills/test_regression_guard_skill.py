import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).parents[2]
SCRIPT = ROOT / ".agents" / "skills" / "twstock-regression-guard" / "scripts" / "run_regression_guard.py"


@pytest.fixture
def synthetic_guard(tmp_path: Path):
    workspace = tmp_path / "workspace"
    tests = workspace / "tests"
    tests.mkdir(parents=True)
    (tests / "test_smoke.py").write_text("def test_smoke():\n    assert True\n", encoding="utf-8")
    protected = tmp_path / "protected.bin"
    baseline = b"baseline\n"
    protected.write_bytes(baseline)
    before = tmp_path / "before.json"
    before.write_text(
        json.dumps({"protected_files": [{"path": str(protected), "sha256": hashlib.sha256(baseline).hexdigest()}]}) + "\n",
        encoding="utf-8",
    )
    return workspace, protected, before, tmp_path / "report.json"


def run_guard(workspace: Path, before: Path, output: Path, *extra: str):
    env = os.environ.copy()
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--workspace", str(workspace), "--before-manifest", str(before), "--output", str(output), *extra],
        capture_output=True, text=True, check=False, env=env, timeout=60,
    )
    report = json.loads(output.read_text(encoding="utf-8")) if output.exists() else None
    return result, report


def test_guard_passes_clean_baseline(synthetic_guard):
    workspace, _, before, output = synthetic_guard
    result, report = run_guard(workspace, before, output, "--baseline", "321")
    assert result.returncode == 0
    assert report["status"] == "REGRESSION_GUARD_PASSED"
    assert report["protected_mismatch_count"] == 0
    assert report["pytest_exit_code"] == 0
    assert report["tests_passed"] == 1
    assert report["tests_failed"] == report["tests_errors"] == 0
    assert report["required_suites_missing"] == []
    assert report["test_count_below_reference"] is True
    assert report["pytest_marker"] == "not live"


def test_guard_fails_protected_hash_change(synthetic_guard):
    workspace, protected, before, output = synthetic_guard
    protected.write_bytes(b"baselinE\n")
    result, report = run_guard(workspace, before, output)
    assert result.returncode == 2
    assert report["status"] == "REGRESSION_GUARD_FAILED"
    assert report["protected_mismatch_count"] == 1
    assert report["protected_files_changed"] == [str(protected)]
    assert report["protected_files_missing"] == []
    assert report["pytest_not_run"] is True


@pytest.mark.parametrize("dry_run", [False, True])
def test_guard_fails_missing_artifact(synthetic_guard, dry_run: bool):
    workspace, protected, before, output = synthetic_guard
    protected.unlink()
    result, report = run_guard(workspace, before, output, *(["--dry-run"] if dry_run else []))
    assert result.returncode == 2
    assert report["status"] == "REGRESSION_GUARD_FAILED"
    assert report["protected_mismatch_count"] == 1
    assert report["protected_files_missing"] == [str(protected)]
    assert report["after_sha"][0]["sha256"] is None


def test_guard_dry_run_still_fails_hash_mismatch(synthetic_guard):
    workspace, protected, before, output = synthetic_guard
    protected.write_bytes(b"baselinE\n")
    result, report = run_guard(workspace, before, output, "--dry-run")
    assert result.returncode == 2
    assert report["status"] == "REGRESSION_GUARD_FAILED"
    assert report["protected_mismatch_count"] == 1
    assert report["pytest_exit_code"] is None


def test_guard_dry_run_does_not_mutate_baseline(synthetic_guard):
    workspace, protected, before, output = synthetic_guard
    baseline_bytes = before.read_bytes(), protected.read_bytes()
    result, report = run_guard(workspace, before, output, "--dry-run")
    assert result.returncode == 0
    assert report["status"] == "REGRESSION_GUARD_DRY_RUN_INTEGRITY_PASSED"
    assert report["pytest_not_run"] is True
    assert report["pytest_exit_code"] is None
    assert (before.read_bytes(), protected.read_bytes()) == baseline_bytes
    assert not list(workspace.rglob(".pytest_cache"))


def test_guard_propagates_pytest_failure(synthetic_guard):
    workspace, _, before, output = synthetic_guard
    (workspace / "tests" / "test_smoke.py").write_text("def test_smoke():\n    assert False\n", encoding="utf-8")
    result, report = run_guard(workspace, before, output)
    assert result.returncode == 2
    assert report["status"] == "REGRESSION_GUARD_FAILED"
    assert report["protected_mismatch_count"] == 0
    assert report["pytest_exit_code"] == 1
    assert report["tests_failed"] == 1


def test_guard_fails_when_required_suite_has_no_selected_tests(synthetic_guard):
    workspace, _, before, output = synthetic_guard
    (workspace / "tests" / "test_required.py").write_text(
        "import pytest\n@pytest.mark.live\ndef test_live_only():\n    assert True\n", encoding="utf-8"
    )
    result, report = run_guard(workspace, before, output, "--required-suite", "tests/test_required.py")
    assert result.returncode == 2
    assert report["pytest_exit_code"] == 0
    assert report["required_suites_missing"] == ["tests/test_required.py"]


def test_guard_fails_when_all_tests_are_skipped(synthetic_guard):
    workspace, _, before, output = synthetic_guard
    (workspace / "tests" / "test_smoke.py").write_text(
        "import pytest\n@pytest.mark.skip(reason='synthetic')\ndef test_smoke():\n    assert True\n",
        encoding="utf-8",
    )
    result, report = run_guard(workspace, before, output)
    assert result.returncode == 2
    assert report["pytest_exit_code"] == 0
    assert report["tests_passed"] == 0
    assert report["required_suites_missing"] == ["tests"]
