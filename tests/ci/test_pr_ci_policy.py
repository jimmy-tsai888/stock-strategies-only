"""Portable negative cases for the read-only pull-request gate."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path


ROOT = Path(__file__).parents[2]
POLICY_PATH = ROOT / ".github/scripts/pr_ci_policy.py"
WORKFLOW = ROOT / ".github/workflows/pr-readonly.yml"
MANIFEST = ROOT / ".github/fixtures/pr-protected-manifest.json"
GUARD = ROOT / ".agents/skills/twstock-regression-guard/scripts/run_regression_guard.py"
spec = importlib.util.spec_from_file_location("pr_ci_policy", POLICY_PATH)
assert spec and spec.loader
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
gate_spec = importlib.util.spec_from_file_location("pr_ci_gate", ROOT / ".github/scripts/pr_ci_gate.py")
assert gate_spec and gate_spec.loader
gate = importlib.util.module_from_spec(gate_spec)
gate_spec.loader.exec_module(gate)
installer_spec = importlib.util.spec_from_file_location("install_gitleaks", ROOT / ".github/scripts/install_gitleaks.py")
assert installer_spec and installer_spec.loader
installer = importlib.util.module_from_spec(installer_spec)
installer_spec.loader.exec_module(installer)


def _synthetic_guard(tmp_path: Path, *, failing_test: bool = False):
    workspace = tmp_path / "workspace"
    tests = workspace / "tests"
    tests.mkdir(parents=True)
    (tests / "test_smoke.py").write_text(
        "def test_smoke():\n    assert " + ("False" if failing_test else "True") + "\n",
        encoding="utf-8",
    )
    protected = tmp_path / "protected.txt"
    protected.write_text("synthetic baseline\n", encoding="utf-8")
    before = tmp_path / "before.json"
    before.write_text(
        json.dumps({"protected_files": [{"path": str(protected), "sha256": hashlib.sha256(protected.read_bytes()).hexdigest()}]}),
        encoding="utf-8",
    )
    return workspace, protected, before


def _run_guard(workspace: Path, before: Path, output: Path):
    env = os.environ.copy()
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, str(GUARD), "--workspace", str(workspace), "--before-manifest", str(before), "--output", str(output)],
        cwd=workspace, capture_output=True, text=True, env=env, check=False, timeout=60,
    )
    return result, json.loads(output.read_text(encoding="utf-8"))


def test_ci_clean_pr_uses_only_portable_checks(tmp_path: Path):
    assert policy.check_workflow_text(WORKFLOW.read_text(encoding="utf-8")) == []
    assert policy.check_manifest(MANIFEST, ROOT) == []
    assert policy.scan_secrets(ROOT) == []
    runs = policy.RUN_COMMANDS
    assert any("install_gitleaks.py" in command for command in runs)
    assert any("pr_ci_gate.py gitleaks" in command for command in runs)
    assert any("run_regression_guard.py --workspace" in command for command in runs)
    assert any("pr_ci_gate.py negative-pytest" in command for command in runs)
    assert not any("-m pytest -m live" in command for command in runs)
    stage = tmp_path / "portable"
    stage_manifest = tmp_path / "stage-manifest.json"
    gate.stage_portable(stage, stage_manifest)
    staged = {path.relative_to(stage).as_posix() for path in stage.rglob("*") if path.is_file()}
    assert staged == set(gate.STAGED_FILES)
    data = json.loads(stage_manifest.read_text(encoding="utf-8"))
    assert data["required_suites"] == policy.PYTEST_ALLOWLIST
    assert {item["path"] for item in data["protected_files"]} == staged
    assert all(hashlib.sha256((stage / item["path"]).read_bytes()).hexdigest() == item["sha256"] for item in data["protected_files"])
    payload = b"synthetic executable\n"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        info = tarfile.TarInfo("gitleaks")
        info.size = len(payload)
        archive.addfile(info, io.BytesIO(payload))
    target = tmp_path / "gitleaks"
    try:
        installer.install_verified_archive(buffer.getvalue(), target)
    except ValueError as exc:
        assert "SHA256 mismatch" in str(exc)
    else:
        raise AssertionError("unverified Gitleaks archive was installed")
    assert not target.exists()
    installer.install_verified_archive(buffer.getvalue(), target, hashlib.sha256(buffer.getvalue()).hexdigest())
    assert target.read_bytes() == payload
    workspace, _, before = _synthetic_guard(tmp_path)
    result, report = _run_guard(workspace, before, tmp_path / "report.json")
    assert result.returncode == 0
    assert report["status"] == "REGRESSION_GUARD_PASSED"


def test_ci_blocks_protected_synthetic_tamper(tmp_path: Path):
    fixture = tmp_path / ".github/fixtures/pr-protected-sample.txt"
    fixture.parent.mkdir(parents=True)
    fixture.write_bytes((ROOT / ".github/fixtures/pr-protected-sample.txt").read_bytes())
    manifest = tmp_path / ".github/fixtures/pr-protected-manifest.json"
    manifest.write_bytes(MANIFEST.read_bytes())
    assert policy.check_manifest(manifest, tmp_path) == []
    fixture.write_bytes(fixture.read_bytes() + b"x")
    assert any("hash mismatch" in issue for issue in policy.check_manifest(manifest, tmp_path))
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["protected_files"][0]["sha256"] = "invalid"
    manifest.write_text(json.dumps(data), encoding="utf-8")
    assert any("SHA256 format" in issue for issue in policy.check_manifest(manifest, tmp_path))


def test_ci_blocks_failing_pytest(tmp_path: Path):
    workspace, _, before = _synthetic_guard(tmp_path, failing_test=True)
    result, report = _run_guard(workspace, before, tmp_path / "report.json")
    assert result.returncode == 2
    assert report["status"] == "REGRESSION_GUARD_FAILED"
    assert report["pytest_exit_code"] == 1
    assert report["tests_failed"] == 1
    gate.check_failing_pytest(Path(tempfile.gettempdir()))


def test_ci_blocks_fake_secret_without_echoing_value(tmp_path: Path, capsys):
    fake = "AK" + "IA" + "A" * 16
    spec_file = tmp_path / "outputs/future-contract/spec.json"
    spec_file.parent.mkdir(parents=True)
    spec_file.write_text(json.dumps({"key": fake}), encoding="utf-8")
    (tmp_path / "LICENSE").write_text(fake, encoding="utf-8")
    (tmp_path / ".env").write_text("PLACEHOLDER=1\n", encoding="utf-8")
    findings = policy.scan_secrets(tmp_path)
    assert {item["rule"] for item in findings} == {"aws_access_key", "sensitive_path"}
    assert {item["path"] for item in findings} == {"outputs/future-contract/spec.json", "LICENSE", ".env"}
    assert policy.main([str(POLICY_PATH), "scan-secrets", str(tmp_path)]) == 2
    assert fake not in capsys.readouterr().out


def test_ci_blocks_live_invocation_without_running_it():
    original = WORKFLOW.read_text(encoding="utf-8")
    changed = original.replace(
        "      - name: Prove failing synthetic pytest blocks Regression Guard\n",
        "      - name: Run live pytest\n        run: .venv/bin/python -m pytest -m live\n"
        "      - name: Prove failing synthetic pytest blocks Regression Guard\n",
    )
    assert changed != original
    assert any("run commands differ" in issue for issue in policy.check_workflow_text(changed))


def test_ci_blocks_added_checkout_repository_and_submodules():
    original = WORKFLOW.read_bytes().decode("utf-8")
    changed = original.replace(
        "          persist-credentials: false\n",
        "          persist-credentials: false\n          repository: other/example\n          submodules: recursive\n",
    )
    assert changed != original
    assert any("approved SHA256" in issue for issue in policy.check_workflow_text(changed))
