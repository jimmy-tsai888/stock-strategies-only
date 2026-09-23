"""Verify protected hashes and run the explicitly non-live pytest suite."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path


SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}\Z")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _required_suites(workspace: Path, names: list[str]) -> list[tuple[str, str, bool]]:
    """Return (name, JUnit classname prefix, is_directory) for safe suite paths."""
    suites = []
    for name in names:
        path = (workspace / name).resolve()
        if not path.is_relative_to(workspace) or not path.exists() or not (path.is_file() or path.is_dir()):
            raise ValueError(f"required suite is absent or outside workspace: {name}")
        relative = path.relative_to(workspace)
        module = relative.with_suffix("") if path.is_file() else relative
        suites.append((name, ".".join(module.parts), path.is_dir()))
    return suites


def _junit_counts(path: Path, suites: list[tuple[str, str, bool]]) -> dict[str, object]:
    root = ET.parse(path).getroot()
    cases = list(root.iter("testcase"))
    failures = sum(case.find("failure") is not None for case in cases)
    errors = sum(case.find("error") is not None for case in cases)
    skipped = sum(case.find("skipped") is not None for case in cases)
    classnames = [case.get("classname", "") for case in cases if case.find("skipped") is None]
    missing_suites = [
        name
        for name, module, is_dir in suites
        if not any(classname.startswith(module + ".") if is_dir else classname == module for classname in classnames)
    ]
    return {
        "tests_collected": len(cases),
        "tests_passed": len(cases) - failures - errors - skipped,
        "tests_failed": failures,
        "tests_errors": errors,
        "tests_skipped": skipped,
        "required_suites_missing": missing_suites,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="TWStock non-live regression guard")
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--before-manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline", type=int, default=None, help="optional test-count reference; never a pass threshold")
    parser.add_argument("--required-suite", action="append", help="suite path relative to workspace; repeatable")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    workspace = args.workspace.resolve()
    if not workspace.is_dir():
        parser.error("workspace must be an existing directory")
    before = json.loads(args.before_manifest.read_text(encoding="utf-8"))
    protected = before.get("protected_files")
    if not isinstance(protected, list) or not protected:
        parser.error("before-manifest must contain a nonempty protected_files list")

    before_sha = []
    after_sha = []
    changed = []
    missing = []
    unreadable = []
    seen = set()
    protected_paths = set()
    for item in protected:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str) or not item["path"]:
            parser.error("every protected file needs a path")
        expected = item.get("sha256")
        if not isinstance(expected, str) or not SHA256_PATTERN.fullmatch(expected):
            parser.error(f"invalid SHA256 for protected file: {item['path']}")
        path = Path(item["path"])
        if not path.is_absolute():
            path = workspace / path
        path = path.resolve()
        if path in seen:
            parser.error(f"duplicate protected path: {item['path']}")
        seen.add(path)
        protected_paths.add(path)
        before_sha.append({"path": item["path"], "sha256": expected})
        actual = None
        if not path.is_file():
            missing.append(item["path"])
        else:
            try:
                actual = digest(path)
            except OSError:
                unreadable.append(item["path"])
            else:
                if actual.lower() != expected.lower():
                    changed.append(item["path"])
        after_sha.append({"path": item["path"], "sha256": actual})

    output = args.output.resolve()
    if output == args.before_manifest.resolve() or output in protected_paths:
        parser.error("output must not overwrite the baseline manifest or a protected file")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    mismatches = changed + missing + unreadable
    suite_names = args.required_suite or before.get("required_suites") or ["tests"]
    if not isinstance(suite_names, list) or not suite_names or not all(isinstance(s, str) and s for s in suite_names):
        parser.error("required_suites must be a nonempty list of paths")
    try:
        suites = _required_suites(workspace, suite_names)
    except ValueError as exc:
        parser.error(str(exc))

    stdout = ""
    code = None
    counts: dict[str, object] = {
        "tests_collected": None,
        "tests_passed": None,
        "tests_failed": None,
        "tests_errors": None,
        "tests_skipped": None,
        "required_suites_missing": [],
    }
    junit_error = None
    if not args.dry_run and not mismatches:
        cache = args.output.parent / f"pytest-cache-{uuid.uuid4().hex}"
        junit = args.output.parent / f"pytest-junit-{uuid.uuid4().hex}.xml"
        command = [
            sys.executable, "-X", "utf8", "-m", "pytest", "-q", "-m", "not live",
            "--basetemp", str(cache), "--junitxml", str(junit), "tests",
        ]
        result = subprocess.run(command, cwd=workspace, text=True, capture_output=True, check=False)
        stdout, code = result.stdout + result.stderr, result.returncode
        try:
            counts = _junit_counts(junit, suites)
        except (OSError, ET.ParseError, ValueError) as exc:
            junit_error = f"{type(exc).__name__}: {exc}"

    if mismatches:
        status = "REGRESSION_GUARD_FAILED"
    elif args.dry_run:
        status = "REGRESSION_GUARD_DRY_RUN_INTEGRITY_PASSED"
    elif (
        code == 0
        and junit_error is None
        and counts["tests_collected"] > 0
        and counts["tests_passed"] > 0
        and counts["tests_failed"] == 0
        and counts["tests_errors"] == 0
        and not counts["required_suites_missing"]
    ):
        status = "REGRESSION_GUARD_PASSED"
    else:
        status = "REGRESSION_GUARD_FAILED"

    warning_matches = re.findall(r"(\d+) warnings?\b", stdout)
    report = {
        "status": status,
        "before_sha": before_sha,
        "after_sha": after_sha,
        "protected_files_changed": mismatches,
        "protected_files_missing": missing,
        "protected_files_unreadable": unreadable,
        "protected_mismatch_count": len(mismatches),
        **counts,
        "required_suites": suite_names,
        "test_count_reference": args.baseline,
        "test_count_below_reference": args.baseline is not None and counts["tests_passed"] is not None and counts["tests_passed"] < args.baseline,
        "warnings": int(warning_matches[-1]) if warning_matches else 0 if code is not None else None,
        "pytest_exit_code": code,
        "pytest_marker": "not live",
        "dry_run": args.dry_run,
        "pytest_not_run": code is None,
        "pytest_skipped_reason": "protected mismatch" if mismatches else "dry run" if args.dry_run else None,
        "junit_error": junit_error,
        "pytest_output": stdout[-4000:],
    }
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))
    return 0 if status != "REGRESSION_GUARD_FAILED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
