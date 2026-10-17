"""Exact-source acceptance probe. Only isolated mode may write a temporary board."""
from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True


def _git(root, *args):
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                          text=True, timeout=30).stdout.strip()


def _source(root, expected):
    if _git(root, "rev-parse", "--show-toplevel") != str(root):
        raise ValueError("Source root is not the repository root")
    if _git(root, "rev-parse", "HEAD") != expected:
        raise ValueError("Source SHA differs from expected SHA")
    if _git(root, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("Source has tracked changes")
    sys.path.insert(0, str(root))
    collector = importlib.import_module("hermes_cli.kanban_pr_acceptance")
    path = Path(collector.__file__).resolve()
    if path != root / "hermes_cli/kanban_pr_acceptance.py":
        raise ValueError("Collector module came from another source root")
    return collector, {"source_sha": expected, "collector_path": str(path),
                       "collector_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}


def _safe_db(path, temporary):
    from agent.delegation_context import kanban_path_is_fenced

    path = path.resolve()
    pinned = os.environ.get("HERMES_KANBAN_DB")
    if not path.is_relative_to(temporary.resolve()) or (pinned and path == Path(pinned).resolve()):
        raise ValueError("Temporary DB resolves outside the isolated root or to a pinned board")
    if kanban_path_is_fenced(path):
        raise ValueError("Temporary DB is inside the inherited board fence")
    return path


def _receipt(conn, tid):
    row = conn.execute("SELECT payload FROM task_events WHERE task_id=? AND kind='pr_acceptance' ORDER BY id DESC", (tid,)).fetchone()
    return json.loads(row[0]) if row else None


def _isolated(options):
    import pytest
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect_closing

    fixture_root = (options.fixture_root or Path(__file__).resolve().parents[1]).resolve()
    fixture_sha = _git(fixture_root, "rev-parse", "HEAD")
    if options.fixture_sha and fixture_sha != options.fixture_sha:
        raise ValueError("Fixture SHA differs from expected SHA")
    if _git(fixture_root, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("Fixture source has tracked changes")
    spec = importlib.util.spec_from_file_location("acceptance_http_fixture", fixture_root / "tests/hermes_cli/test_kanban_pr_acceptance.py")
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    marker = os.environ.get("HERMES_DELEGATED_CHILD_CONTEXT")
    reports = []
    with tempfile.TemporaryDirectory(prefix="hermes-acceptance-", dir=fixture_root) as temporary:
        temporary = Path(temporary)
        db = _safe_db(temporary / "board/kanban.db", temporary)
        with pytest.MonkeyPatch.context() as patch:
            setup = fixture.github.__wrapped__(temporary, patch, db_path=db)
            state = next(setup)
            try:
                with connect_closing(db_path=db) as conn:
                    cases = [
                        ("absent", {"base": {"branchProtectionRule": None}}, "not_applicable"),
                        ("hidden-protection", {"base": {"branchProtectionRule": None},
                         "responses": {"branch": {"name": "main", "protected": True}}}, "infra"),
                        ("failure", {"conclusion": "failure"}, "failure"),
                        ("cancelled", {"conclusion": "cancelled"}, "infra"),
                        ("timed_out", {"conclusion": "timed_out"}, "infra"),
                        ("success", {"conclusion": "success"}, "success"),
                        ("malformed-policy", {"base": {}}, "infra"),
                        ("head-drift", {"base": {"branchProtectionRule": None},
                         "final": {"head": {"sha": "b" * 40}, "base": {"ref": "main"}, "state": "open"}}, "stale"),
                    ]
                    for name, fault, classification in cases:
                        reports.append(_lifecycle_case(kb, conn, state, name, fault, classification,
                                                       options.expected_base_refusal))
            finally:
                setup.close()
        assert os.environ.get("HERMES_DELEGATED_CHILD_CONTEXT") == marker
    return {"fixture_sha": fixture_sha, "reports": reports, "fence_preserved": True}


def _lifecycle_case(kb, conn, state, name, fault, classification, expected_base_refusal):
    state.clear()
    state.update(conclusion="success", head="a" * 40, requests=[])
    state.update(fault)
    tid = kb.create_task(conn, title="Isolated acceptance " + name, completion_contract="acme/repo")
    owner = kb.claim_task(conn, tid)
    metadata = {"published_pr": "https://github.com/acme/repo/pull/7"}
    accepted = kb.complete_task(conn, tid, summary="isolated evidence", metadata=metadata,
                                expected_run_id=owner.current_run_id, fire_lifecycle_hook=False)
    receipt = _receipt(conn, tid)
    task = kb.get_task(conn, tid)
    run = dict(conn.execute("SELECT status, outcome FROM task_runs WHERE id=?", (owner.current_run_id,)).fetchone())
    report = {"case": name, "accepted": accepted, "status": task.status,
                    "contract": task.completion_contract, "run": run, "receipt": receipt}
    if expected_base_refusal and name in {"absent", "hidden-protection", "malformed-policy", "head-drift"}:
        assert accepted is False and receipt["classification"] == "missing"
        assert receipt["detail"] == "No repository-required checks are configured; explicitly use a local-only contract for non-CI tasks."
    else:
        assert receipt["classification"] == classification
        assert accepted is (classification in {"success", "not_applicable"})
        assert task.status == ("done" if accepted else "running")
        if accepted:
            assert run == {"status": "done", "outcome": "completed"}
        if name == "absent":
            assert receipt["required"] == receipt["checks"] == []
            assert receipt["base_ref"] == "main" and receipt["recovery"] == ""
    assert receipt["head_sha"] == "a" * 40
    assert task.completion_contract == metadata["published_pr"]
    return report


def _pending(root):
    from hermes_cli._early_recovery import interrupted_pull_marker
    from hermes_cli.update_host_obligation import _owed_path
    from hermes_cli.update_lock import update_marker_path
    from hermes_cli.venv_sync import completion_pending_path

    paths = [completion_pending_path(root), root / ".update-incomplete",
             root / ".lazy-refresh-incomplete", interrupted_pull_marker(root),
             update_marker_path(), _owed_path()]
    for path in paths:
        try:
            path.stat()
        except FileNotFoundError:
            continue
        raise ValueError("Pending runtime obligation at " + str(path))


def _runtime_ready(options):
    import pm
    from pm.environments import running_from_selected_environment, selected_venv

    root = options.source
    _pending(root)
    if not pm.venv_is_current(project_root=root):
        raise ValueError("PM dependency stamp is missing or stale")
    if not options.readiness_child:
        launcher = root / ".hermes/bin/hermes"
        if not launcher.is_file():
            raise ValueError("Published installation launcher is missing")
        command = [str(launcher), "--run-module", "evals.kanban_pr_acceptance_live", str(root),
                   "--mode", "runtime-ready", "--expected-sha", options.expected_sha, "--readiness-child"]
        child = subprocess.run(command, check=True, capture_output=True, text=True, timeout=180)
        value = json.loads(child.stdout)
        if value["source_sha"] != options.expected_sha or value["readiness"]["ready"] is not True:
            raise ValueError("Fresh launcher child did not certify exact-source readiness")
        return {**value["readiness"], "launcher": str(launcher), "fresh_child": True}
    if not running_from_selected_environment(root):
        raise ValueError("Interpreter does not use the PM-selected environment")
    from pm.recovery import STARTUP_IMPORTS
    from hermes_cli.update_cmd_validation import _UPDATE_CRITICAL_MODULES

    for _, module, attribute in STARTUP_IMPORTS:
        getattr(importlib.import_module(module), attribute)
    argv = sys.argv
    try:
        sys.argv = ["hermes", "update"]
        for name in _UPDATE_CRITICAL_MODULES:
            importlib.import_module(name)
    finally:
        sys.argv = argv
    _pending(root)
    return {"ready": True, "selected_environment": str(selected_venv(root)),
            "interpreter": sys.executable, "critical_imports": list(_UPDATE_CRITICAL_MODULES)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=lambda value: Path(value).resolve())
    parser.add_argument("--mode", required=True, choices=("isolated", "read-only", "runtime-ready"))
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--fixture-root", type=Path)
    parser.add_argument("--fixture-sha")
    parser.add_argument("--expected-base-refusal", action="store_true")
    parser.add_argument("--contract")
    parser.add_argument("--published-pr")
    parser.add_argument("--assignee")
    parser.add_argument("--expected-head")
    parser.add_argument("--readiness-child", action="store_true", help=argparse.SUPPRESS)
    options = parser.parse_args(argv)
    try:
        collector, report = _source(options.source, options.expected_sha)
        if options.mode == "isolated":
            report.update(_isolated(options))
        elif options.mode == "read-only":
            if not all((options.contract, options.published_pr, options.assignee, options.expected_head)):
                raise ValueError("Read-only mode requires contract, PR, assignee and expected head")
            receipt = collector.collect_acceptance(options.contract, options.published_pr, assignee=options.assignee)
            report["receipt"] = receipt
            if receipt["head_sha"] != options.expected_head or not receipt["ok"]:
                raise ValueError("Real PR acceptance refused or head differs")
        else:
            if os.environ.get("HERMES_DISABLE_LAZY_INSTALLS", "").lower() not in {"1", "true", "yes"}:
                raise ValueError("Runtime readiness requires lazy installs disabled before launch")
            report["readiness"] = _runtime_ready(options)
        report.update(schema_version=1, mode=options.mode, ok=True)
        code = 0
    except (AssertionError, OSError, ValueError, KeyError, TypeError, ImportError, subprocess.SubprocessError):
        report = {"schema_version": 1, "mode": options.mode, "source_sha": options.expected_sha,
                  "ok": False, "detail": "Probe refused source, isolation, acceptance or readiness evidence."}
        code = 1
    output = json.dumps(report, indent=2) + "\n"
    if options.output:
        options.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
