"""Read-only Kanban inspection and fail-closed isolated update rehearsal."""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"[0-9a-f]{40}\Z")
FORK = "https://github.com/superaitaotao/hermes-agent.git"


def git(root, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="credential.helper",
               GIT_CONFIG_VALUE_0="", GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
    return subprocess.run(["git", "-C", str(root), *args], env=env, stdin=subprocess.DEVNULL,
                          check=True, capture_output=True, text=True, encoding="utf-8", timeout=180).stdout.strip()


def trial_environment():
    return {"HOME": "/trial/home", "HERMES_HOME": "/trial/home/.hermes",
            "HERMES_RUNTIME_DIR": "/trial/home/.hermes/tools",
            "HERMES_GATEWAY_LOCK_DIR": "/trial/state/gateway-locks",
            "XDG_CONFIG_HOME": "/trial/home/.config", "XDG_CACHE_HOME": "/trial/home/.cache",
            "XDG_STATE_HOME": "/trial/state", "XDG_RUNTIME_DIR": "/trial/run",
            "TMPDIR": "/trial/tmp", "PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1",
            "CI": "1", "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "credential.helper", "GIT_CONFIG_VALUE_0": ""}


def validate_trial_homes(env):
    homes = {}
    for key in trial_environment():
        if key in {"HOME", "HERMES_HOME", "HERMES_RUNTIME_DIR", "HERMES_GATEWAY_LOCK_DIR", "TMPDIR"} or key.startswith("XDG_"):
            path = Path(env.get(key, "")).resolve()
            if not path.is_relative_to("/trial"):
                raise ValueError(f"{key} resolves outside /trial")
            homes[key] = str(path)
    if any(key.startswith("HERMES_KANBAN_") or key == "DBUS_SESSION_BUS_ADDRESS" for key in env):
        raise ValueError("Inherited board ownership or service bus")
    return homes


def verify_target(source, origin, expected, ancestor=None):
    if not SHA.fullmatch(expected):
        raise ValueError("Expected target must be a full lowercase SHA")
    advertised = git(source, "ls-remote", origin, "refs/heads/main")
    if advertised.split() != [expected, "refs/heads/main"]:
        raise ValueError("Origin advertised a different candidate")
    descendant = None
    if ancestor:
        try:
            git(source, "merge-base", "--is-ancestor", ancestor, expected)
        except subprocess.CalledProcessError as exc:
            raise ValueError("Moving target is not a descendant") from exc
        descendant = True
    return {"advertised_sha": expected, "ref": "refs/heads/main", "descendant": descendant}


def advance_fixture(writer, bare, candidate):
    git(writer, "switch", "--detach", candidate)
    git(writer, "config", "user.name", "Rehearsal fixture")
    git(writer, "config", "user.email", "rehearsal@example.invalid")
    git(writer, "config", "commit.gpgsign", "false")
    (Path(writer) / "rehearsal-unrelated.txt").write_text("Isolated fixture descendant.\n", encoding="utf-8")
    git(writer, "add", "rehearsal-unrelated.txt")
    git(writer, "commit", "-m", "test: advance isolated origin")
    child = git(writer, "rev-parse", "HEAD")
    git(writer, "push", str(bare), "HEAD:refs/heads/main")
    return child


def source_identity(source, expected):
    if not expected or not SHA.fullmatch(expected):
        raise ValueError("Expected source must be a full lowercase SHA")
    if git(source, "rev-parse", "--show-toplevel") != str(source):
        raise ValueError("Source is not a repository root")
    if git(source, "rev-parse", "HEAD") != expected:
        raise ValueError("Source SHA differs")
    if git(source, "status", "--porcelain", "--untracked-files=no"):
        raise ValueError("Tracked source is dirty")
    return {"source_sha": expected, "source": str(source), "clean_tracked_tree": True,
            "origin": git(source, "remote", "get-url", "origin")}


def select_source(source):
    sys.path.insert(0, str(source))
    module = importlib.import_module("tools.kanban_tools")
    if Path(module.__file__).resolve() != source / "tools/kanban_tools.py":
        raise ValueError("Tool imported from another source")
    return module


def schema_contracts(source, allow_gaps=False):
    select_source(source)
    from tools.registry import registry
    from tools.schema_sanitizer import sanitize_tool_schemas

    schemas = sanitize_tool_schemas([
        {"type": "function", "function": registry.get_schema(name)}
        for name in ("kanban_attach", "kanban_complete")])
    attach, complete = (item["function"]["parameters"] for item in schemas)
    checks = {"metadata_open": complete["properties"]["metadata"].get("additionalProperties") is True,
              "published_pr": "published_pr" in complete["properties"],
              "path": "path" in attach["properties"] and not attach.get("required")}
    if not all(checks.values()) and not allow_gaps:
        raise ValueError("Kanban schema contracts absent")
    return {"contracts": checks, "sanitized_schemas": schemas,
            "tool_source": str(source / "tools/kanban_tools.py")}


def selection(source):
    from hermes_cli.config import require_readable_config_before_write
    from hermes_cli import source_check, update_channel
    from hermes_constants import get_hermes_home

    config = require_readable_config_before_write(get_hermes_home() / "config.yaml")
    co = source_check._read_checkout(source, "git", None)
    return {"origin": co.origin, "channel": update_channel.resolve_update_channel(config, source),
            "channel_record": update_channel.channel_record(config, source), "head": co.head}


def pending(source):
    from hermes_cli._early_recovery import interrupted_pull_marker
    from hermes_cli.update_host_obligation import _owed_path
    from hermes_cli.update_lock import update_marker_path
    from hermes_cli.venv_sync import completion_pending_path

    paths = [completion_pending_path(source), source / ".update-incomplete",
             source / ".lazy-refresh-incomplete", interrupted_pull_marker(source),
             update_marker_path(), _owed_path()]
    for path in paths:
        if path.exists() or path.is_symlink():
            raise ValueError("Pending runtime obligation: " + str(path))


def state_compatibility():
    from hermes_constants import get_default_hermes_root
    from hermes_cli.update_receipt import _profile_homes
    from hermes_state import SessionDB

    checks = []
    for name, home in _profile_homes():
        state = home / "state.db"
        if state.exists():
            db = SessionDB(db_path=state, read_only=True)
            db.close()
            checks.append({"profile": name, "session_reader": True})
    root = get_default_hermes_root()
    for path in [root / "kanban.db", *root.glob("kanban/boards/*/kanban.db")]:
        if path.exists():
            with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as conn:
                if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise ValueError("Unreadable persisted board")
                conn.execute("SELECT id,status FROM tasks LIMIT 1").fetchall()
            checks.append({"board_reader": True, "path": str(path)})
    return checks


def runtime_ready(source, expected, allow_gaps=False, child=False):
    if os.environ.get("HERMES_DISABLE_LAZY_INSTALLS") != "1":
        raise ValueError("Readiness requires lazy installs disabled before launch")
    pending(source)
    select_source(source)
    import pm
    from pm.environments import running_from_selected_environment, selected_venv

    if not pm.venv_is_current(project_root=source):
        raise ValueError("PM dependency stamp missing or stale")
    launcher = source / ".hermes/bin/hermes"
    if not child:
        command = json.loads(subprocess.run([str(launcher), "--print-runtime-command", "--module", "hermes_cli.main"],
                             check=True, capture_output=True, text=True, encoding="utf-8", timeout=180).stdout)
        if str(source) not in command[3]:
            raise ValueError("Launcher refers to another source")
        code = ("import runpy,sys; sys.argv=" + repr([str(ROOT / "scripts/verify_kanban_runtime_contracts.py"),
                "--runtime-ready", "--readiness-child", "--source", str(source), "--expected-sha", expected]
                + (["--allow-baseline-contract-gaps"] if allow_gaps else []))
                + "; runpy.run_path(sys.argv[0],run_name='__main__')")
        from hermes_cli._launchers import runtime_command
        argv = runtime_command(source, code=code, python=command[0])
        result = subprocess.run(argv, check=True, capture_output=True, text=True, encoding="utf-8", timeout=180)
        report = json.loads(result.stdout)
        if report.get("ok") is not True:
            raise ValueError("Fresh launcher child not ready")
        return {**report["readiness"], "launcher": str(launcher), "fresh_child": True}
    if not running_from_selected_environment(source):
        raise ValueError("Not the PM-selected interpreter")
    from pm.recovery import STARTUP_IMPORTS
    from hermes_cli.update_cmd_validation import _UPDATE_CRITICAL_MODULES

    for _, module, attribute in STARTUP_IMPORTS:
        getattr(importlib.import_module(module), attribute)
    for name in _UPDATE_CRITICAL_MODULES:
        importlib.import_module(name)
    pending(source)
    return {"ready": True, "selected_environment": str(selected_venv(source)),
            "interpreter": sys.executable, "dependency_stamp_current": True,
            "critical_imports": list(_UPDATE_CRITICAL_MODULES), "state_readers": state_compatibility()}


def isolated_contracts(source):
    select_source(source)
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect_closing
    from tools.registry import registry
    from agent.delegation_context import kanban_path_is_fenced

    with tempfile.TemporaryDirectory(prefix="contracts-", dir=source) as directory:
        temporary = Path(directory)
        db = temporary / "board/kanban.db"
        if kanban_path_is_fenced(db) or str(db) == os.environ.get("HERMES_KANBAN_DB"):
            raise ValueError("Temporary board is fenced")
        saved = {k: os.environ.get(k) for k in ("HERMES_HOME", "HERMES_KANBAN_DB", "HERMES_KANBAN_TASK")}
        # A private board is a new owner, not permission to clear a delegated fence.
        if os.environ.get("HERMES_KANBAN_TASK"):
            raise ValueError("Isolated dispatch requires an isolated worker process")
        try:
            os.environ["HERMES_HOME"] = str(temporary / "home")
            os.environ["HERMES_KANBAN_DB"] = str(db)
            with connect_closing(db_path=db) as conn:
                tid = kb.create_task(conn, title="isolated contract")
                kb.claim_task(conn, tid)
                payload = bytes(range(256)) * 1000
                src = temporary / "evidence.bin"
                src.write_bytes(payload)
                hashes = []
                for args in ({"path": str(src)}, {"filename": "inline.bin", "content_base64": base64.b64encode(payload).decode()}):
                    result = json.loads(registry.dispatch("kanban_attach", {"task_id": tid, **args}))
                    if result.get("ok") is not True:
                        raise ValueError("Attachment dispatch refused")
                    row = conn.execute("SELECT stored_path FROM task_attachments WHERE id=?", (result["attachment_id"],)).fetchone()
                    data = Path(row[0]).read_bytes()
                    if data != payload:
                        raise ValueError("Attachment bytes changed")
                    hashes.append({"size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
                before = conn.execute("SELECT COUNT(*) FROM task_attachments").fetchone()[0]
                bad = json.loads(registry.dispatch("kanban_attach", {"task_id": tid, "path": str(src), "content_base64": "aGk="}))
                if "error" not in bad or conn.execute("SELECT COUNT(*) FROM task_attachments").fetchone()[0] != before:
                    raise ValueError("Refusal changed storage")
                url = "https://github.com/example/project/pull/42"
                result = json.loads(registry.dispatch("kanban_complete", {"task_id": tid, "summary": "isolated contract",
                    "published_pr": url, "metadata": {"findings": [{"details": {"passed": True}}]}}))
                run = kb.latest_run(conn, tid)
                if result.get("ok") is not True or run.metadata != {"published_pr": url, "findings": [{"details": {"passed": True}}]}:
                    raise ValueError("Completion normalization changed")
                return {"attachment_hashes": hashes, "refusal_unchanged": True, "pr_normalization": True}
        finally:
            for key, value in saved.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--read-only", action="store_true")
    modes.add_argument("--runtime-ready", action="store_true")
    modes.add_argument("--rehearse-update", action="store_true")
    parser.add_argument("--source", type=Path, default=ROOT)
    parser.add_argument("--expected-sha")
    parser.add_argument("--selection-only", action="store_true")
    parser.add_argument("--allow-baseline-contract-gaps", action="store_true")
    parser.add_argument("--readiness-child", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--target-mode", choices=("local-fixture", "published-fork"))
    parser.add_argument("--candidate")
    parser.add_argument("--installed")
    parser.add_argument("--output", type=Path)
    options = parser.parse_args(argv)
    try:
        source = options.source.resolve()
        if options.rehearse_update:
            from scripts.kanban_update_rehearsal import rehearse
            report = rehearse(options)
        else:
            report = source_identity(source, options.expected_sha or git(source, "rev-parse", "HEAD"))
            report.update(schema_contracts(source, options.allow_baseline_contract_gaps))
            if options.selection_only:
                report["selection"] = selection(source)
            if options.runtime_ready:
                report["readiness"] = runtime_ready(source, options.expected_sha, options.allow_baseline_contract_gaps, options.readiness_child)
            elif not options.read_only:
                report.update(isolated_contracts(source))
        report.update(schema_version=1, ok=True)
        code = 0
    except (AssertionError, OSError, ValueError, KeyError, ImportError, subprocess.SubprocessError) as exc:
        report = {"schema_version": 1, "ok": False, "error_type": type(exc).__name__, "detail": str(exc)}
        code = 1
    output = json.dumps(report, indent=2) + "\n"
    if options.output:
        options.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return code


if __name__ == "__main__":
    sys.path.insert(0, str(ROOT))
    raise SystemExit(main())
