"""Model-facing completion metadata and durable registry handoff contracts."""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

pytest_plugins = ("tests.hermes_cli.test_kanban_pr_acceptance",)


@pytest.fixture
def worker_board(tmp_path, monkeypatch):
    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_connect as kbc

    home = tmp_path / "hermes"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("HERMES_PROFILE", "test-worker")
    monkeypatch.setenv("HERMES_KANBAN_BOARD", "metadata-contract")
    monkeypatch.delenv("HERMES_KANBAN_DB", raising=False)
    monkeypatch.delenv("HERMES_SESSION_ID", raising=False)
    kb.create_board("metadata-contract")
    with kbc.connect_closing(board="metadata-contract") as conn:
        tid = kb.create_task(conn, title="metadata handoff", assignee="test-worker")
        claimed = kb.claim_task(conn, tid)
        assert claimed.status == "running"
        run_id = kb.latest_run(conn, tid).id
    monkeypatch.setenv("HERMES_KANBAN_TASK", tid)
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(run_id))
    return tid


def test_sanitized_handoff_metadata_explicitly_allows_caller_keys(worker_board):
    from tools import kanban_tools
    from tools.registry import invalidate_check_fn_cache, registry
    from tools.schema_sanitizer import sanitize_tool_schemas

    invalidate_check_fn_cache()
    schemas = sanitize_tool_schemas(registry.get_definitions(
        {"kanban_complete", "kanban_request_review"}, quiet=True))
    metadata = {
        schema["function"]["name"]:
        schema["function"]["parameters"]["properties"]["metadata"]
        for schema in schemas
    }
    assert set(metadata) == {"kanban_complete", "kanban_request_review"}
    for name, declaration in metadata.items():
        assert declaration["type"] == "object", name
        assert declaration.get("additionalProperties") is True, name


def test_registry_completion_persists_nested_caller_metadata(worker_board):
    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_connect as kbc
    from tools import kanban_tools
    from tools.registry import registry

    metadata = {
        "published_pr": "https://github.com/example/project/pull/42",
        "findings": [{"severity": "P2", "details": {"paths": ["tools/contract.py"]}}],
        "caller_context": {"labels": ["backend", "reviewed"], "passed": True, "count": 3},
    }
    out = json.loads(registry.dispatch("kanban_complete", {
        "summary": "Persist structured completion facts.", "metadata": metadata,
    }))
    assert out["ok"] is True, out
    assert out["task_id"] == worker_board
    with kbc.connect_closing(board="metadata-contract") as conn:
        assert kb.get_task(conn, worker_board).status == "done"
        run = kb.latest_run(conn, worker_board)
        assert run.outcome == "completed"
        assert run.summary == "Persist structured completion facts."
        assert run.metadata == {
            "published_pr": "https://github.com/example/project/pull/42",
            "findings": [{"severity": "P2", "details": {"paths": ["tools/contract.py"]}}],
            "caller_context": {"labels": ["backend", "reviewed"], "passed": True, "count": 3},
        }


PR_URL = "https://github.com/acme/repo/pull/7"


def _completion_snapshot(conn, tid):
    from hermes_cli import kanban_db as kb

    return {
        "task": dict(conn.execute("SELECT * FROM tasks WHERE id=?", (tid,)).fetchone()),
        "runs": [dict(row) for row in conn.execute(
            "SELECT * FROM task_runs WHERE task_id=? ORDER BY id", (tid,))],
        "events": [dict(row) for row in conn.execute(
            "SELECT * FROM task_events WHERE task_id=? ORDER BY id", (tid,))],
        "attachments": [(dict(row), Path(row["stored_path"]).read_bytes()) for row in conn.execute(
            "SELECT * FROM task_attachments WHERE task_id=? ORDER BY id", (tid,))],
    }


def _dispatch_task(conn, monkeypatch):
    from hermes_cli import kanban_db as kb

    tid = kb.create_task(conn, title="registry publication", completion_contract="acme/repo")
    claimed = kb.claim_task(conn, tid)
    monkeypatch.setenv("HERMES_KANBAN_TASK", tid)
    monkeypatch.setenv("HERMES_KANBAN_RUN_ID", str(claimed.current_run_id))
    monkeypatch.delenv("HERMES_SESSION_ID", raising=False)
    kb.store_attachment_bytes(conn, tid, "retained.bin", b"existing artifact\x00")
    return tid


@pytest.mark.platforms("linux")
@pytest.mark.parametrize("source", ["top-level", "top-level-no-metadata", "metadata", "matching"])
def test_registry_completion_normalizes_publication(github, monkeypatch, source):
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from tools import kanban_tools
    from tools.registry import registry

    with connect() as conn:
        tid = _dispatch_task(conn, monkeypatch)
        metadata = {"findings": [{"severity": "P2", "paths": ["tools/example.py"]}]}
        args = {"summary": "Verified publication."}
        if source != "top-level-no-metadata":
            args["metadata"] = metadata
        if source != "metadata":
            args["published_pr"] = PR_URL
        if source in {"metadata", "matching"}:
            metadata["published_pr"] = PR_URL
        original = copy.deepcopy(args)
        before = _completion_snapshot(conn, tid)
        out = json.loads(registry.dispatch("kanban_complete", args))
        assert out.get("ok") is True, out
        assert args == original
        assert kb.get_task(conn, tid).status == "done"
        assert kb.get_task(conn, tid).completion_contract == PR_URL
        run = kb.latest_run(conn, tid)
        assert run.outcome == "completed"
        expected = {"published_pr": PR_URL}
        if source != "top-level-no-metadata":
            expected["findings"] = [{"severity": "P2", "paths": ["tools/example.py"]}]
        assert run.metadata == expected
        receipt = json.loads(conn.execute(
            "SELECT payload FROM task_events WHERE task_id=? AND kind='pr_acceptance'",
            (tid,)).fetchone()[0])
        assert (receipt["ok"], receipt["classification"], receipt["pr_url"], receipt["head_sha"]) == (
            True, "success", PR_URL, "a" * 40)
        assert _completion_snapshot(conn, tid)["attachments"] == before["attachments"]


@pytest.mark.platforms("linux")
@pytest.mark.parametrize("case,error", [
    ("conflict", "published_pr conflicts with metadata.published_pr"),
    ("invalid-metadata", "metadata must be an object/dict"),
    ("absent", "PR acceptance missing"),
    ("uncertified", "PR acceptance failure"),
])
def test_registry_completion_refuses_invalid_publication(github, monkeypatch, case, error):
    from hermes_cli import kanban_db as kb
    from hermes_cli.kanban_db_connect import connect
    from tools import kanban_tools
    from tools.registry import registry

    with connect() as conn:
        tid = _dispatch_task(conn, monkeypatch)
        args = {"summary": "Publication must be certified.", "metadata": {"notes": ["keep"]}}
        if case != "absent":
            args["published_pr"] = PR_URL
        if case == "conflict":
            args["metadata"]["published_pr"] = "https://github.com/acme/repo/pull/8"
        elif case == "invalid-metadata":
            args["metadata"] = ["not an object"]
        elif case == "uncertified":
            github["conclusion"] = "failure"
        original = copy.deepcopy(args)
        before = _completion_snapshot(conn, tid)
        out = json.loads(registry.dispatch("kanban_complete", args))
        assert error in out.get("error", ""), out
        assert args == original
        after = _completion_snapshot(conn, tid)
        assert kb.get_task(conn, tid).status == "running"
        assert after["runs"] == before["runs"]
        assert after["attachments"] == before["attachments"]
        if case in {"conflict", "invalid-metadata"}:
            assert after == before
        else:
            receipt = json.loads(conn.execute(
                "SELECT payload FROM task_events WHERE task_id=? AND kind='pr_acceptance'",
                (tid,)).fetchone()[0])
            assert receipt["ok"] is False
            assert receipt["classification"] == ("missing" if case == "absent" else "failure")
