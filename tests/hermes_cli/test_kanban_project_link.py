"""Kanban <-> Projects integration: project-linked tasks get a deterministic
worktree path + branch instead of the random ``wt/<task-id>`` fallback, and an
operator can bind an existing null-linked card that lost its project at creation.

Test-value gate for the ``bind-project`` tests added below (one answer per
added/checked contract, recorded here because the repair sibling is the subject):

1. Behaviour protected: the literal resulting binding (project plus KV-derived
   worktree path and branch) and every field/edge/history the repair must not
   touch, plus the receipt event that makes the change attributable.
2. Credible regression: a silent no-op (no binding written), a partial write
   (binding without the event), an unsafe rebind of a started or differently
   linked card, a repair without effective dispatch exclusion, and a replay that
   writes a second event.
3. Existing coverage misses it: ``create_task`` tests only cover creation-time
   linking; nothing repairs an existing row, and no test proves the refusal
   surface or the receipt.
4. No test-only production seam: every test drives the same public
   ``bind_project``/CLI entry points production uses, real SQLite and a real git
   repository. The two race tests patch read helpers to *simulate* interleaving;
   the write path stays real.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc
from hermes_cli import projects_db as pdb

ROOT = Path(__file__).parents[2]
_REASON = "plan ff29c573 + card t_49bd91a7"


@pytest.fixture
def kanban_conn(tmp_path):
    c = kbc.connect(db_path=tmp_path / "kanban.db")
    try:
        yield c
    finally:
        c.close()


def _make_project(name="Web App", repo="/tmp/webapp", board_slug=None):
    with pdb.connect_closing() as pc:
        pid = pdb.create_project(pc, name=name, folders=[repo], board_slug=board_slug)
        project = pdb.get_project(pc, pid)
        assert project is not None
        return project


def test_project_linked_task_gets_deterministic_worktree_and_branch(kanban_conn):
    proj = _make_project()
    tid = kb.create_task(kanban_conn, title="Add login", project_id=proj.slug)
    task = kb.get_task(kanban_conn, tid)

    assert task.project_id == proj.id
    assert task.workspace_kind == "worktree"
    # Worktree dir anchored under the project's primary repo, keyed on task id.
    assert task.workspace_path == os.path.join(proj.primary_path, ".worktrees", tid)
    # Deterministic branch: <slug>/<task-id>-<title-slug>. NOT a random wt/...
    assert task.branch_name == f"{proj.slug}/{tid}-add-login"
    assert not task.branch_name.startswith("wt/")


def test_explicit_branch_overrides_project_default(kanban_conn):
    proj = _make_project()
    tid = kb.create_task(
        kanban_conn,
        title="x",
        project_id=proj.slug,
        workspace_kind="worktree",
        branch_name="feature/custom",
    )
    task = kb.get_task(kanban_conn, tid)
    assert task.branch_name == "feature/custom"


def test_unlinked_task_unchanged(kanban_conn):
    tid = kb.create_task(kanban_conn, title="plain")
    task = kb.get_task(kanban_conn, tid)

    assert task.project_id is None
    assert task.workspace_kind == "scratch"
    # No branch is persisted — the worker still owns the wt/<id> fallback for
    # genuinely ad-hoc worktree tasks, but unlinked scratch tasks have none.
    assert task.branch_name is None


# ---------------------------------------------------------------------------
# Operator-only repair of a null project binding (``kanban bind-project``)
# ---------------------------------------------------------------------------


def _kpb():
    """The repair sibling, imported late so a pre-delivery tree still collects."""
    from hermes_cli import kanban_project_binding as kpb

    return kpb


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True, timeout=60,
    )


@pytest.fixture
def git_repo(tmp_path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    return repo


@pytest.fixture
def project(git_repo) -> pdb.Project:
    return _make_project(repo=str(git_repo), board_slug=kb.get_current_board())


def _nominated_card(conn, workspace_path, *, title="Repair the project link", **kwargs):
    """An unstarted ``todo`` card parked behind a blocked parent, as the incident had."""
    gate = kb.create_task(conn, title="blocked gate", initial_status="blocked")
    return kb.create_task(
        conn,
        title=title,
        workspace_kind="worktree",
        workspace_path=str(workspace_path),
        parents=(gate,),
        **kwargs,
    )


def _row(conn, task_id) -> dict:
    return dict(conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone())


def _events(conn, task_id, kind=None) -> list[dict]:
    sql = "SELECT id, kind, payload, created_at FROM task_events WHERE task_id = ?"
    params: list = [task_id]
    if kind:
        sql += " AND kind = ?"
        params.append(kind)
    return [dict(row) for row in conn.execute(sql + " ORDER BY id", params)]


def _bind(conn, card, project, overrides=None):
    """Call the repair with the plan's arguments, plus any per-test overrides."""
    kwargs = dict(
        task_id=card.id,
        project=project.id,
        expected_workspace=project.primary_path,
        expected_branch_null=True,
        reason=_REASON,
        actor="twohomes-coder",
        board=kb.get_current_board(),
    )
    kwargs.update(overrides or {})
    return _kpb().bind_project(conn, **kwargs)


def _reasons(conn, card, project, overrides=None) -> str:
    with pytest.raises(_kpb().BindingRefused) as excinfo:
        _bind(conn, card, project, overrides)
    return " | ".join(excinfo.value.reasons)


def _assert_untouched(conn, task_id, *, row, events) -> None:
    assert _row(conn, task_id) == row
    assert _events(conn, task_id) == events


def test_bind_project_applies_the_canonical_binding_and_preserves_the_card(
    kanban_conn, project, git_repo,
):
    gate = kb.create_task(kanban_conn, title="blocked gate", initial_status="blocked")
    tid = kb.create_task(
        kanban_conn, title="Repair the project link", body="operator-nominated card",
        assignee="twohomes-coder", created_by="twohomes-planner", workspace_kind="worktree",
        workspace_path=str(git_repo), parents=(gate,), tenant="twohomes", priority=80,
        skills=["twohomes-kanban-policy"], max_runtime_seconds=86400, session_id="local-session",
        completion_contract="superaitaotao/hermes-agent",
    )
    child = kb.create_task(kanban_conn, title="child of the repair", parents=(tid,))
    card = kb.get_task(kanban_conn, tid)
    assert card.status == "todo"
    before, events_before = _row(kanban_conn, tid), _events(kanban_conn, tid)

    result = _bind(kanban_conn, card, project)

    expected_new = {
        "project_id": project.id,
        "workspace_path": str(git_repo / ".worktrees" / tid),
        "branch_name": f"{project.slug}/{tid}-repair-the-project-link",
    }
    assert result["status"] == "applied"
    assert result["new"] == expected_new
    assert result["old"] == {
        "project_id": None, "workspace_path": str(git_repo), "branch_name": None,
    }
    after = _row(kanban_conn, tid)
    assert {column: after[column] for column in expected_new} == expected_new
    # Every other column, including the fields a naive re-create would drop.
    assert {
        column: value for column, value in after.items()
        if column not in {"project_id", "workspace_path", "branch_name"}
    } == {
        column: value for column, value in before.items()
        if column not in {"project_id", "workspace_path", "branch_name"}
    }
    assert after["status"] == "todo"
    assert after["claim_lock"] is None and after["worker_pid"] is None
    assert after["current_run_id"] is None
    # Graph, history and receipt.
    assert kb.parent_ids(kanban_conn, tid) == [gate]
    assert kb.child_ids(kanban_conn, tid) == [child]
    events_after = _events(kanban_conn, tid)
    assert events_after[: len(events_before)] == events_before
    receipts = _events(kanban_conn, tid, "project_bound")
    assert len(receipts) == 1
    payload = json.loads(receipts[0]["payload"])
    assert payload["old"] == result["old"]
    assert payload["new"] == expected_new
    assert payload["actor"] == "twohomes-coder"
    assert payload["reason"] == _REASON
    assert payload["source"] == {
        "kind": "canonical_project_store",
        "store": str(pdb.projects_db_path()),
        "project_id": project.id,
        "project_slug": project.slug,
        "board_slug": kb.get_current_board(),
        "primary_path": project.primary_path,
    }
    assert result["receipt"]["event_id"] == receipts[0]["id"]
    assert result["readback"]["task"]["project_id"] == project.id
    assert result["readback"]["parents"] == [gate]
    # The repair records the binding; the worker still creates the worktree.
    assert not (git_repo / ".worktrees").exists()


def test_bind_project_dry_run_reports_the_binding_without_writing(kanban_conn, project, git_repo):
    tid = _nominated_card(kanban_conn, git_repo)
    card = kb.get_task(kanban_conn, tid)
    row, events = _row(kanban_conn, tid), _events(kanban_conn, tid)

    result = _bind(kanban_conn, card, project, {"dry_run": True})

    assert result["status"] == "dry_run"
    assert result["new"]["project_id"] == project.id
    assert result["receipt"] is None and result["readback"] is None
    _assert_untouched(kanban_conn, tid, row=row, events=events)


def test_bind_project_replay_returns_the_durable_receipt_once(kanban_conn, project, git_repo):
    tid = _nominated_card(kanban_conn, git_repo)
    card = kb.get_task(kanban_conn, tid)
    applied = _bind(kanban_conn, card, project)
    row_after_apply = _row(kanban_conn, tid)

    replayed = _bind(kanban_conn, card, project)

    assert replayed["status"] == "replayed"
    assert replayed["new"] == applied["new"]
    assert replayed["receipt"]["event_id"] == applied["receipt"]["event_id"]
    assert _row(kanban_conn, tid) == row_after_apply
    assert len(_events(kanban_conn, tid, "project_bound")) == 1


def test_bind_project_refuses_a_matching_binding_without_a_receipt(kanban_conn, project, git_repo):
    tid = _nominated_card(kanban_conn, git_repo)
    card = kb.get_task(kanban_conn, tid)
    _bind(kanban_conn, card, project)
    with kb.write_txn(kanban_conn):
        kanban_conn.execute(
            "DELETE FROM task_events WHERE task_id = ? AND kind = 'project_bound'", (tid,),
        )
    row, events = _row(kanban_conn, tid), _events(kanban_conn, tid)

    assert "receipt_missing" in _reasons(kanban_conn, card, project)

    _assert_untouched(kanban_conn, tid, row=row, events=events)


def test_bind_project_never_claims_a_normally_created_project_card(kanban_conn, project):
    """A card the normal create path linked carries no receipt, so it is not 'replayed'."""
    tid = kb.create_task(kanban_conn, title="created with project", project_id=project.id)
    card = kb.get_task(kanban_conn, tid)
    assert card.project_id == project.id
    row, events = _row(kanban_conn, tid), _events(kanban_conn, tid)

    assert "receipt_missing" in _reasons(kanban_conn, card, project)

    _assert_untouched(kanban_conn, tid, row=row, events=events)


def test_bind_project_refuses_a_card_that_already_started(kanban_conn, project, git_repo):
    tid = kb.create_task(
        kanban_conn, title="ready card", workspace_kind="worktree", workspace_path=str(git_repo),
    )
    card = kb.get_task(kanban_conn, tid)
    assert card.status == "ready"
    row, events = _row(kanban_conn, tid), _events(kanban_conn, tid)

    assert "task_not_todo" in _reasons(kanban_conn, card, project)

    _assert_untouched(kanban_conn, tid, row=row, events=events)


def test_bind_project_refuses_a_claimed_card_with_a_live_worker(kanban_conn, project, git_repo):
    from hermes_cli import kanban_db_dispatch as kbd

    tid = kb.create_task(
        kanban_conn, title="claimed card", workspace_kind="worktree", workspace_path=str(git_repo),
    )
    assert kb.claim_task(kanban_conn, tid) is not None
    kbd._set_worker_pid(kanban_conn, tid, os.getpid())
    card = kb.get_task(kanban_conn, tid)
    row, events = _row(kanban_conn, tid), _events(kanban_conn, tid)

    reasons = _reasons(kanban_conn, card, project)

    assert "task_not_inactive" in reasons
    assert "worker_still_running" in reasons
    _assert_untouched(kanban_conn, tid, row=row, events=events)


def test_bind_project_refuses_when_process_inspection_is_unavailable(
    kanban_conn, project, git_repo, monkeypatch,
):
    from hermes_cli import kanban_db_dispatch as kbd

    kpb = _kpb()
    tid = kb.create_task(
        kanban_conn, title="worker card", workspace_kind="worktree", workspace_path=str(git_repo),
    )
    assert kb.claim_task(kanban_conn, tid) is not None
    kbd._set_worker_pid(kanban_conn, tid, os.getpid())
    monkeypatch.setattr(kpb, "_pid_state", lambda pid, started_at: "unknown")

    assert "process_inspection_unavailable" in _reasons(
        kanban_conn, kb.get_task(kanban_conn, tid), project,
    )


def test_bind_project_refuses_an_archived_project(kanban_conn, project, git_repo):
    tid = _nominated_card(kanban_conn, git_repo)
    card = kb.get_task(kanban_conn, tid)
    with pdb.connect_closing() as pc:
        assert pdb.archive_project(pc, project.id) is True
    row, events = _row(kanban_conn, tid), _events(kanban_conn, tid)

    assert "project_archived" in _reasons(kanban_conn, card, project)

    _assert_untouched(kanban_conn, tid, row=row, events=events)


def test_bind_project_refuses_a_project_scoped_to_another_board(kanban_conn, git_repo):
    other = _make_project(name="Other Board Project", repo=str(git_repo), board_slug="elsewhere")
    tid = _nominated_card(kanban_conn, git_repo)
    card = kb.get_task(kanban_conn, tid)

    assert "project_board_mismatch" in _reasons(kanban_conn, card, other)


def test_bind_project_refuses_a_project_without_a_board(kanban_conn, project, git_repo):
    unrelated_repo = git_repo.parent / "unscoped-repo"
    unrelated_repo.mkdir()
    unscoped = _make_project(name="Unscoped", repo=str(unrelated_repo))
    assert unscoped.board_slug is None
    tid = _nominated_card(kanban_conn, git_repo)

    assert "project_board_mismatch" in _reasons(kanban_conn, kb.get_task(kanban_conn, tid), unscoped)
    assert project.id != unscoped.id


def test_bind_project_refuses_an_unknown_project(kanban_conn, project, git_repo):
    tid = _nominated_card(kanban_conn, git_repo)

    assert "project_not_found" in _reasons(
        kanban_conn, kb.get_task(kanban_conn, tid), project, {"project": "p_0badc0de"},
    )


def test_bind_project_refuses_a_conflicting_existing_binding(kanban_conn, project, tmp_path):
    other_repo = tmp_path / "other-repo"
    other_repo.mkdir()
    _git(other_repo, "init", "-q")
    other = _make_project(name="Other", repo=str(other_repo), board_slug=kb.get_current_board())
    tid = kb.create_task(kanban_conn, title="bound elsewhere", project_id=other.id)
    card = kb.get_task(kanban_conn, tid)
    assert card.project_id == other.id
    row, events = _row(kanban_conn, tid), _events(kanban_conn, tid)

    assert "conflicting_binding" in _reasons(kanban_conn, card, project)

    _assert_untouched(kanban_conn, tid, row=row, events=events)


def test_bind_project_refuses_an_anchor_that_is_not_the_project_root(
    kanban_conn, project, tmp_path,
):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    tid = _nominated_card(kanban_conn, elsewhere)
    card = kb.get_task(kanban_conn, tid)
    row, events = _row(kanban_conn, tid), _events(kanban_conn, tid)

    reasons = _reasons(kanban_conn, card, project)

    assert "task_not_at_project_root" in reasons
    assert "expected_workspace_mismatch" in reasons
    _assert_untouched(kanban_conn, tid, row=row, events=events)


def test_bind_project_refuses_a_wrong_expected_workspace(kanban_conn, project, git_repo, tmp_path):
    tid = _nominated_card(kanban_conn, git_repo)
    card = kb.get_task(kanban_conn, tid)

    reasons = _reasons(
        kanban_conn, card, project, {"expected_workspace": str(tmp_path / "not-here")},
    )

    assert "expected_workspace_mismatch" in reasons
    assert "task_not_at_project_root" not in reasons


def test_bind_project_refuses_a_non_worktree_card(kanban_conn, project):
    gate = kb.create_task(kanban_conn, title="gate", initial_status="blocked")
    tid = kb.create_task(kanban_conn, title="scratch card", parents=(gate,))
    card = kb.get_task(kanban_conn, tid)
    assert card.workspace_kind == "scratch"

    assert "task_not_worktree" in _reasons(kanban_conn, card, project)


def test_bind_project_requires_actor_reason_and_the_null_branch_assertion(
    kanban_conn, project, git_repo,
):
    tid = _nominated_card(kanban_conn, git_repo)
    card = kb.get_task(kanban_conn, tid)
    row, events = _row(kanban_conn, tid), _events(kanban_conn, tid)

    reasons = _reasons(
        kanban_conn, card, project,
        {"reason": "  ", "actor": "", "expected_branch_null": False},
    )

    assert "reason_missing" in reasons
    assert "actor_missing" in reasons
    assert "expected_branch_null_required" in reasons
    _assert_untouched(kanban_conn, tid, row=row, events=events)


def test_bind_project_refuses_an_existing_target_directory(kanban_conn, project, git_repo):
    tid = _nominated_card(kanban_conn, git_repo)
    card = kb.get_task(kanban_conn, tid)
    (git_repo / ".worktrees" / tid).mkdir(parents=True)
    row, events = _row(kanban_conn, tid), _events(kanban_conn, tid)

    assert "target_path_exists" in _reasons(kanban_conn, card, project)

    _assert_untouched(kanban_conn, tid, row=row, events=events)


def test_bind_project_refuses_an_existing_target_branch(kanban_conn, project, git_repo):
    tid = _nominated_card(kanban_conn, git_repo)
    card = kb.get_task(kanban_conn, tid)
    branch = f"{project.slug}/{tid}-repair-the-project-link"
    _git(git_repo, "-c", "user.email=w01@example.com", "-c", "user.name=w01",
         "commit", "--allow-empty", "-m", "init")
    _git(git_repo, "branch", branch)
    row, events = _row(kanban_conn, tid), _events(kanban_conn, tid)

    assert "target_branch_exists" in _reasons(kanban_conn, card, project)

    _assert_untouched(kanban_conn, tid, row=row, events=events)


def test_bind_project_refuses_an_ambiguous_repository_identity(kanban_conn, tmp_path):
    plain = tmp_path / "plain-dir"
    plain.mkdir()
    project = _make_project(name="Not A Repo", repo=str(plain), board_slug=kb.get_current_board())
    tid = _nominated_card(kanban_conn, plain)
    card = kb.get_task(kanban_conn, tid)
    row, events = _row(kanban_conn, tid), _events(kanban_conn, tid)

    assert "ambiguous_repository_identity" in _reasons(kanban_conn, card, project)

    _assert_untouched(kanban_conn, tid, row=row, events=events)


def test_bind_project_refuses_while_another_dispatcher_holds_the_lock(
    kanban_conn, project, git_repo,
):
    tid = _nominated_card(kanban_conn, git_repo)
    card = kb.get_task(kanban_conn, tid)
    row, events = _row(kanban_conn, tid), _events(kanban_conn, tid)
    db_file_name = kbc._main_db_file(kanban_conn)
    assert db_file_name
    db_file = Path(db_file_name)

    with kbc._dispatch_tick_lock(db_file) as held:
        assert held is True
        assert "dispatch_exclusion_busy" in _reasons(kanban_conn, card, project)

    _assert_untouched(kanban_conn, tid, row=row, events=events)


def test_bind_project_refuses_a_no_op_dispatch_lock(kanban_conn, project, git_repo, monkeypatch):
    tid = _nominated_card(kanban_conn, git_repo)
    card = kb.get_task(kanban_conn, tid)
    row, events = _row(kanban_conn, tid), _events(kanban_conn, tid)

    @contextlib.contextmanager
    def _fake_lock(db_path):
        yield True  # the real lock is genuinely free: the probe must catch this

    monkeypatch.setattr(kbc, "_dispatch_tick_lock", _fake_lock)

    assert "dispatch_exclusion_unavailable" in _reasons(kanban_conn, card, project)
    _assert_untouched(kanban_conn, tid, row=row, events=events)


def test_bind_project_rolls_back_the_row_and_receipt_on_a_failed_write(
    kanban_conn, project, git_repo,
):
    tid = _nominated_card(kanban_conn, git_repo)
    card = kb.get_task(kanban_conn, tid)
    row, events = _row(kanban_conn, tid), _events(kanban_conn, tid)
    kanban_conn.execute(
        "CREATE TRIGGER refuse_project_bound BEFORE INSERT ON task_events "
        "WHEN NEW.kind = 'project_bound' BEGIN SELECT RAISE(ABORT, 'receipt refused'); END"
    )

    with pytest.raises(sqlite3.Error):
        _bind(kanban_conn, card, project)

    _assert_untouched(kanban_conn, tid, row=row, events=events)


def test_bind_project_refuses_a_card_changed_between_validation_and_apply(
    kanban_conn, project, git_repo, monkeypatch, tmp_path,
):
    kpb = _kpb()
    tid = _nominated_card(kanban_conn, git_repo)
    card = kb.get_task(kanban_conn, tid)
    stale = kpb._load_card(kanban_conn, tid)
    moved = str(tmp_path / "moved-elsewhere")
    # A stale validation read plus a no-op revalidation is the interleaving the
    # CAS predicate exists for; the UPDATE and the write path stay real.
    monkeypatch.setattr(kpb, "_load_card", lambda conn, task_id: stale)
    monkeypatch.setattr(kpb, "_revalidate", lambda conn, proposal: None)
    with kb.write_txn(kanban_conn):
        kanban_conn.execute("UPDATE tasks SET workspace_path = ? WHERE id = ?", (moved, tid))

    assert "concurrent_modification" in _reasons(kanban_conn, card, project)
    assert _row(kanban_conn, tid)["workspace_path"] == moved
    assert _events(kanban_conn, tid, "project_bound") == []


# ---------------------------------------------------------------------------
# CLI wiring: parser + profile-scoped canonical store + JSON (one subprocess)
# ---------------------------------------------------------------------------


def _run_hermes(home: Path, *args: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["HOME"] = str(home.parent)
    env["HERMES_HOME"] = str(home / ".hermes")
    env["HERMES_KANBAN_HOME"] = str(home / ".hermes")
    for name in (
        "HERMES_KANBAN_BOARD", "HERMES_KANBAN_DB", "HERMES_KANBAN_TASK",
        "HERMES_KANBAN_WORKSPACES_ROOT", "HERMES_DELEGATED_CHILD_CONTEXT",
    ):
        env.pop(name, None)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [sys.executable, "-m", "hermes_cli.main", *args],
        cwd=ROOT, env=env, capture_output=True, text=True, check=False, timeout=180,
    )


def _cli_task(run: subprocess.CompletedProcess) -> dict:
    assert run.returncode == 0, run.stderr
    return json.loads(run.stdout)


def test_cli_bind_project_dry_run_apply_and_replay(tmp_path, git_repo):
    home = tmp_path / "home"
    profile = "exp-agent"
    (home / ".hermes" / "profiles" / profile).mkdir(parents=True)
    (home / ".hermes" / "profiles" / profile / "config.yaml").write_text(
        "model: {}\n", encoding="utf-8",
    )
    assert _run_hermes(home, "kanban", "boards", "create", "two-homes").returncode == 0

    store = home / ".hermes" / "profiles" / profile / "projects.db"
    profile_store = pdb.connect(db_path=store)
    try:
        project_id = pdb.create_project(
            profile_store, name="Virtual Eric", folders=[str(git_repo)], board_slug="two-homes",
        )
    finally:
        profile_store.close()

    def kanban(*args: str) -> subprocess.CompletedProcess:
        return _run_hermes(home, "-p", profile, "kanban", "--board", "two-homes", *args)

    parent = _cli_task(kanban("create", "gate", "--initial-status", "blocked", "--json"))["id"]
    tid = _cli_task(kanban(
        "create", "Repair the project link", "--parent", parent,
        "--workspace", f"worktree:{git_repo}", "--json",
    ))["id"]
    bind_args = (
        "bind-project", tid, "--project", project_id,
        "--expected-workspace", str(git_repo), "--expected-branch-null",
        "--reason", _REASON,
    )

    dry = _cli_task(kanban(*bind_args, "--dry-run", "--json"))
    assert dry["status"] == "dry_run"
    assert dry["project"]["store"] == str(store)
    before = _cli_task(kanban("show", tid, "--json"))["task"]
    assert before["project_id"] is None and before["branch_name"] is None

    refused = kanban(
        *[str(git_repo / "not-the-root") if arg == str(git_repo) else arg for arg in bind_args],
        "--dry-run", "--json",
    )
    assert refused.returncode == 1, refused.stdout
    assert "expected_workspace_mismatch" in refused.stdout

    applied = _cli_task(kanban(*bind_args, "--json"))
    assert applied["status"] == "applied"
    after = _cli_task(kanban("show", tid, "--json"))
    assert after["task"]["project_id"] == project_id
    assert after["task"]["workspace_path"] == str(git_repo / ".worktrees" / tid)
    assert after["task"]["branch_name"] == f"virtual-eric/{tid}-repair-the-project-link"
    assert after["task"]["status"] == "todo"
    assert after["parents"] == [parent]

    replayed = _cli_task(kanban(*bind_args, "--json"))
    assert replayed["status"] == "replayed"
    assert replayed["receipt"]["event_id"] == applied["receipt"]["event_id"]
