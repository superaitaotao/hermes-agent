"""Operator-only repair of a null project binding on an existing Kanban card.

A cross-profile create can silently drop its project link: the project lives in
the creator's per-profile store, so ``create_task`` resolves nothing and the
board keeps an unstarted card with ``project_id``/``branch_name`` NULL and the
repository root as its worktree anchor. Re-creating the card would lose its id,
edges, history and approvals, so the repair binds an explicitly nominated card
in place: one row update plus one ``project_bound`` receipt event, under the
board's dispatch exclusion.

Only ``hermes kanban bind-project`` calls this. There is deliberately no native
tool, dashboard setter, global projects store, creation guard, migration or
backfill: every refusal below exists because the unchecked alternative silently
drops a link or rebinds a card someone is already running.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from hermes_cli import kanban_db as kb
from hermes_cli import kanban_db_connect as kbc
from hermes_cli import projects_db as pdb

PROJECT_BOUND_EVENT = "project_bound"
"""Audit-event kind that doubles as the durable, replay-visible receipt."""

_GIT_TIMEOUT_SECONDS = 30
_CARD_COLUMNS = (
    "id", "title", "status", "workspace_kind", "workspace_path", "branch_name",
    "project_id", "claim_lock", "claim_expires", "current_run_id",
    "worker_pid", "worker_started_at",
)
_BINDING_COLUMNS = ("project_id", "workspace_path", "branch_name")
# The predicate repeats every value revalidation just checked, so a writer that
# slipped between revalidation and this UPDATE cannot be overwritten.
_BIND_SQL = """
UPDATE tasks
   SET project_id = ?, workspace_path = ?, branch_name = ?
 WHERE id = ?
   AND project_id IS NULL
   AND branch_name IS NULL
   AND workspace_path = ?
   AND workspace_kind = 'worktree'
   AND status = ?
   AND claim_lock IS NULL
   AND claim_expires IS NULL
   AND worker_pid IS NULL
   AND current_run_id IS NULL
"""
_READBACK_FIELDS = (
    "id", "title", "status", "assignee", "created_by", "priority", "tenant",
    "workspace_kind", "workspace_path", "branch_name", "project_id", "skills",
    "session_id", "max_runtime_seconds", "completion_contract", "block_kind",
    "claim_lock", "claim_expires", "worker_pid", "current_run_id",
)


class BindingRefused(RuntimeError):
    """A nominated repair was refused; no row, event or file changed."""

    def __init__(self, reasons: list[str]):
        self.reasons = tuple(reasons)
        super().__init__("kanban bind-project refused: " + "; ".join(self.reasons))


@dataclass(frozen=True)
class _Card:
    """Guard view of the nominated row (only the columns this repair reads)."""

    id: str
    title: str
    status: str
    workspace_kind: str
    workspace_path: Optional[str]
    branch_name: Optional[str]
    project_id: Optional[str]
    claim_lock: Optional[str]
    claim_expires: Optional[int]
    current_run_id: Optional[int]
    worker_pid: Optional[int]
    worker_started_at: Optional[str]


@dataclass(frozen=True)
class _Project:
    """Canonical project identity, read from the selected profile's store."""

    record: pdb.Project
    primary_path: str
    store: str

    @property
    def id(self) -> str:
        return self.record.id

    @property
    def slug(self) -> str:
        return self.record.slug

    def as_source(self) -> dict[str, Any]:
        return {
            "kind": "canonical_project_store",
            "store": self.store,
            "project_id": self.record.id,
            "project_slug": self.record.slug,
            "board_slug": self.record.board_slug or "",
            "primary_path": self.primary_path,
        }


@dataclass(frozen=True)
class _Proposal:
    task_id: str
    old: Optional[dict[str, Any]]
    new: dict[str, Any]
    old_status: str
    project: _Project
    actor: str
    reason: str
    board: str


def bind_project(
    conn: sqlite3.Connection,
    *,
    task_id: str,
    project: str,
    expected_workspace: str,
    expected_branch_null: bool,
    reason: str,
    actor: str,
    board: Optional[str] = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Bind one nominated card with a null project/branch to its canonical project.

    ``status`` in the result is ``dry_run`` (validated, nothing written),
    ``applied`` (row updated + receipt appended) or ``replayed`` (the durable
    receipt of an earlier identical apply). Every refusal raises
    :class:`BindingRefused` before a write; the caller surfaces ``.reasons``.
    """
    board = (board or kb.get_current_board()).strip()
    _require_inputs(
        task_id=task_id, project=project, expected_workspace=expected_workspace,
        expected_branch_null=expected_branch_null, reason=reason, actor=actor,
    )
    card = _load_card(conn, task_id.strip())
    if card is None:
        raise BindingRefused([f"task_not_found: no card {task_id.strip()!r} on board {board!r}"])
    canonical = _load_project(project, board)
    target = _target_binding(canonical, card)
    if card.project_id is not None or card.branch_name is not None:
        return _existing_binding(
            conn, card=card, project=canonical, target=target, actor=actor, reason=reason, board=board,
        )
    reasons = (
        _card_refusals(conn, card)
        + _anchor_refusals(card, canonical, expected_workspace)
        + _target_refusals(canonical, target)
    )
    if reasons:
        raise BindingRefused(reasons)
    proposal = _Proposal(
        task_id=card.id,
        old={"project_id": None, "workspace_path": card.workspace_path, "branch_name": None},
        new=target,
        old_status=card.status,
        project=canonical,
        actor=actor.strip(),
        reason=reason.strip(),
        board=board,
    )
    if dry_run:
        return _result("dry_run", proposal, receipt=None, readback=None)
    with _dispatch_exclusion(conn):
        _revalidate(conn, proposal)
        _apply(conn, proposal)
        receipt = _receipt(conn, proposal.task_id, proposal.new)
        readback = _readback(conn, proposal.task_id)
    return _result("applied", proposal, receipt=receipt, readback=readback)


def refusal_result(exc: BindingRefused, *, task_id: str) -> dict[str, Any]:
    """JSON body for a refused run (shared by the CLI and its tests)."""
    return {"ok": False, "status": "refused", "task_id": task_id, "refused": list(exc.reasons)}


# ---------------------------------------------------------------------------
# Inputs and refusal predicates
# ---------------------------------------------------------------------------


def _require_inputs(
    *, task_id: str, project: str, expected_workspace: str, expected_branch_null: bool,
    reason: str, actor: str,
) -> None:
    required = (
        ((task_id or "").strip(), "task_id_missing: a task id is required"),
        ((project or "").strip(), "project_missing: --project is required"),
        ((expected_workspace or "").strip(), "expected_workspace_missing: --expected-workspace is required"),
        ((reason or "").strip(), "reason_missing: a reason is required (recorded on the receipt)"),
        ((actor or "").strip(), "actor_missing: an actor is required (recorded on the receipt)"),
    )
    missing = [reason_text for value, reason_text in required if not value]
    if not expected_branch_null:
        missing.append(
            "expected_branch_null_required: this verb repairs null bindings only; "
            "pass --expected-branch-null to assert it"
        )
    if missing:
        raise BindingRefused(missing)


def _existing_binding(
    conn: sqlite3.Connection, *, card: _Card, project: _Project, target: dict[str, Any],
    actor: str, reason: str, board: str,
) -> dict[str, Any]:
    """Replay path: a card that already carries a binding is never overwritten."""
    current = {column: getattr(card, column) for column in _BINDING_COLUMNS}
    if current != target:
        raise BindingRefused([
            f"conflicting_binding: card already carries {current!r}; "
            f"refusing to overwrite it with {target!r}",
        ])
    receipt = _receipt(conn, card.id, target)
    if receipt is None:
        raise BindingRefused([
            "receipt_missing: the card already matches the requested binding but no "
            "project_bound receipt records who made it; refusing an unattributed repair",
        ])
    proposal = _Proposal(
        task_id=card.id, old=None, new=target, old_status=card.status, project=project,
        actor=actor.strip(), reason=reason.strip(), board=board,
    )
    return _result("replayed", proposal, receipt=receipt, readback=_readback(conn, card.id))


def _card_refusals(conn: sqlite3.Connection, card: _Card) -> list[str]:
    """Refuse anything but an unstarted, unclaimed, process-free worktree card."""
    reasons: list[str] = []
    if card.workspace_kind != "worktree":
        reasons.append(f"task_not_worktree: workspace_kind={card.workspace_kind!r}")
    if card.status != "todo":
        reasons.append(
            f"task_not_todo: status={card.status!r}; only an unstarted todo card may be repaired"
        )
    for column in ("claim_lock", "claim_expires", "current_run_id", "worker_pid"):
        value = getattr(card, column)
        if value:
            reasons.append(f"task_not_inactive: {column}={value!r}")
    reasons.extend(_process_refusals(conn, card))
    return reasons


def _process_refusals(conn: sqlite3.Connection, card: _Card) -> list[str]:
    """A pid recorded on the card or any of its runs must be provably gone."""
    owners = [(card.worker_pid, card.worker_started_at, f"card {card.id}")]
    rows = conn.execute(
        "SELECT id, status, worker_pid, worker_started_at FROM task_runs "
        "WHERE task_id = ? AND worker_pid IS NOT NULL ORDER BY id",
        (card.id,),
    ).fetchall()
    owners.extend(
        (
            kb._row_get(row, "worker_pid"),
            kb._row_get(row, "worker_started_at"),
            f"run {kb._row_get(row, 'id')} ({kb._row_get(row, 'status')})",
        )
        for row in rows
    )
    reasons: list[str] = []
    for pid, started_at, owner in owners:
        if not pid:
            continue
        state = _pid_state(int(pid), started_at)
        if state == "alive":
            reasons.append(f"worker_still_running: {owner} owns live pid {pid}")
        elif state == "unknown":
            reasons.append(
                f"process_inspection_unavailable: cannot tell whether pid {pid} ({owner}) is running"
            )
    return reasons


def _pid_state(pid: int, started_at: Optional[str]) -> str:
    """``alive`` / ``gone`` / ``unknown`` for a recorded worker pid."""
    from hermes_cli.kanban_db_dispatch import UNVERIFIED_WORKER_FINGERPRINT, _process_fingerprint
    from hermes_cli.process_identity import _pid_alive_matches

    alive = _pid_alive_matches(pid, None)
    if alive is None:
        return "unknown"
    if not alive:
        return "gone"
    if started_at in (None, "") or started_at == UNVERIFIED_WORKER_FINGERPRINT:
        return "alive"
    if isinstance(started_at, str) and "|" in started_at:
        current = _process_fingerprint(pid)
        if current is None:
            return "unknown"
        return "alive" if current == started_at else "gone"
    from gateway.status import _start_times_agree, get_process_start_time

    current_start = get_process_start_time(pid)
    if current_start is None:
        return "unknown"
    try:
        return "alive" if _start_times_agree(current_start, started_at) else "gone"
    except (TypeError, ValueError):
        return "unknown"


def _anchor_refusals(card: _Card, project: _Project, expected_workspace: str) -> list[str]:
    """The card's anchor must be exactly the canonical repo root the caller named."""
    stored = _normalize_path(card.workspace_path)
    reasons: list[str] = []
    if stored != _normalize_path(project.primary_path):
        reasons.append(
            f"task_not_at_project_root: workspace_path={card.workspace_path!r} is not the "
            f"canonical project root {project.primary_path!r}"
        )
    if stored != _normalize_path(expected_workspace):
        reasons.append(
            f"expected_workspace_mismatch: workspace_path={card.workspace_path!r} but "
            f"--expected-workspace={expected_workspace!r}"
        )
    return reasons


def _target_refusals(project: _Project, target: dict[str, Any]) -> list[str]:
    """The derived worktree path and branch must be free, in a provable repo."""
    primary = Path(project.primary_path)
    if not primary.is_dir():
        return [f"project_root_missing: {primary} is not a directory"]
    reasons: list[str] = []
    worktrees = primary / ".worktrees"
    if worktrees.exists() and not worktrees.is_dir():
        reasons.append(f"worktrees_root_not_a_directory: {worktrees} is not a directory")
    if os.path.lexists(target["workspace_path"]):
        reasons.append(
            f"target_path_exists: {target['workspace_path']} already exists; "
            "the repair never creates or reuses a worktree"
        )
    reasons.extend(_git_refusals(primary, target["branch_name"]))
    return reasons


def _git_refusals(primary: Path, branch: str) -> list[str]:
    top = _git(primary, "rev-parse", "--show-toplevel")
    if top.returncode != 0:
        return [
            f"ambiguous_repository_identity: {primary} is not a usable git repository "
            f"({_git_error(top)})",
        ]
    if os.path.realpath(top.stdout.strip()) != os.path.realpath(primary):
        return [
            f"ambiguous_repository_identity: git reports repository root "
            f"{top.stdout.strip()!r} for {primary}",
        ]
    if _git(primary, "check-ref-format", "--branch", branch).returncode != 0:
        return [f"invalid_target_branch: {branch!r} is not a valid branch name"]
    existing = _git(primary, "show-ref", "--verify", "--quiet", f"refs/heads/{branch}")
    if existing.returncode == 0:
        return [f"target_branch_exists: refs/heads/{branch} already exists in {primary}"]
    if existing.returncode != 1:
        return [
            f"ambiguous_repository_identity: cannot inspect refs in {primary} "
            f"({_git_error(existing)})",
        ]
    return []


def _git(cwd: Path, *args: str) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["git", "-C", str(cwd), *args],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=_GIT_TIMEOUT_SECONDS, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return subprocess.CompletedProcess(
            args=("git", *args), returncode=127, stdout="", stderr=str(exc),
        )


def _git_error(result: subprocess.CompletedProcess) -> str:
    return (result.stderr or result.stdout or f"git exited {result.returncode}").strip()


# ---------------------------------------------------------------------------
# Canonical inputs: card, project, derived target
# ---------------------------------------------------------------------------


def _load_card(conn: sqlite3.Connection, task_id: str) -> Optional[_Card]:
    row = conn.execute(
        "SELECT " + ", ".join(_CARD_COLUMNS) + " FROM tasks WHERE id = ?", (task_id,),
    ).fetchone()
    if row is None:
        return None
    return _Card(**{column: kb._row_get(row, column) for column in _CARD_COLUMNS})


def _load_project(reference: str, board: str) -> _Project:
    """Read the canonical project from the selected profile's store, read-only.

    A read-only connection is what keeps ``--dry-run`` free of even an empty
    ``projects.db`` creation.
    """
    path = pdb.projects_db_path()
    if not path.is_file():
        raise BindingRefused([
            f"project_store_missing: no projects store for the selected profile at {path}",
        ])
    project = _read_project(path, reference)
    reasons: list[str] = []
    if project.archived:
        reasons.append(f"project_archived: {project.id} ({project.slug}) is archived")
    if (project.board_slug or "") != board:
        reasons.append(
            f"project_board_mismatch: {project.id} ({project.slug}) is scoped to board "
            f"{project.board_slug!r}, not {board!r}"
        )
    if not (project.primary_path or "").strip():
        reasons.append(
            f"project_without_primary_path: {project.id} ({project.slug}) has no primary repo path"
        )
    if reasons:
        raise BindingRefused(reasons)
    return _Project(
        record=project,
        primary_path=_normalize_path(project.primary_path),
        store=str(path),
    )


def _read_project(path: Path, reference: str):
    try:
        store = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise BindingRefused([f"project_store_unreadable: {path}: {exc}"]) from exc
    store.row_factory = sqlite3.Row
    try:
        project = pdb.get_project(store, reference.strip())
    except sqlite3.Error as exc:
        raise BindingRefused([f"project_store_unreadable: {path}: {exc}"]) from exc
    finally:
        store.close()
    if project is None:
        raise BindingRefused([
            f"project_not_found: no project {reference.strip()!r} in {path}",
        ])
    return project


def _target_binding(project: _Project, card: _Card) -> dict[str, Any]:
    """Derived isolation path + deterministic branch; never caller-supplied."""
    return {
        "project_id": project.id,
        "workspace_path": os.path.join(project.primary_path, ".worktrees", card.id),
        "branch_name": pdb.branch_name_for(project.record, card.id, title=card.title),
    }


def _normalize_path(value: Optional[str]) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return os.path.normpath(os.path.abspath(os.path.expanduser(text)))


# ---------------------------------------------------------------------------
# Apply: dispatch exclusion, revalidation, CAS, receipt, readback
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _dispatch_exclusion(conn: sqlite3.Connection):
    """Hold the board's dispatch lock for the whole write, or refuse.

    ``_dispatch_tick_lock`` degrades to a no-op when it cannot even open the
    lock file, so the yielded flag alone cannot prove exclusion; the probe
    below proves it independently and refuses when the lock is not real.
    """
    db_file = kbc._main_db_file(conn)
    if not db_file:
        raise BindingRefused([
            "dispatch_exclusion_unavailable: the board connection has no database file to lock",
        ])
    with kbc._dispatch_tick_lock(Path(db_file)) as held:
        if not held:
            raise BindingRefused([
                "dispatch_exclusion_busy: another dispatcher holds the board dispatch lock; "
                "retry once it releases",
            ])
        _assert_effective_exclusion(Path(db_file))
        yield


def _assert_effective_exclusion(db_file: Path) -> None:
    """Refuse when the board dispatch lock is a no-op (second lock succeeds)."""
    lock_path = db_file.with_name(db_file.name + ".dispatch.lock")
    try:
        probe = lock_path.open("a+b")
    except OSError as exc:
        raise BindingRefused([
            f"dispatch_exclusion_unavailable: cannot open {lock_path} ({exc}); "
            "the dispatch lock degrades to a no-op without it",
        ]) from exc
    try:
        try:
            acquired = kbc._try_lock_nb(probe)
        except OSError:
            # Windows byte-range locks raise instead of returning False when the
            # region is already locked — which, here, means by us.
            acquired = False
        if acquired:
            kbc._unlock(probe)
            raise BindingRefused([
                "dispatch_exclusion_unavailable: the board dispatch lock yielded without "
                "holding a real lock (no-op fallback); refusing to bind without effective exclusion",
            ])
    finally:
        probe.close()


def _revalidate(conn: sqlite3.Connection, proposal: _Proposal) -> None:
    """Re-read the card and the project inside the exclusion, immediately before apply."""
    card = _load_card(conn, proposal.task_id)
    if card is None:
        raise BindingRefused([
            f"task_not_found: card {proposal.task_id} disappeared before apply",
        ])
    current = {column: getattr(card, column) for column in _BINDING_COLUMNS}
    if current != proposal.old:
        raise BindingRefused([
            f"changed_since_validation: {current!r} is no longer {proposal.old!r}; nothing was written",
        ])
    reasons = _card_refusals(conn, card)
    if reasons:
        raise BindingRefused(reasons)
    project = _load_project(proposal.project.id, proposal.board)
    if project != proposal.project:
        raise BindingRefused([
            f"project_changed_since_validation: {project.as_source()!r} is no longer "
            f"{proposal.project.as_source()!r}",
        ])


def _apply(conn: sqlite3.Connection, proposal: _Proposal) -> None:
    """One atomic update + receipt; a failed predicate rolls both back."""
    with kb.write_txn(conn):
        updated = conn.execute(_BIND_SQL, (
            proposal.new["project_id"],
            proposal.new["workspace_path"],
            proposal.new["branch_name"],
            proposal.task_id,
            proposal.old["workspace_path"],
            proposal.old_status,
        )).rowcount
        if updated != 1:
            raise BindingRefused([
                "concurrent_modification: the card changed between revalidation and the "
                "update predicate; nothing was written",
            ])
        kb._append_event(conn, proposal.task_id, PROJECT_BOUND_EVENT, _event_payload(proposal))


def _event_payload(proposal: _Proposal) -> dict[str, Any]:
    return {
        "task_id": proposal.task_id,
        "board": proposal.board,
        "old": proposal.old,
        "new": proposal.new,
        "source": proposal.project.as_source(),
        "actor": proposal.actor,
        "reason": proposal.reason,
    }


def _receipt(conn: sqlite3.Connection, task_id: str, target: dict[str, Any]) -> Optional[dict[str, Any]]:
    """Durable receipt for exactly this target binding, if one was ever written."""
    rows = conn.execute(
        "SELECT id, payload, created_at FROM task_events WHERE task_id = ? AND kind = ? ORDER BY id",
        (task_id, PROJECT_BOUND_EVENT),
    ).fetchall()
    for row in rows:
        payload = _payload_dict(kb._row_get(row, "payload"))
        if payload.get("new") == target:
            return {
                "event": PROJECT_BOUND_EVENT,
                "event_id": kb._row_get(row, "id"),
                "created_at": kb._row_get(row, "created_at"),
                "payload": payload,
            }
    return None


def _payload_dict(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw or "{}")
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _readback(conn: sqlite3.Connection, task_id: str) -> dict[str, Any]:
    """Literal post-write state: preserved fields, both edges, receipt events."""
    task = kb.get_task(conn, task_id)
    if task is None:
        raise BindingRefused([f"task_not_found: card {task_id} is gone; readback impossible"])
    return {
        "task": {field: getattr(task, field) for field in _READBACK_FIELDS},
        "parents": kb.parent_ids(conn, task_id),
        "children": kb.child_ids(conn, task_id),
        "events": [
            {
                "id": kb._row_get(row, "id"),
                "kind": kb._row_get(row, "kind"),
                "created_at": kb._row_get(row, "created_at"),
                "payload": _payload_dict(kb._row_get(row, "payload")),
            }
            for row in conn.execute(
                "SELECT id, kind, payload, created_at FROM task_events "
                "WHERE task_id = ? AND kind = ? ORDER BY id",
                (task_id, PROJECT_BOUND_EVENT),
            )
        ],
    }


def _result(
    status: str, proposal: _Proposal, *, receipt: Optional[dict[str, Any]],
    readback: Optional[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "ok": True,
        "status": status,
        "task_id": proposal.task_id,
        "board": proposal.board,
        "project": proposal.project.as_source(),
        "old": proposal.old,
        "new": proposal.new,
        "actor": proposal.actor,
        "reason": proposal.reason,
        "receipt": receipt,
        "readback": readback,
    }
