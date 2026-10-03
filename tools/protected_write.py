"""Protected-write consent: the D1 mechanism surface.

One human-authorized exact local file-tool operation (``write_file``, a replace
patch or a V4A patch) is previewed deterministically, authorized by a root broker,
executed transactionally and verified by readback. This module is the public face
D2 (file-tool integration) and the CLI build on; the implementation lives in
``tools/protected_write_*`` topical siblings.

Documented limit: this is SUPPORTED FILE-TOOL AUTHORIZATION, not confinement of
arbitrary same-uid shell/Python, ptrace or a compromised runtime/dispatcher. Such
code can already write repository files. D1 ships the mechanism only: it never
installs a bundle, registers a live run, issues a grant or exempts a write.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any, Mapping

from tools import protected_write_protocol as protocol
from tools.protected_write_authority import (
    AuthorityStore, ConsentError, DEFAULT_DB_PATH, StoreUnavailable,
    TERMINAL_GRANT_STATES, dispatcher_fingerprint_for, open_store,
)
from tools.protected_write_context import (
    ExecutionIdentity, IdentityError, current_identity, denied_execution_context_reason,
    is_delegated_child_process_context, is_dispatcher_owned_worker_context,
    process_identity,
)
from tools.protected_write_preparer import (
    PrepareError, PreparedPlan, RootedFileSystemReader, escape_untrusted, prepare,
    render_diff,
)

__all__ = [
    "AuthorityStore",
    "ConsentError",
    "DEFAULT_DB_PATH",
    "ExecutionIdentity",
    "IdentityError",
    "PrepareError",
    "PreparedPlan",
    "RootedFileSystemReader",
    "StoreUnavailable",
    "TERMINAL_GRANT_STATES",
    "current_identity",
    "denied_execution_context_reason",
    "dispatcher_fingerprint_for",
    "escape_untrusted",
    "is_delegated_child_process_context",
    "is_dispatcher_owned_worker_context",
    "open_store",
    "prepare",
    "process_identity",
    "protocol",
    "render_diff",
    "runtime_context",
]

GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_CONFIG_SYSTEM": os.devnull,
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "LC_ALL": "C",
}


class ContextError(RuntimeError):
    """The runtime cannot fill an execution identity; callers must fail closed."""


def _git(worktree: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(worktree), "-c", "core.hooksPath=/dev/null", *args],
            capture_output=True, text=True, timeout=30,
            env={**GIT_ENV, "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ContextError(f"cannot run git in {worktree}: {exc}") from exc
    if result.returncode != 0:
        raise ContextError(
            f"git {' '.join(args)} failed in {worktree}: {result.stderr.strip()}")
    return result.stdout.strip()


def resolve_git_paths(worktree: os.PathLike[str] | str) -> tuple[str, str, str]:
    """-> ``(worktree, git_dir, common_dir)`` realpaths for one checkout or worktree."""
    root = Path(os.path.realpath(worktree))
    git_path = root / ".git"
    if not git_path.exists():
        raise ContextError(f"{root} is not a git worktree")
    if git_path.is_file():
        text = git_path.read_text(encoding="utf-8").strip()
        if not text.startswith("gitdir:"):
            raise ContextError(f"unrecognised .git file at {git_path}")
        git_dir = Path(os.path.realpath(root / text[len("gitdir:"):].strip()))
    else:
        git_dir = Path(os.path.realpath(git_path))
    commondir_marker = git_dir / "commondir"
    if commondir_marker.is_file():
        common_dir = Path(os.path.realpath(git_dir / commondir_marker.read_text().strip()))
    else:
        common_dir = git_dir
    return str(root), str(git_dir), str(common_dir)


def baseline_sha(worktree: os.PathLike[str] | str) -> str:
    """Full lowercase 40-hex HEAD of the worktree; a short or empty answer is refused."""
    sha = _git(Path(worktree), "rev-parse", "HEAD")
    if not protocol.is_git_sha(sha):
        raise ContextError(f"git rev-parse HEAD returned {sha!r}, not a full SHA")
    return sha


def runtime_context(
    *,
    worktree: os.PathLike[str] | str,
    board: str | None = None,
    card: str | None = None,
    profile: str | None = None,
    home: str | None = None,
    run: str | None = None,
    session: str | None = None,
    registration_generation: int = 0,
) -> dict:
    """Fill the execution identity from the RUNTIME. The model never chooses the owner."""
    from hermes_cli.kanban_db import get_current_board
    from hermes_constants import get_hermes_home

    resolved_home = os.path.realpath(home or str(get_hermes_home()))
    worktree_real, git_dir, common_dir = resolve_git_paths(worktree)
    identity = current_identity()
    return protocol.validate_context({
        "board": board or _env("HERMES_KANBAN_BOARD") or get_current_board() or "default",
        "card": card or _env("HERMES_KANBAN_TASK") or "",
        "profile": profile or _env("HERMES_PROFILE") or Path(profile_home(resolved_home)).name,
        "home": resolved_home,
        "run": run if run is not None else (_env("HERMES_KANBAN_RUN_ID") or ""),
        "session": session if session is not None else (current_session_id() or ""),
        "registration_generation": registration_generation,
        "uid": identity.uid,
        "pid": identity.pid,
        "boot_id": identity.boot_id,
        "start_ticks": identity.start_ticks,
        "worktree": worktree_real,
        "git_dir": git_dir,
        "common_dir": common_dir,
        "baseline": baseline_sha(worktree_real),
    })


def profile_home(resolved_home: str) -> str:
    """The profile directory for a Hermes home, so a named profile is not mistaken for the root."""
    from hermes_constants import named_profile_home

    profile = named_profile_home(resolved_home)
    return str(profile) if profile is not None else resolved_home


def current_session_id() -> str:
    """Session id of the active turn, or ``""`` when no session scope is bound."""
    try:
        from gateway.session_context import get_session_env
    except Exception:
        return ""
    try:
        return str(get_session_env("HERMES_SESSION_ID") or "")
    except Exception:
        return ""


def _env(name: str) -> str | None:
    value = os.environ.get(name)
    return value.strip() or None if value else None
