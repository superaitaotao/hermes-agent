"""Execution identity and owner predicates for protected-write consent.

D1 scope: identity facts and the delegate/cron refusal predicate only. No write
path consults this yet — D2 wires it into the file tools.

The broker authenticates the *consume* peer by exact process identity: PID EQUALS
the registered worker PID and uid/boot-id/start-ticks match. There is no
descendant allowance, and no ancestry, environment or bearer-token fallback,
because a copied environment is trivially forgeable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

BOOT_ID_PATH = Path("/proc/sys/kernel/random/boot_id")
PROC_ROOT = Path("/proc")


class IdentityError(RuntimeError):
    """A process identity fact could not be established; callers must fail closed."""


@dataclass(frozen=True)
class ExecutionIdentity:
    """Kernel-attested identity of one process at one moment."""

    uid: int
    pid: int
    boot_id: str
    start_ticks: int

    def as_context_fields(self) -> dict:
        return {
            "uid": self.uid,
            "pid": self.pid,
            "boot_id": self.boot_id,
            "start_ticks": self.start_ticks,
        }

    def matches(self, other: "ExecutionIdentity") -> bool:
        return self == other


def boot_id(path: Path | None = None) -> str:
    """Kernel boot id; a different value proves a reboot since the record was written."""
    target = BOOT_ID_PATH if path is None else path
    try:
        value = target.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise IdentityError(f"cannot read boot id from {target}: {exc}") from exc
    if not value:
        raise IdentityError(f"empty boot id at {target}")
    return value


def _stat_fields(pid: int) -> list[str]:
    try:
        raw = (PROC_ROOT / str(pid) / "stat").read_text(encoding="utf-8")
    except OSError as exc:
        raise IdentityError(f"cannot read /proc/{pid}/stat: {exc}") from exc
    # comm may contain spaces and parens; split after the final ')'.
    close = raw.rfind(")")
    if close == -1:
        raise IdentityError(f"malformed /proc/{pid}/stat")
    tail = raw[close + 2:].split()
    return tail


def process_start_ticks(pid: int) -> int:
    """Field 22 of /proc/<pid>/stat: start time in clock ticks since boot.

    Distinguishes a live process from a recycled PID holding the same number.
    """
    fields = _stat_fields(pid)
    try:
        # tail[0] is field 3 (state); starttime is field 22 -> index 19.
        return int(fields[19])
    except (IndexError, ValueError) as exc:
        raise IdentityError(f"cannot parse start time for pid {pid}") from exc


def process_uid(pid: int) -> int:
    """Effective-from-real uid of ``pid`` as the kernel reports it in /proc/<pid>/status."""
    try:
        status = (PROC_ROOT / str(pid) / "status").read_text(encoding="utf-8")
    except OSError as exc:
        raise IdentityError(f"cannot read /proc/{pid}/status: {exc}") from exc
    for line in status.splitlines():
        if line.startswith("Uid:"):
            parts = line.split()
            if len(parts) >= 2:
                return int(parts[1])
    raise IdentityError(f"no Uid line in /proc/{pid}/status")


def process_identity(pid: int, *, exotic_uid: int | None = None) -> ExecutionIdentity:
    """Identity of an arbitrary live process. Raises :class:`IdentityError` when unreadable."""
    return ExecutionIdentity(
        uid=process_uid(pid) if exotic_uid is None else exotic_uid,
        pid=pid,
        boot_id=boot_id(),
        start_ticks=process_start_ticks(pid),
    )


def current_identity() -> ExecutionIdentity:
    pid = os.getpid()
    return ExecutionIdentity(
        uid=os.getuid(),
        pid=pid,
        boot_id=boot_id(),
        start_ticks=process_start_ticks(pid),
    )


def is_delegated_child_process_context() -> bool:
    """True inside a delegate_task child (this process or a subprocess it spawned)."""
    from agent.delegation_context import is_delegated_child_process_context as _impl

    return bool(_impl())


def is_dispatcher_owned_worker_context() -> bool:
    """True only for the dispatcher-owned Kanban worker, not a child or cron run."""
    from agent.delegation_context import is_dispatcher_owned_worker_context as _impl

    return bool(_impl())


def denied_execution_context_reason() -> str | None:
    """Why this execution may never prepare, look up or claim, or ``None`` when allowed.

    A same-PID delegate or cron run must be refused BEFORE prepare/lookup/claim:
    it inherits the worker's PID and environment but is not the worker the human
    registered. Arbitrary Python tampering inside the same uid is outside the
    supported boundary (see the plan's documented limit) and is not detectable here.
    """
    if is_delegated_child_process_context():
        return "delegated child context may not use protected-write consent"
    if not is_dispatcher_owned_worker_context():
        return "non-dispatcher-owned context (cron/in-process run) may not use protected-write consent"
    return None
