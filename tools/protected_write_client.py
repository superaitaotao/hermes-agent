"""Unprivileged client for protected-write consent.

Everything the ordinary agent process may do lives here: prepare a request
deterministically, ask the broker for read-only status, and look up / claim /
finalize against the consume socket. Registration, issuance, revoke and recovery
are admin-only and are never reachable from this module.

The delegate/cron refusal happens HERE, before prepare/lookup/claim, because the
broker is a different process and cannot see this process's ContextVars.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import Any, Mapping

from tools import protected_write_protocol as proto
from tools.protected_write_broker import (
    ADMIN_SOCKET_NAME, CONSUME_SOCKET_NAME, DEFAULT_SOCKET_DIR,
)
from tools.protected_write_context import denied_execution_context_reason
from tools.protected_write_preparer import PreparedPlan, RootedFileSystemReader, prepare

DEFAULT_TIMEOUT_SECONDS = 30.0


class ClientError(RuntimeError):
    """The request was refused or could not be delivered."""


class ConsentDenied(ClientError):
    """The broker (or this process's own context) refused the request."""


def require_worker_context() -> None:
    """Refuse before prepare/lookup/claim in a delegate, cron or other non-owner context."""
    reason = denied_execution_context_reason()
    if reason:
        raise ConsentDenied(reason)


def _socket_path(socket_dir: os.PathLike[str] | str, name: str) -> Path:
    return Path(socket_dir) / name


def request(
    socket_path: os.PathLike[str] | str,
    method: str,
    params: Mapping[str, Any],
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    """Send exactly one v1 message and read exactly one response."""
    message = {
        "schema_version": proto.SCHEMA_VERSION,
        "method": method,
        "params": dict(params),
    }
    frame = proto.encode_frame(message)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
        conn.settimeout(timeout)
        try:
            conn.connect(str(socket_path))
        except OSError as exc:
            raise ClientError(f"cannot reach the broker at {socket_path}: {exc}") from exc
        conn.sendall(frame)
        header = _recv_exactly(conn, proto.FRAME_HEADER_BYTES)
        length = proto.decode_header(header)
        payload = _recv_exactly(conn, length)
    response = proto.decode_payload(payload)
    if not isinstance(response, dict):
        raise ClientError("broker returned a non-object response")
    if not response.get("ok"):
        raise ConsentDenied(str(response.get("error", "broker refused the request")))
    return response


def _recv_exactly(conn: socket.socket, count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        chunk = conn.recv(remaining)
        if not chunk:
            raise ClientError("broker closed the connection mid-response")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


# ── read-only paths an ordinary writer may use ────────────────────────────
def worktree_status(
    identity: Mapping[str, Any], *,
    socket_dir: os.PathLike[str] | str = DEFAULT_SOCKET_DIR,
) -> dict:
    """Read-only status. No authority is granted by any answer here."""
    return request(
        _socket_path(socket_dir, CONSUME_SOCKET_NAME), "worktree_status",
        {"identity": dict(identity)})


def preview(
    tool: str,
    arguments: Mapping[str, Any],
    context: Mapping[str, Any],
    *,
    worktree_root: os.PathLike[str] | str,
    reader: RootedFileSystemReader | None = None,
    protected_reason_for: Any = None,
) -> PreparedPlan:
    """Deterministic local preview. Nothing is written and no grant is created."""
    return prepare(
        tool, arguments, context, reader=reader, worktree_root=worktree_root,
        protected_reason_for=protected_reason_for)


# ── consume-socket lifecycle calls ────────────────────────────────────────
def lookup(
    descriptor: Mapping[str, Any],
    context: Mapping[str, Any],
    *,
    socket_dir: os.PathLike[str] | str = DEFAULT_SOCKET_DIR,
) -> dict:
    require_worker_context()
    return request(
        _socket_path(socket_dir, CONSUME_SOCKET_NAME), "lookup",
        {"context": dict(context), "descriptor": dict(descriptor)})


def claim(
    grant_id: str,
    descriptor: Mapping[str, Any],
    transaction_id: str,
    journal_digest: str,
    context: Mapping[str, Any],
    *,
    socket_dir: os.PathLike[str] | str = DEFAULT_SOCKET_DIR,
) -> dict:
    require_worker_context()
    return request(
        _socket_path(socket_dir, CONSUME_SOCKET_NAME), "claim",
        {"context": dict(context), "descriptor": dict(descriptor), "grant_id": grant_id,
         "transaction_id": transaction_id, "journal_digest": journal_digest})


def finalize(
    claim_id: str,
    transaction_id: str,
    outcome: str,
    readback: Mapping[str, str],
    context: Mapping[str, Any],
    *,
    socket_dir: os.PathLike[str] | str = DEFAULT_SOCKET_DIR,
) -> dict:
    require_worker_context()
    return request(
        _socket_path(socket_dir, CONSUME_SOCKET_NAME), "finalize",
        {"context": dict(context), "claim_id": claim_id, "transaction_id": transaction_id,
         "outcome": outcome, "readback": dict(readback)})


# ── root-side helpers used by the admin launcher and by tests ─────────────
def admin_request(
    method: str,
    params: Mapping[str, Any],
    *,
    socket_dir: os.PathLike[str] | str = DEFAULT_SOCKET_DIR,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict:
    return request(
        _socket_path(socket_dir, ADMIN_SOCKET_NAME), method, params, timeout=timeout)
