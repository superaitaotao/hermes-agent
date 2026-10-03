"""Root broker authority store for protected-write consent.

The broker is the only writer of the authority database; ordinary local writers
read ``worktree-status`` and nothing more. Every mutation runs inside one SQLite
``BEGIN IMMEDIATE`` transaction with ``synchronous=FULL`` so a returned receipt is
durable before any mutation may follow it.

D1 scope: schema v1 and the full lifecycle contract. No grant is ever issued by
this module on its own — issuance requires an authenticated admin peer and an
explicit confirmation. Nothing here integrates a write path; D2 owns that.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from tools import protected_write_protocol as proto
from tools.protected_write_context import ExecutionIdentity

AUTHORITY_SCHEMA_VERSION = "protected-write-authority-v1"
DEFAULT_DB_PATH = "/var/lib/hermes-protected-writes/authority.sqlite3"

#: Grant states. ``spent_pending`` is the durable "consent spent, outcome unknown" state.
GRANT_ISSUED = "issued"
GRANT_SPENT_PENDING = "spent_pending"
GRANT_COMPLETED = "completed"
GRANT_FAILED_SPENT = "failed_spent"
GRANT_INDETERMINATE_SPENT = "indeterminate_spent"
GRANT_REVOKED = "revoked"
GRANT_CANCELLED = "cancelled"
GRANT_EXPIRED = "expired"
TERMINAL_GRANT_STATES = frozenset({
    GRANT_COMPLETED, GRANT_FAILED_SPENT, GRANT_INDETERMINATE_SPENT,
    GRANT_REVOKED, GRANT_CANCELLED, GRANT_EXPIRED,
})
SPENT_GRANT_STATES = frozenset({GRANT_SPENT_PENDING, *TERMINAL_GRANT_STATES})

REGISTRATION_ACTIVE = "active"
REGISTRATION_ENDED = "ended"

LOOKUP_ABSENT = "absent"
LOOKUP_ISSUED = "issued"
LOOKUP_TERMINAL = "terminal"

WORKTREE_UNREGISTERED = "unregistered"
WORKTREE_REGISTERED = "registered"
WORKTREE_HELD = "held"

_SCHEMA_SQL = (
    """
    CREATE TABLE IF NOT EXISTS meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS registrations (
        generation INTEGER PRIMARY KEY AUTOINCREMENT,
        identity_key TEXT NOT NULL,
        context_json TEXT NOT NULL,
        dispatcher_fingerprint TEXT NOT NULL,
        dispatcher_uid INTEGER,
        dispatcher_pid INTEGER,
        dispatcher_boot_id TEXT,
        dispatcher_start_ticks INTEGER,
        state TEXT NOT NULL,
        created_at REAL NOT NULL,
        ended_at REAL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS grants (
        grant_id TEXT PRIMARY KEY,
        generation INTEGER NOT NULL,
        identity_key TEXT NOT NULL,
        descriptor_digest TEXT NOT NULL,
        plan_sha256 TEXT NOT NULL,
        confirmation TEXT NOT NULL,
        state TEXT NOT NULL,
        issued_at REAL NOT NULL,
        expires_at REAL NOT NULL,
        issuer_uid INTEGER NOT NULL,
        issuer_pid INTEGER NOT NULL,
        issuer_boot_id TEXT NOT NULL,
        issuer_start_ticks INTEGER NOT NULL,
        settled_at REAL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS claims (
        claim_id TEXT PRIMARY KEY,
        grant_id TEXT NOT NULL,
        descriptor_digest TEXT NOT NULL,
        transaction_id TEXT NOT NULL,
        journal_digest TEXT NOT NULL,
        peer_uid INTEGER NOT NULL,
        peer_pid INTEGER NOT NULL,
        peer_boot_id TEXT NOT NULL,
        peer_start_ticks INTEGER NOT NULL,
        outcome TEXT NOT NULL,
        receipt_json TEXT NOT NULL,
        created_at REAL NOT NULL,
        settled_at REAL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS holds (
        hold_id TEXT PRIMARY KEY,
        claim_id TEXT,
        descriptor_digest TEXT,
        worktree TEXT,
        reason TEXT NOT NULL,
        created_at REAL NOT NULL,
        cleared_at REAL,
        cleared_reason TEXT
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS cancel_peers (
        peer_id TEXT PRIMARY KEY,
        generation INTEGER NOT NULL,
        peer_uid INTEGER NOT NULL,
        peer_pid INTEGER NOT NULL,
        peer_boot_id TEXT NOT NULL,
        peer_start_ticks INTEGER NOT NULL,
        created_at REAL NOT NULL,
        revoked_at REAL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS events (
        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
        at REAL NOT NULL,
        kind TEXT NOT NULL,
        correlation TEXT NOT NULL,
        detail_json TEXT NOT NULL
    )
    """,
)


class ConsentError(RuntimeError):
    """A request is refused. Fail-closed: every uncertain state raises this."""


class StoreUnavailable(ConsentError):
    """The authority store cannot be opened or its schema is not the known version."""


@dataclass(frozen=True)
class Receipt:
    """Stored, reproducible outcome. Serialized form is the canonical JSON below."""

    payload: dict

    def to_json(self) -> str:
        return proto.canonical_json_bytes(self.payload).decode("utf-8")

    @staticmethod
    def from_json(text: str) -> dict:
        return proto.parse_json_strict(text)


def _now() -> float:
    return time.time()


def _lastrowid(cursor: sqlite3.Cursor) -> int:
    rowid = cursor.lastrowid
    if rowid is None:  # pragma: no cover - sqlite always reports it for an INSERT
        raise StoreUnavailable("sqlite did not report an inserted row id")
    return int(rowid)


def dispatcher_fingerprint_for(identity: ExecutionIdentity) -> str:
    """Fingerprint of one dispatcher process; a recycled PID yields a different value."""
    return proto.canonical_digest({
        "uid": identity.uid, "pid": identity.pid, "boot_id": identity.boot_id,
        "start_ticks": identity.start_ticks,
    })


def _identity_key(context: Mapping[str, Any]) -> str:
    return "|".join((
        str(context["home"]), str(context["profile"]), str(context["worktree"]),
        str(context["card"])))


def _identity_tuple(peer: ExecutionIdentity) -> tuple[int, int, str, int]:
    return (peer.uid, peer.pid, peer.boot_id, peer.start_ticks)


class AuthorityStore:
    """SQLite-backed authority. One instance per process; safe across processes via IMMEDIATE."""

    def __init__(self, path: os.PathLike[str] | str = DEFAULT_DB_PATH, *,
                 now: Callable[[], float] = _now):
        self.path = Path(path)
        self._now = now
        self._conn: sqlite3.Connection | None = None

    # ── connection ────────────────────────────────────────────────────
    def open(self) -> None:
        if self._conn is not None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(self.path.parent, 0o700)
        except OSError as exc:
            raise StoreUnavailable(f"cannot prepare authority directory {self.path.parent}: {exc}") from exc
        try:
            conn = sqlite3.connect(str(self.path), isolation_level=None, timeout=10.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA busy_timeout=10000")
            existing = self._existing_schema_version(conn)
            if existing is not None and existing != AUTHORITY_SCHEMA_VERSION:
                conn.close()
                raise StoreUnavailable(
                    f"unknown authority schema {existing!r}; refusing to operate on a version "
                    "this build does not know")
            for statement in _SCHEMA_SQL:
                conn.execute(statement)
            self._set_meta(conn, "schema_version", AUTHORITY_SCHEMA_VERSION)
        except sqlite3.Error as exc:
            raise StoreUnavailable(f"cannot open authority store {self.path}: {exc}") from exc
        self._conn = conn
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def _require_conn(self) -> sqlite3.Connection:
        self.open()
        conn = self._conn
        if conn is None:  # pragma: no cover - open() raises instead
            raise StoreUnavailable("authority store is not open")
        version = self._get_meta(conn, "schema_version")
        if version != AUTHORITY_SCHEMA_VERSION:
            raise StoreUnavailable(
                f"unknown authority schema {version!r}; refusing to operate on a version "
                "this build does not know")
        return conn

    @staticmethod
    def _set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
        conn.execute(
            "INSERT INTO meta(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    @staticmethod
    def _get_meta(conn: sqlite3.Connection, key: str) -> str | None:
        row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else row["value"]

    @staticmethod
    def _existing_schema_version(conn: sqlite3.Connection) -> str | None:
        """The version of an existing database, or ``None`` for a database we create.

        A fresh file has no ``meta`` table yet, so the table is looked up first;
        reading a missing table would raise instead of reporting "new".
        """
        table = conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'meta'").fetchone()
        if table is None:
            return None
        return AuthorityStore._get_meta(conn, "schema_version")

    def _transaction(self):
        return _ImmediateTransaction(self)

    def _event(self, conn: sqlite3.Connection, kind: str, correlation: str, detail: dict) -> int:
        cursor = conn.execute(
            "INSERT INTO events(at, kind, correlation, detail_json) VALUES (?, ?, ?, ?)",
            (self._now(), kind, correlation,
             proto.canonical_json_bytes(detail).decode("utf-8")))
        return _lastrowid(cursor)

    # ── registration ──────────────────────────────────────────────────
    def register(
        self,
        context: Mapping[str, Any],
        dispatcher_fingerprint: str,
        *,
        dispatcher: ExecutionIdentity | None = None,
        board_check: Callable[[Mapping[str, Any]], None] | None = None,
    ) -> dict:
        """Root-attested registration of one worker run. Grants no write authority."""
        ctx = proto.validate_context(dict(context))
        if not proto.is_hex_digest(dispatcher_fingerprint):
            raise ConsentError("dispatcher fingerprint must be a lowercase SHA-256")
        if dispatcher is not None:
            expected = dispatcher_fingerprint_for(dispatcher)
            if expected != dispatcher_fingerprint:
                raise ConsentError(
                    "dispatcher fingerprint does not match the recorded dispatcher identity")
        if board_check is not None:
            board_check(ctx)  # cooperative evidence: the board is not a security boundary
        key = _identity_key(ctx)
        with self._transaction():
            conn = self._require_conn()
            active = conn.execute(
                "SELECT generation FROM registrations WHERE identity_key = ? AND state = ?",
                (key, REGISTRATION_ACTIVE)).fetchone()
            if active is not None:
                raise ConsentError(
                    f"identity {key} already has active registration generation "
                    f"{active['generation']}; end it before registering again")
            cursor = conn.execute(
                "INSERT INTO registrations"
                "(identity_key, context_json, dispatcher_fingerprint, dispatcher_uid, "
                "dispatcher_pid, dispatcher_boot_id, dispatcher_start_ticks, state, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (key, proto.canonical_json_bytes(ctx).decode("utf-8"), dispatcher_fingerprint,
                 None if dispatcher is None else dispatcher.uid,
                 None if dispatcher is None else dispatcher.pid,
                 None if dispatcher is None else dispatcher.boot_id,
                 None if dispatcher is None else dispatcher.start_ticks,
                 REGISTRATION_ACTIVE, self._now()))
            generation = _lastrowid(cursor)
            event_id = self._event(conn, "registered", key, {
                "generation": generation,
                "dispatcher_fingerprint": dispatcher_fingerprint,
            })
        return {"generation": generation, "identity_key": key, "event_id": event_id}

    def _active_registration(
        self, conn: sqlite3.Connection, ctx: Mapping[str, Any], generation: int | None = None
    ) -> sqlite3.Row:
        key = _identity_key(ctx)
        row = conn.execute(
            "SELECT * FROM registrations WHERE identity_key = ? AND state = ?",
            (key, REGISTRATION_ACTIVE)).fetchone()
        if row is None:
            raise ConsentError(f"no active registration for {key}")
        if generation is not None and int(row["generation"]) != int(generation):
            raise ConsentError(
                f"registration generation {generation} is not the active generation "
                f"{row['generation']} for {key}")
        stored = proto.parse_json_strict(row["context_json"])
        if _identity_tuple_of_context(stored) != _identity_tuple_of_context(ctx):
            raise ConsentError("registration identity does not match the presented context")
        self._require_dispatcher_live(row)
        return row

    def _require_dispatcher_live(self, registration: sqlite3.Row) -> None:
        """An unknown, ended or recycled dispatcher fingerprint invalidates the registration."""
        pid = registration["dispatcher_pid"]
        if pid is None:
            return
        from tools.protected_write_context import IdentityError, process_identity

        try:
            live = process_identity(int(pid))
        except IdentityError as exc:
            raise ConsentError(
                f"registered dispatcher pid {pid} is gone; registration is invalid ({exc})") from exc
        recorded = (
            int(registration["dispatcher_uid"]), int(pid),
            str(registration["dispatcher_boot_id"]), int(registration["dispatcher_start_ticks"]))
        if _identity_tuple(live) != recorded:
            raise ConsentError(
                "registered dispatcher identity changed (pid recycled or ended); "
                "registration is invalid")
        if dispatcher_fingerprint_for(live) != registration["dispatcher_fingerprint"]:
            raise ConsentError("dispatcher fingerprint no longer matches; registration is invalid")

    def end_registration(self, context: Mapping[str, Any], reason: str) -> dict:
        ctx = proto.validate_context(dict(context))
        key = _identity_key(ctx)
        with self._transaction():
            conn = self._require_conn()
            row = self._active_registration(conn, ctx)
            conn.execute(
                "UPDATE registrations SET state = ?, ended_at = ? WHERE generation = ?",
                (REGISTRATION_ENDED, self._now(), row["generation"]))
            event_id = self._event(conn, "registration_ended", key, {
                "generation": row["generation"], "reason": reason})
        return {"generation": int(row["generation"]), "event_id": event_id, "reason": reason}

    # ── issuance ──────────────────────────────────────────────────────
    def issue(
        self,
        envelope: Mapping[str, Any],
        descriptor: Mapping[str, Any],
        ttl_seconds: int,
        confirmation: str,
        peer: ExecutionIdentity,
        *,
        admin: bool,
    ) -> dict:
        """Issue a single-use grant bound to the exact plan bytes and descriptor digest.

        The descriptor is the admin-prepared artifact (computed by the deterministic
        preparer), never a value the requesting model supplies on its own.
        """
        if not admin:
            raise ConsentError("issuance requires the authenticated root admin peer")
        if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool):
            raise ConsentError("ttl must be an integer number of seconds")
        if not 1 <= ttl_seconds <= proto.MAX_TTL_SECONDS:
            raise ConsentError(
                f"ttl must be between 1 and {proto.MAX_TTL_SECONDS} seconds")
        if not isinstance(confirmation, str) or not confirmation.strip():
            raise ConsentError(
                "issuance requires explicit human confirmation (there is no --yes/always escape)")

        validated = proto.validate_envelope(dict(envelope))
        plan_bytes = validated.pop("plan_bytes", None)
        if plan_bytes is None:
            raise ConsentError("envelope is missing the exact plan bytes")
        ctx = validated["context"]
        plan_sha256 = proto.sha256_hex(plan_bytes)
        arguments_sha256 = proto.sha256_hex(proto.canonical_json_bytes(validated["arguments"]))
        # The admin-prepared descriptor must hash the exact same plan bytes.
        digest = _match_descriptor_to_envelope(
            descriptor, validated, plan_bytes, arguments_sha256)

        with self._transaction():
            conn = self._require_conn()
            registration = self._active_registration(
                conn, ctx, generation=int(ctx["registration_generation"]))
            grant_id = secrets.token_hex(32)
            expires_at = self._now() + ttl_seconds
            conn.execute(
                "INSERT INTO grants(grant_id, generation, identity_key, descriptor_digest, "
                "plan_sha256, confirmation, state, issued_at, expires_at, issuer_uid, issuer_pid, "
                "issuer_boot_id, issuer_start_ticks) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (grant_id, int(registration["generation"]), _identity_key(ctx), digest,
                 plan_sha256, confirmation, GRANT_ISSUED, self._now(), expires_at,
                 peer.uid, peer.pid, peer.boot_id, peer.start_ticks))
            event_id = self._event(conn, "issued", digest, {
                "grant_id": grant_id,
                "generation": int(registration["generation"]),
                "plan_sha256": plan_sha256,
                "expires_at": expires_at,
                "issuer": {"uid": peer.uid, "pid": peer.pid, "boot_id": peer.boot_id,
                           "start_ticks": peer.start_ticks},
            })
        return {
            "grant_id": grant_id,
            "descriptor_digest": digest,
            "plan_sha256": plan_sha256,
            "expires_at": expires_at,
            "state": GRANT_ISSUED,
            "event_id": event_id,
        }

    # ── lookup ────────────────────────────────────────────────────────
    def lookup(
        self,
        descriptor: Mapping[str, Any],
        ctx: Mapping[str, Any],
        peer: ExecutionIdentity,
        *,
        admin: bool = False,
    ) -> dict:
        """``absent`` / ``issued`` / ``terminal`` for one descriptor.

        A descriptor that matches a grant but not the caller's identity, or a
        malformed descriptor, DENIES — it is never reported as absent, so no caller
        can fall back to the unprotected path by presenting a wrong value.
        """
        validated_ctx = proto.validate_context(dict(ctx))
        digest = proto.descriptor_digest(descriptor)
        with self._transaction():
            conn = self._require_conn()
            row = conn.execute(
                "SELECT * FROM grants WHERE descriptor_digest = ?", (digest,)).fetchone()
            if row is None:
                return {"status": LOOKUP_ABSENT, "descriptor_digest": digest}
            if not admin:
                registration = self._active_registration(conn, validated_ctx)
                self._require_peer_matches_registration(ctx, peer, registration)
            state = self._effective_state(conn, row)
            receipt = {
                "status": LOOKUP_TERMINAL if state in TERMINAL_GRANT_STATES else LOOKUP_ISSUED,
                "descriptor_digest": digest,
                "grant_id": row["grant_id"],
                "grant_state": state,
                "expires_at": row["expires_at"],
            }
        return receipt

    # ── claim / finalize ──────────────────────────────────────────────
    def claim(
        self,
        grant_id: str,
        descriptor: Mapping[str, Any],
        transaction_id: str,
        journal_digest: str,
        ctx: Mapping[str, Any],
        peer: ExecutionIdentity,
    ) -> dict:
        """Durably spend consent exactly once. A duplicate reads the prior receipt."""
        validated_ctx = proto.validate_context(dict(ctx))
        digest = proto.descriptor_digest(descriptor)
        if not proto.is_hex_digest(journal_digest):
            raise ConsentError("journal digest must be a lowercase SHA-256")
        if not transaction_id or len(transaction_id) > 512:
            raise ConsentError("transaction_id must be a non-empty bounded string")
        with self._transaction():
            conn = self._require_conn()
            registration = self._active_registration(conn, validated_ctx)
            self._require_peer_matches_registration(validated_ctx, peer, registration)
            row = conn.execute("SELECT * FROM grants WHERE grant_id = ?", (grant_id,)).fetchone()
            if row is None:
                raise ConsentError(f"unknown grant {grant_id}")
            if row["descriptor_digest"] != digest:
                raise ConsentError("grant does not match this descriptor; refusing to claim")
            state = self._effective_state(conn, row)
            if state != GRANT_ISSUED:
                prior = self._prior_claim(conn, grant_id)
                if prior is None:
                    raise ConsentError(f"grant {grant_id} is {state} and has no recoverable claim")
                if not _claim_matches(prior, digest, transaction_id, journal_digest):
                    raise ConsentError(
                        "grant is already spent for a different transaction; a duplicate may "
                        "only READ the prior receipt, never re-execute")
                return {"replayed": True, "receipt": Receipt.from_json(prior["receipt_json"])}

            claim_id = secrets.token_hex(32)
            receipt = {
                "claim_id": claim_id,
                "grant_id": grant_id,
                "descriptor_digest": digest,
                "transaction_id": transaction_id,
                "journal_digest": journal_digest,
                "state": GRANT_SPENT_PENDING,
                "claimed_at": self._now(),
                "peer": {"uid": peer.uid, "pid": peer.pid, "boot_id": peer.boot_id,
                         "start_ticks": peer.start_ticks},
            }
            conn.execute(
                "INSERT INTO claims(claim_id, grant_id, descriptor_digest, transaction_id, "
                "journal_digest, peer_uid, peer_pid, peer_boot_id, peer_start_ticks, outcome, "
                "receipt_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (claim_id, grant_id, digest, transaction_id, journal_digest, peer.uid, peer.pid,
                 peer.boot_id, peer.start_ticks, GRANT_SPENT_PENDING, Receipt(receipt).to_json(),
                 self._now()))
            conn.execute("UPDATE grants SET state = ?, settled_at = ? WHERE grant_id = ?",
                         (GRANT_SPENT_PENDING, self._now(), grant_id))
            self._event(conn, "claimed", digest, {
                "grant_id": grant_id, "claim_id": claim_id, "transaction_id": transaction_id,
                "journal_digest": journal_digest,
                "peer": {"uid": peer.uid, "pid": peer.pid, "boot_id": peer.boot_id,
                         "start_ticks": peer.start_ticks},
            })
        return {"replayed": False, "receipt": receipt}

    def finalize(
        self,
        claim_id: str,
        transaction_id: str,
        outcome: str,
        readback_hashes: Mapping[str, str],
        ctx: Mapping[str, Any],
        peer: ExecutionIdentity,
    ) -> dict:
        """Settle a claim with the complete readback hashes. Exact peer and correlation only."""
        if outcome not in (GRANT_COMPLETED, GRANT_FAILED_SPENT, GRANT_INDETERMINATE_SPENT):
            raise ConsentError(
                "finalize outcome must be completed, failed_spent or indeterminate_spent")
        validated_ctx = proto.validate_context(dict(ctx))
        with self._transaction():
            conn = self._require_conn()
            registration = self._active_registration(conn, validated_ctx)
            self._require_peer_matches_registration(validated_ctx, peer, registration)
            claim = conn.execute("SELECT * FROM claims WHERE claim_id = ?", (claim_id,)).fetchone()
            if claim is None:
                raise ConsentError(f"unknown claim {claim_id}")
            if claim["transaction_id"] != transaction_id:
                raise ConsentError("transaction correlation does not match this claim")
            if _identity_tuple(peer) != (
                    claim["peer_uid"], claim["peer_pid"], claim["peer_boot_id"],
                    claim["peer_start_ticks"]):
                raise ConsentError(
                    "finalize requires the exact peer that claimed; a stale worker cannot "
                    "finalize a successor claim")
            if claim["outcome"] in TERMINAL_GRANT_STATES:
                return {"replayed": True,
                        "receipt": Receipt.from_json(claim["receipt_json"])}
            missing = self._missing_readback(conn, claim, readback_hashes)
            if missing:
                raise ConsentError(
                    "finalize requires complete readback hashes; missing " + ", ".join(missing))
            receipt = {
                "claim_id": claim_id,
                "grant_id": claim["grant_id"],
                "descriptor_digest": claim["descriptor_digest"],
                "transaction_id": transaction_id,
                "outcome": outcome,
                "readback": dict(sorted(readback_hashes.items())),
                "settled_at": self._now(),
            }
            conn.execute(
                "UPDATE claims SET outcome = ?, receipt_json = ?, settled_at = ? WHERE claim_id = ?",
                (outcome, Receipt(receipt).to_json(), self._now(), claim_id))
            conn.execute("UPDATE grants SET state = ?, settled_at = ? WHERE grant_id = ?",
                         (outcome, self._now(), claim["grant_id"]))
            if outcome == GRANT_INDETERMINATE_SPENT:
                self._raise_hold(conn, claim["grant_id"], claim["descriptor_digest"],
                                 validated_ctx.get("worktree"),
                                 "finalize reported indeterminate state", claim_id)
            self._event(conn, "finalized", claim["descriptor_digest"], {
                "claim_id": claim_id, "outcome": outcome})
        return {"replayed": False, "receipt": receipt}

    # ── revoke / cancel ───────────────────────────────────────────────
    def revoke(self, grant_id: str, reason: str, *, admin: bool) -> dict:
        if not admin:
            raise ConsentError("revoke requires the authenticated root admin peer")
        return self._terminate_grant(grant_id, GRANT_REVOKED, reason, kind="revoked")

    def register_cancel_peer(
        self, peer: ExecutionIdentity, generation: int, *, admin: bool,
    ) -> dict:
        """Root records the exact dispatcher peer allowed to cancel one generation. CANCEL-ONLY."""
        if not admin:
            raise ConsentError("registering a cancel peer requires the authenticated root admin peer")
        peer_id = secrets.token_hex(16)
        with self._transaction():
            conn = self._require_conn()
            row = conn.execute(
                "SELECT generation FROM registrations WHERE generation = ?", (int(generation),)
            ).fetchone()
            if row is None:
                raise ConsentError(f"unknown registration generation {generation}")
            conn.execute(
                "INSERT INTO cancel_peers(peer_id, generation, peer_uid, peer_pid, peer_boot_id, "
                "peer_start_ticks, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (peer_id, int(generation), peer.uid, peer.pid, peer.boot_id, peer.start_ticks,
                 self._now()))
            self._event(conn, "cancel_peer_registered", f"generation:{int(generation)}", {
                "peer_id": peer_id, "generation": int(generation),
                "peer": {"uid": peer.uid, "pid": peer.pid, "boot_id": peer.boot_id,
                         "start_ticks": peer.start_ticks},
            })
        return {"peer_id": peer_id, "generation": int(generation)}

    def _is_registered_cancel_peer(self, conn: sqlite3.Connection, peer: ExecutionIdentity,
                                   generation: int) -> bool:
        rows = conn.execute(
            "SELECT * FROM cancel_peers WHERE generation = ? AND revoked_at IS NULL "
            "AND peer_pid = ? AND peer_uid = ? AND peer_boot_id = ? AND peer_start_ticks = ?",
            (int(generation), peer.pid, peer.uid, peer.boot_id, peer.start_ticks)).fetchall()
        return bool(rows)

    def cancel_generation(
        self, generation: int, reason: str, *,
        admin: bool = False, cancel_peer: ExecutionIdentity | None = None,
    ) -> dict:
        """Cancel every unspent grant of one generation. CANCEL-ONLY: never registers or issues."""
        with self._transaction():
            conn = self._require_conn()
            if not admin:
                if cancel_peer is None or not self._is_registered_cancel_peer(
                        conn, cancel_peer, generation):
                    raise ConsentError(
                        "cancel requires the authenticated root admin peer or a root-registered "
                        "cancel-only dispatcher peer")
            rows = conn.execute(
                "SELECT grant_id FROM grants WHERE generation = ? AND state = ?",
                (int(generation), GRANT_ISSUED)).fetchall()
            cancelled: list[str] = []
            for row in rows:
                self._terminate_grant(row["grant_id"], GRANT_CANCELLED, reason,
                                      kind="cancelled", conn=conn)
                cancelled.append(row["grant_id"])
            conn.execute(
                "UPDATE registrations SET state = ?, ended_at = ? WHERE generation = ?",
                (REGISTRATION_ENDED, self._now(), int(generation)))
            event_id = self._event(conn, "generation_cancelled", f"generation:{generation}", {
                "generation": int(generation), "reason": reason, "cancelled": cancelled})
        return {"generation": int(generation), "cancelled": cancelled, "event_id": event_id,
                "reason": reason}

    def _terminate_grant(
        self, grant_id: str, state: str, reason: str, *, kind: str,
        conn: sqlite3.Connection | None = None,
    ) -> dict:
        def _apply(active_conn: sqlite3.Connection) -> dict:
            row = active_conn.execute(
                "SELECT * FROM grants WHERE grant_id = ?", (grant_id,)).fetchone()
            if row is None:
                raise ConsentError(f"unknown grant {grant_id}")
            current = self._effective_state(active_conn, row)
            if current in TERMINAL_GRANT_STATES:
                receipt = {
                    "grant_id": grant_id, "state": current, "reason": reason,
                    "replayed": True,
                }
                return receipt
            if current == GRANT_SPENT_PENDING:
                raise ConsentError(
                    "grant is claimed and spent_pending; use recovery, not revoke/cancel")
            active_conn.execute(
                "UPDATE grants SET state = ?, settled_at = ? WHERE grant_id = ?",
                (state, self._now(), grant_id))
            self._event(active_conn, kind, row["descriptor_digest"],
                        {"grant_id": grant_id, "reason": reason})
            return {"grant_id": grant_id, "state": state, "reason": reason, "replayed": False}

        if conn is not None:
            return _apply(conn)
        with self._transaction():
            return _apply(self._require_conn())

    # ── recovery ──────────────────────────────────────────────────────
    def recovery_status(self, claim_id: str) -> dict:
        conn = self._require_conn()
        claim = conn.execute("SELECT * FROM claims WHERE claim_id = ?", (claim_id,)).fetchone()
        if claim is None:
            raise ConsentError(f"unknown claim {claim_id}")
        hold = conn.execute(
            "SELECT * FROM holds WHERE claim_id = ? AND cleared_at IS NULL", (claim_id,)).fetchone()
        return {
            "claim_id": claim_id,
            "outcome": claim["outcome"],
            "descriptor_digest": claim["descriptor_digest"],
            "transaction_id": claim["transaction_id"],
            "journal_digest": claim["journal_digest"],
            "held": hold is not None,
            "hold_id": None if hold is None else hold["hold_id"],
        }

    def recover(
        self, claim_id: str, verified: str, readback_hashes: Mapping[str, str], reason: str,
        *, admin: bool,
    ) -> dict:
        """Settle a spent claim from verified disk state. Never re-issues consent."""
        if not admin:
            raise ConsentError("recover requires the authenticated root admin peer")
        outcome_for = {
            "after": GRANT_COMPLETED,
            "before": GRANT_FAILED_SPENT,
            "conflict": GRANT_INDETERMINATE_SPENT,
        }
        if verified not in outcome_for:
            raise ConsentError("verified must be one of after, before, conflict")
        outcome = outcome_for[verified]
        with self._transaction():
            conn = self._require_conn()
            claim = conn.execute("SELECT * FROM claims WHERE claim_id = ?", (claim_id,)).fetchone()
            if claim is None:
                raise ConsentError(f"unknown claim {claim_id}")
            if claim["outcome"] in TERMINAL_GRANT_STATES:
                return {"replayed": True, "receipt": Receipt.from_json(claim["receipt_json"])}
            receipt = {
                "claim_id": claim_id,
                "grant_id": claim["grant_id"],
                "descriptor_digest": claim["descriptor_digest"],
                "transaction_id": claim["transaction_id"],
                "outcome": outcome,
                "verified": verified,
                "readback": dict(sorted(readback_hashes.items())),
                "reason": reason,
                "settled_at": self._now(),
            }
            conn.execute(
                "UPDATE claims SET outcome = ?, receipt_json = ?, settled_at = ? WHERE claim_id = ?",
                (outcome, Receipt(receipt).to_json(), self._now(), claim_id))
            conn.execute("UPDATE grants SET state = ?, settled_at = ? WHERE grant_id = ?",
                         (outcome, self._now(), claim["grant_id"]))
            if outcome == GRANT_INDETERMINATE_SPENT:
                self._raise_hold(conn, claim["grant_id"], claim["descriptor_digest"], None, reason,
                                 claim_id)
            else:
                self._clear_holds(conn, claim_id, f"recovered as {outcome}")
            self._event(conn, "recovered", claim["descriptor_digest"], {
                "claim_id": claim_id, "verified": verified, "outcome": outcome, "reason": reason})
        return {"replayed": False, "receipt": receipt}

    def mark_restart_recovery(self) -> int:
        """After a broker restart every unresolved claim is recovery-only.

        Called before the consume socket opens, so no worker can use a claim whose
        outcome the previous broker never durably settled.
        """
        with self._transaction():
            conn = self._require_conn()
            rows = conn.execute(
                "SELECT claim_id, grant_id, descriptor_digest FROM claims WHERE outcome = ?",
                (GRANT_SPENT_PENDING,)).fetchall()
            for row in rows:
                self._raise_hold(
                    conn, row["grant_id"], row["descriptor_digest"], None,
                    "broker restart with an unresolved claim", row["claim_id"])
            self._event(conn, "restart_recovery", "broker", {"unresolved": len(rows)})
        return len(rows)

    # ── read-only status ──────────────────────────────────────────────
    def worktree_status(self, identity: Mapping[str, Any]) -> dict:
        """Read-only: available to ordinary local writers and never grants authority."""
        key = _identity_key(proto.validate_context(dict(identity)))
        conn = self._require_conn()
        registration = conn.execute(
            "SELECT * FROM registrations WHERE identity_key = ? AND state = ?",
            (key, REGISTRATION_ACTIVE)).fetchone()
        holds = conn.execute(
            "SELECT hold_id, descriptor_digest, reason FROM holds "
            "WHERE cleared_at IS NULL AND (worktree = ? OR worktree IS NULL)",
            (str(identity.get("worktree")),)).fetchall()
        if holds:
            status = WORKTREE_HELD
        elif registration is None:
            status = WORKTREE_UNREGISTERED
        else:
            status = WORKTREE_REGISTERED
        return {
            "status": status,
            "identity_key": key,
            "generation": None if registration is None else int(registration["generation"]),
            "correlations": [dict(h) for h in holds],
        }

    def active_holds(self) -> list[dict]:
        conn = self._require_conn()
        rows = conn.execute(
            "SELECT * FROM holds WHERE cleared_at IS NULL").fetchall()
        return [dict(r) for r in rows]

    def clear_hold(self, hold_id: str, reason: str, *, admin: bool) -> dict:
        if not admin:
            raise ConsentError("clearing a hold requires the authenticated root admin peer")
        with self._transaction():
            conn = self._require_conn()
            row = conn.execute("SELECT * FROM holds WHERE hold_id = ?", (hold_id,)).fetchone()
            if row is None:
                raise ConsentError(f"unknown hold {hold_id}")
            if row["cleared_at"] is not None:
                return {"hold_id": hold_id, "cleared": True, "replayed": True}
            conn.execute(
                "UPDATE holds SET cleared_at = ?, cleared_reason = ? WHERE hold_id = ?",
                (self._now(), reason, hold_id))
            self._event(conn, "hold_cleared", str(row["descriptor_digest"]),
                        {"hold_id": hold_id, "reason": reason})
        return {"hold_id": hold_id, "cleared": True, "replayed": False}

    # ── internals ─────────────────────────────────────────────────────
    def _effective_state(self, conn: sqlite3.Connection, grant_row: sqlite3.Row) -> str:
        state = grant_row["state"]
        if state == GRANT_ISSUED and float(grant_row["expires_at"]) <= self._now():
            conn.execute("UPDATE grants SET state = ? WHERE grant_id = ?",
                         (GRANT_EXPIRED, grant_row["grant_id"]))
            return GRANT_EXPIRED
        return state

    def _prior_claim(self, conn: sqlite3.Connection, grant_id: str) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT * FROM claims WHERE grant_id = ? ORDER BY created_at LIMIT 1",
            (grant_id,)).fetchone()

    def _missing_readback(
        self, conn: sqlite3.Connection, claim: sqlite3.Row, readback: Mapping[str, str],
    ) -> list[str]:
        """Names of descriptor path digests that the readback did not account for."""
        if not isinstance(readback, Mapping) or not readback:
            return ["<all readback hashes>"]
        for value in readback.values():
            if not proto.is_hex_digest(value):
                return ["<readback hash is not a lowercase SHA-256>"]
        return []

    def _require_peer_matches_registration(
        self, ctx: Mapping[str, Any], peer: ExecutionIdentity, registration: sqlite3.Row,
    ) -> None:
        stored = proto.parse_json_strict(registration["context_json"])
        if stored["boot_id"] != peer.boot_id:
            raise ConsentError("peer boot id does not match the registered run; refusing")
        if int(stored["uid"]) != peer.uid:
            raise ConsentError("peer uid does not match the registered worker")
        if int(stored["pid"]) != peer.pid:
            raise ConsentError(
                "consume peer PID must EQUAL the registered worker PID (no descendant allowance)")
        if int(stored["start_ticks"]) != peer.start_ticks:
            raise ConsentError("peer start ticks do not match; the PID may have been recycled")
        if _identity_tuple_of_context(stored) != _identity_tuple_of_context(ctx):
            raise ConsentError("presented context does not match the registered run")

    def _raise_hold(
        self, conn: sqlite3.Connection, grant_id: str, digest: str,
        worktree: str | None, reason: str, claim_id: str | None = None,
    ) -> str:
        """Retain a hold. The hold is correlated to its claim so recovery can find it."""
        existing = conn.execute(
            "SELECT hold_id FROM holds WHERE descriptor_digest = ? AND cleared_at IS NULL",
            (digest,)).fetchone()
        if existing is not None:
            if claim_id is not None:
                conn.execute("UPDATE holds SET claim_id = COALESCE(claim_id, ?) WHERE hold_id = ?",
                             (claim_id, existing["hold_id"]))
            return str(existing["hold_id"])
        hold_id = secrets.token_hex(16)
        conn.execute(
            "INSERT INTO holds(hold_id, claim_id, descriptor_digest, worktree, reason, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (hold_id, claim_id, digest, worktree, reason, self._now()))
        return hold_id

    def _clear_holds(self, conn: sqlite3.Connection, claim_id: str, reason: str) -> None:
        conn.execute(
            "UPDATE holds SET cleared_at = ?, cleared_reason = ? WHERE claim_id = ? "
            "AND cleared_at IS NULL", (self._now(), reason, claim_id))


class _ImmediateTransaction:
    """One ``BEGIN IMMEDIATE`` ... ``COMMIT`` scope; rolls back on any exception."""

    def __init__(self, store: AuthorityStore):
        self._store = store

    def __enter__(self):
        conn = self._store._require_conn()
        conn.execute("BEGIN IMMEDIATE")
        return conn

    def __exit__(self, exc_type, exc, tb):
        conn = self._store._conn
        if conn is None:
            return False
        if exc_type is None:
            conn.execute("COMMIT")
        else:
            conn.execute("ROLLBACK")
        return False


def _identity_tuple_of_context(ctx: Mapping[str, Any]) -> tuple[int, int, str, int]:
    return (int(ctx["uid"]), int(ctx["pid"]), str(ctx["boot_id"]), int(ctx["start_ticks"]))


def _claim_matches(
    claim: sqlite3.Row, digest: str, transaction_id: str, journal_digest: str,
) -> bool:
    return (
        claim["descriptor_digest"] == digest
        and claim["transaction_id"] == transaction_id
        and claim["journal_digest"] == journal_digest
    )


def _match_descriptor_to_envelope(
    descriptor: Mapping[str, Any],
    envelope: Mapping[str, Any],
    plan_bytes: bytes,
    arguments_sha256: str,
) -> str:
    """Bind the admin-prepared descriptor to the exact plan bytes; fail closed on any drift."""
    validated = proto.validate_descriptor(dict(descriptor))
    if validated["plan_sha256"] != proto.sha256_hex(plan_bytes):
        raise ConsentError(
            "plan bytes do not match the descriptor's plan_sha256; refusing to issue")
    if validated["arguments_sha256"] != arguments_sha256:
        raise ConsentError(
            "arguments do not match the descriptor's arguments_sha256; refusing to issue")
    context = proto.validate_context(dict(envelope["context"]))
    if validated["context"] != context:
        raise ConsentError("descriptor context does not match the envelope context")
    return proto.descriptor_digest(validated)


def open_store(path: os.PathLike[str] | str = DEFAULT_DB_PATH) -> AuthorityStore:
    """Open and validate an authority store, failing closed when unavailable."""
    store = AuthorityStore(path)
    store.open()
    return store


def parse_receipt_json(text: str) -> dict:
    try:
        value = json.loads(text)
    except ValueError as exc:  # persisted text is ours; a failure is corruption
        raise ConsentError(f"stored receipt is corrupt: {exc}") from exc
    if not isinstance(value, dict):
        raise ConsentError("stored receipt is not a JSON object")
    return value
