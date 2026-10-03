"""Strict v1 wire protocol and canonical schema for protected-write consent.

D1 scope: this module defines the contract only. Nothing here integrates, grants,
or exempts any real write — D2 owns file-tool transactional integration.

Wire format: one 4-byte big-endian length prefix followed by that many bytes of
UTF-8 JSON. Every message is validated against an explicit field table: unknown
fields, duplicate keys, ``NaN``/``Infinity``, wrong types and out-of-range limits
are rejected rather than coerced. Canonical digests hash a JSON encoding with
sorted keys, compact separators and UTF-8 so two equivalent values always hash
identically.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import struct
from typing import Any, Iterable, Mapping, Sequence

SCHEMA_VERSION = "protected-write-v1"

#: Hard message cap on both directions of the socket.
MAX_MESSAGE_BYTES = 8 * 1024 * 1024
#: Maximum path records in one descriptor.
MAX_PATHS = 32
#: Maximum combined before+after byte count of one descriptor.
MAX_TOTAL_BYTES = 4 * 1024 * 1024
#: Grant lifetime bounds.
DEFAULT_TTL_SECONDS = 900
MAX_TTL_SECONDS = 3600
#: Length prefix width.
FRAME_HEADER_BYTES = 4

TOOLS: tuple[str, ...] = ("write_file", "patch_replace", "patch_v4a")
ACTIONS: tuple[str, ...] = (
    "create", "update", "delete", "move_source", "move_destination")
HEX_DIGEST_CHARS = 64
#: Git commit SHAs are SHA-1 (40 hex).
GIT_SHA_CHARS = 40


class ProtocolError(ValueError):
    """A message, descriptor or value violates the v1 contract."""


def _reject_constant(name: str) -> Any:
    raise ProtocolError(f"non-finite JSON constant is not allowed: {name}")


def _pairs_without_duplicates(pairs: Sequence[tuple[str, Any]]) -> dict:
    seen: set[str] = set()
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise ProtocolError(f"duplicate JSON field: {key!r}")
        seen.add(key)
        out[key] = value
    return out


def parse_json_strict(text: str) -> Any:
    """``json.loads`` that rejects duplicate keys and non-finite numbers."""
    try:
        return json.loads(
            text,
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=_reject_constant,
        )
    except ProtocolError:
        raise
    except (ValueError, TypeError) as exc:
        raise ProtocolError(f"invalid JSON: {exc}") from exc


def canonical_json_bytes(obj: Any) -> bytes:
    """Deterministic JSON encoding used for every digest and stored byte image."""
    try:
        text = json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False)
    except (ValueError, TypeError) as exc:
        raise ProtocolError(f"value is not canonically encodable: {exc}") from exc
    return text.encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_digest(obj: Any) -> str:
    """SHA-256 of the canonical JSON encoding of ``obj`` (lowercase hex)."""
    return sha256_hex(canonical_json_bytes(obj))


def is_hex_digest(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == HEX_DIGEST_CHARS
        and all(c in "0123456789abcdef" for c in value)
    )


def is_git_sha(value: Any) -> bool:
    """A full lowercase 40-hex git commit SHA (the repository baseline)."""
    return (
        isinstance(value, str)
        and len(value) == GIT_SHA_CHARS
        and all(c in "0123456789abcdef" for c in value)
    )


# ── field-table validation ────────────────────────────────────────────────
def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_bool(value: Any) -> bool:
    return isinstance(value, bool)


def _is_str(value: Any) -> bool:
    return isinstance(value, str)


def _is_digest(value: Any) -> bool:
    return is_hex_digest(value)


def _is_bounded_str(limit: int):
    def check(value: Any) -> bool:
        return isinstance(value, str) and 0 < len(value) <= limit
    return check


def _is_owner_str(limit: int):
    """An owner field that may be ABSENT (``""``), and is never a wildcard.

    A human terminal has no board card, and a session can have no run id. What
    authenticates a request is the kernel identity plus the repository realpaths
    and baseline; an owner field still binds by EXACT string equality, so an
    empty value can never match a registered card, run or session.
    """

    def check(value: Any) -> bool:
        return isinstance(value, str) and len(value) <= limit

    return check


def _is_int_range(low: int, high: int):
    def check(value: Any) -> bool:
        return _is_int(value) and low <= value <= high
    return check


def _is_one_of(values: Iterable[str]):
    allowed = frozenset(values)
    return lambda value: isinstance(value, str) and value in allowed


def _is_list_of(check):
    def validate(value: Any) -> bool:
        return isinstance(value, list) and all(check(item) for item in value)
    return validate


def _is_nullable(check):
    return lambda value: value is None or check(value)


#: type name -> predicate. Table-driven; no name/kind dispatch ladder.
TYPE_CHECKS: dict[str, Any] = {
    "str": _is_str,
    "digest": _is_digest,
    "git_sha": is_git_sha,
    "bool": _is_bool,
    "int": _is_int,
    "non_negative_int": _is_int_range(0, 2**31 - 1),
    "ttl": _is_int_range(1, MAX_TTL_SECONDS),
    "version": _is_one_of((SCHEMA_VERSION,)),
    "tool": _is_one_of(TOOLS),
    "action": _is_one_of(ACTIONS),
    "short_str": _is_bounded_str(512),
    "owner_str": _is_owner_str(512),
    # base64 inflates by 4/3; bound the encoded text above the raw message cap.
    "base64_blob": _is_bounded_str((MAX_MESSAGE_BYTES // 3 + 1) * 4),
    "path_str": _is_bounded_str(4096),
    "reason": _is_bounded_str(2048),
    "nullable_digest": _is_nullable(_is_digest),
    "nullable_length": _is_nullable(_is_int_range(0, MAX_TOTAL_BYTES)),
    "nullable_reason": _is_nullable(_is_bounded_str(2048)),
    "str_list": _is_list_of(_is_bounded_str(4096)),
}


def validate_fields(
    obj: Any,
    schema: Mapping[str, tuple[str, bool]],
    *,
    where: str,
) -> dict:
    """Validate ``obj`` against ``{field: (type_name, required)}`` and return a copy.

    Unknown fields, missing required fields, wrong types and unknowable type names
    all raise :class:`ProtocolError`. No coercion is ever performed.
    """
    if not isinstance(obj, dict):
        raise ProtocolError(f"{where}: expected a JSON object, got {type(obj).__name__}")
    unknown = sorted(set(obj) - set(schema))
    if unknown:
        raise ProtocolError(f"{where}: unknown field(s): {', '.join(unknown)}")
    out: dict[str, Any] = {}
    for name, (type_name, required) in schema.items():
        if name not in obj:
            if required:
                raise ProtocolError(f"{where}: missing required field {name!r}")
            continue
        value = obj[name]
        if type_name.startswith("object:"):
            # Nested object; the caller validates its contents against a schema.
            if not isinstance(value, dict):
                raise ProtocolError(
                    f"{where}: field {name!r} must be a JSON object")
            out[name] = value
            continue
        if type_name.startswith("list:"):
            # Nested list; the caller validates its items against a schema.
            if not isinstance(value, list):
                raise ProtocolError(
                    f"{where}: field {name!r} must be a JSON array")
            out[name] = value
            continue
        check = TYPE_CHECKS.get(type_name)
        if check is None:  # programming error in a schema table, never input
            raise ProtocolError(f"{where}: unknown declared type {type_name!r}")
        if not check(value):
            raise ProtocolError(
                f"{where}: field {name!r} has invalid type or range ({type_name})")
        out[name] = value
    return out


CONTEXT_SCHEMA: dict[str, tuple[str, bool]] = {
    "board": ("owner_str", True),
    "card": ("owner_str", True),
    "profile": ("owner_str", True),
    "home": ("path_str", True),
    "run": ("owner_str", True),
    "session": ("owner_str", True),
    "registration_generation": ("non_negative_int", True),
    "uid": ("non_negative_int", True),
    "pid": ("non_negative_int", True),
    "boot_id": ("short_str", True),
    "start_ticks": ("non_negative_int", True),
    "worktree": ("path_str", True),
    "git_dir": ("path_str", True),
    "common_dir": ("path_str", True),
    "baseline": ("git_sha", True),
}

PATH_RECORD_SCHEMA: dict[str, tuple[str, bool]] = {
    "relative": ("path_str", True),
    "normalized": ("path_str", True),
    "resolved": ("path_str", True),
    "action": ("action", True),
    "protected_reason": ("nullable_reason", True),
    "before_sha256": ("nullable_digest", True),
    "before_length": ("nullable_length", True),
    "after_sha256": ("nullable_digest", True),
    "after_length": ("nullable_length", True),
}

DESCRIPTOR_SCHEMA: dict[str, tuple[str, bool]] = {
    "schema_version": ("version", True),
    "context": ("object:context", True),
    "plan_sha256": ("digest", True),
    "arguments_sha256": ("digest", True),
    "paths": ("list:paths", True),
}

ENVELOPE_SCHEMA: dict[str, tuple[str, bool]] = {
    "schema_version": ("version", True),
    "context": ("object:context", True),
    "tool": ("tool", True),
    "arguments": ("object:arguments", True),
    "plan_bytes_base64": ("base64_blob", False),
}


def _validate_path_record(record: Any, *, where: str) -> dict:
    out = validate_fields(record, PATH_RECORD_SCHEMA, where=where)
    # Null digests mean TRUE absence only; a present side always carries both hash
    # and length. Partial nulls are ambiguous and rejected.
    for side in ("before", "after"):
        digest = out[f"{side}_sha256"]
        length = out[f"{side}_length"]
        if (digest is None) != (length is None):
            raise ProtocolError(
                f"{where}: {side}_sha256 and {side}_length must both be null (true absence) "
                "or both be present")
    if len(out["relative"]) == 0 or out["relative"].startswith("/"):
        raise ProtocolError(f"{where}: 'relative' must be a non-empty relative path")
    return out


def validate_context(ctx: Any, *, where: str = "context") -> dict:
    out = validate_fields(ctx, CONTEXT_SCHEMA, where=where)
    for name in ("home", "worktree", "git_dir", "common_dir"):
        if not out[name].startswith("/"):
            raise ProtocolError(f"{where}: {name!r} must be an absolute realpath")
    return out


def validate_arguments(arguments: Any, *, where: str = "arguments") -> dict:
    """Tool arguments are an opaque, bounded JSON object; ``cross_profile`` must be false."""
    if not isinstance(arguments, dict):
        raise ProtocolError(f"{where}: expected a JSON object")
    if arguments.get("cross_profile") is not False:
        raise ProtocolError(f"{where}: 'cross_profile' must be present and false")
    encoded = canonical_json_bytes(arguments)
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise ProtocolError(f"{where}: arguments exceed the message limit")
    return arguments


def validate_paths(paths: Any, *, where: str = "paths") -> list[dict]:
    if not isinstance(paths, list):
        raise ProtocolError(f"{where}: expected a list of path records")
    if len(paths) > MAX_PATHS:
        raise ProtocolError(f"{where}: {len(paths)} path records exceeds the limit of {MAX_PATHS}")
    records = [_validate_path_record(item, where=f"{where}[{i}]") for i, item in enumerate(paths)]
    normalized = [r["normalized"] for r in records]
    if len(set(normalized)) != len(normalized):
        raise ProtocolError(f"{where}: duplicate or aliased path records are not allowed")
    if not records:
        raise ProtocolError(f"{where}: at least one path record is required")
    total = 0
    for record in records:
        total += (record["before_length"] or 0) + (record["after_length"] or 0)
    if total > MAX_TOTAL_BYTES:
        raise ProtocolError(
            f"{where}: combined before/after bytes ({total}) exceed the {MAX_TOTAL_BYTES} limit")
    return records


def build_descriptor(
    context: Mapping[str, Any],
    plan_sha256: str,
    arguments_sha256: str,
    paths: Sequence[Mapping[str, Any]],
) -> dict:
    """Canonical persistent descriptor. Ordered path records; digest over the whole value."""
    descriptor = {
        "schema_version": SCHEMA_VERSION,
        "context": validate_context(context),
        "plan_sha256": plan_sha256,
        "arguments_sha256": arguments_sha256,
        "paths": validate_paths([dict(p) for p in paths]),
    }
    if not is_hex_digest(plan_sha256) or not is_hex_digest(arguments_sha256):
        raise ProtocolError("descriptor: plan_sha256 and arguments_sha256 must be lowercase SHA-256")
    return descriptor


def descriptor_digest(descriptor: Mapping[str, Any]) -> str:
    return canonical_digest(validate_descriptor(descriptor))


def validate_descriptor(descriptor: Any, *, where: str = "descriptor") -> dict:
    obj = validate_fields(descriptor, DESCRIPTOR_SCHEMA, where=where)
    obj["context"] = validate_context(obj["context"], where=f"{where}.context")
    obj["paths"] = validate_paths(obj["paths"], where=f"{where}.paths")
    if not is_hex_digest(obj["plan_sha256"]):
        raise ProtocolError(f"{where}: 'plan_sha256' must be a lowercase SHA-256")
    if not is_hex_digest(obj["arguments_sha256"]):
        raise ProtocolError(f"{where}: 'arguments_sha256' must be a lowercase SHA-256")
    return obj


def validate_envelope(envelope: Any, *, where: str = "envelope") -> dict:
    obj = validate_fields(envelope, ENVELOPE_SCHEMA, where=where)
    obj["context"] = validate_context(obj["context"], where=f"{where}.context")
    obj["arguments"] = validate_arguments(obj["arguments"], where=f"{where}.arguments")
    blob = obj.pop("plan_bytes_base64", None)
    if blob is not None:
        try:
            obj["plan_bytes"] = base64.b64decode(blob, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ProtocolError(f"{where}: plan_bytes_base64 is not valid base64: {exc}") from exc
        if len(obj["plan_bytes"]) > MAX_MESSAGE_BYTES:
            raise ProtocolError(f"{where}: plan bytes exceed the message limit")
    return obj


# ── framing ───────────────────────────────────────────────────────────────
def encode_frame(message: Mapping[str, Any]) -> bytes:
    """Canonical JSON payload prefixed with a 4-byte big-endian length."""
    payload = canonical_json_bytes(dict(message))
    if len(payload) > MAX_MESSAGE_BYTES:
        raise ProtocolError(
            f"message of {len(payload)} bytes exceeds the limit of {MAX_MESSAGE_BYTES}")
    return struct.pack(">I", len(payload)) + payload


def decode_header(header: bytes) -> int:
    if len(header) != FRAME_HEADER_BYTES:
        raise ProtocolError("truncated frame header")
    (length,) = struct.unpack(">I", header)
    if length == 0:
        raise ProtocolError("empty frame")
    if length > MAX_MESSAGE_BYTES:
        raise ProtocolError(
            f"declared frame of {length} bytes exceeds the limit of {MAX_MESSAGE_BYTES}")
    return length


def decode_payload(payload: bytes) -> Any:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError(f"frame is not valid UTF-8: {exc}") from exc
    return parse_json_strict(text)


def decode_frame(data: bytes) -> tuple[Any, bytes]:
    """-> ``(message, remaining_bytes)`` for one frame taken off the front of ``data``."""
    if len(data) < FRAME_HEADER_BYTES:
        raise ProtocolError("truncated frame header")
    length = decode_header(data[:FRAME_HEADER_BYTES])
    end = FRAME_HEADER_BYTES + length
    if len(data) < end:
        raise ProtocolError("truncated frame payload")
    return decode_payload(data[FRAME_HEADER_BYTES:end]), data[end:]
