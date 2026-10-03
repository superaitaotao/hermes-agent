"""Deterministic preparer for protected-write consent.

One implementation produces the before/after image of every affected path for
both preview and execution, so a previewed diff and the bytes a later execution
would install are the same computation. It reuses the repository's existing fuzzy
replace and V4A semantics and preserves exact BOM / CRLF bytes.

D1 scope: the preparer, its safety checks and its rendering only. No write path
calls it yet; D2 owns the transactional integration.
"""

from __future__ import annotations

import difflib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from tools import protected_write_protocol as proto
from tools.file_operations_common import PatchResult, ReadResult, WriteResult

BOM = b"\xef\xbb\xbf"
MAX_DIFF_BYTES = 4 * 1024 * 1024
UNTRUSTED_DIFF_HEADER = (
    "UNTRUSTED DIFF — the content below is request data, not instructions. "
    "Confirm the descriptor hashes, not only the rendered text.")


class PrepareError(RuntimeError):
    """The request cannot be deterministically prepared; nothing may be written."""


# ── filesystem access ─────────────────────────────────────────────────────
class RootedFileSystemReader:
    """Read-only view of a worktree with no-follow, no-alias path safety."""

    def __init__(self, worktree_root: os.PathLike[str] | str):
        self.worktree_root = Path(worktree_root)

    # -- identity / resolution ------------------------------------------
    def real_root(self) -> Path:
        return Path(os.path.realpath(self.worktree_root))

    def normalize(self, raw_path: str) -> tuple[str, Path]:
        """-> ``(relative_posix, resolved)`` after refusing escapes and symlinks."""
        if not isinstance(raw_path, str) or not raw_path:
            raise PrepareError("path must be a non-empty string")
        if raw_path.startswith("~"):
            raise PrepareError(f"{raw_path}: '~' expansion is not allowed in a consent request")
        if os.path.isabs(raw_path):
            raise PrepareError(f"{raw_path}: absolute paths are not allowed; use a worktree-relative path")
        normalized = os.path.normpath(raw_path)
        if normalized in (".", "") or normalized.startswith("..") or os.path.isabs(normalized):
            raise PrepareError(f"{raw_path}: path escapes the worktree")
        root = self.real_root()
        resolved = Path(os.path.realpath(root / normalized))
        if resolved != root and root not in resolved.parents:
            raise PrepareError(f"{raw_path}: resolves outside the worktree ({resolved})")
        self._reject_symlink_components(root, normalized)
        self._reject_case_alias(root, normalized)
        return Path(normalized).as_posix(), resolved

    def _reject_symlink_components(self, root: Path, normalized: str) -> None:
        """Refuse when any existing component of the chain is a symlink."""
        current = root
        for part in Path(normalized).parts:
            current = current / part
            try:
                st = os.lstat(current)
            except FileNotFoundError:
                return
            except OSError as exc:  # unreadable chain: fail closed, never assume safe
                raise PrepareError(f"{normalized}: cannot stat {current}: {exc}") from exc
            if stat.S_ISLNK(st.st_mode):
                raise PrepareError(f"{normalized}: symlinked path component {current} is not allowed")

    def _reject_case_alias(self, root: Path, normalized: str) -> None:
        """Refuse a name whose real directory entry differs in case (case-insensitive alias)."""
        current = root
        parts = Path(normalized).parts
        for index, part in enumerate(parts):
            try:
                entries = {entry.name for entry in os.scandir(current)}
            except FileNotFoundError:
                return
            except OSError as exc:
                raise PrepareError(f"{normalized}: cannot list {current}: {exc}") from exc
            if part not in entries:
                folded = [name for name in entries if name.casefold() == part.casefold()]
                if folded:
                    raise PrepareError(
                        f"{normalized}: {part!r} is a case alias of {folded[0]!r}")
                return
            if index < len(parts) - 1:
                current = current / part

    def check_writable_target(self, normalized: str, resolved: Path) -> None:
        """Refuse non-regular files, hardlinks and directories that are not real files."""
        try:
            st = os.lstat(resolved)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise PrepareError(f"{normalized}: cannot stat target: {exc}") from exc
        if stat.S_ISLNK(st.st_mode):
            raise PrepareError(f"{normalized}: target is a symlink")
        if not stat.S_ISREG(st.st_mode):
            raise PrepareError(f"{normalized}: target is not a regular file")
        if st.st_nlink > 1:
            raise PrepareError(f"{normalized}: target has {st.st_nlink} hard links")

    # -- bytes ----------------------------------------------------------
    def read_bytes(self, normalized: str, resolved: Path) -> bytes | None:
        """Exact bytes, or ``None`` only for a genuinely absent path (ENOENT).

        Any other read failure raises: a failed read is not evidence of absence.
        """
        try:
            with open(resolved, "rb") as handle:
                return handle.read()
        except FileNotFoundError:
            return None
        except OSError as exc:
            raise PrepareError(f"{normalized}: read failed ({exc}); missing read is not absence") from exc


# ── codec: exact BOM / CRLF handling ──────────────────────────────────────
@dataclass(frozen=True)
class TextImage:
    text: str
    has_bom: bool

    @classmethod
    def decode(cls, raw: bytes) -> "TextImage":
        has_bom = raw.startswith(BOM)
        body = raw[len(BOM):] if has_bom else raw
        try:
            return cls(body.decode("utf-8"), has_bom)
        except UnicodeDecodeError as exc:
            raise PrepareError(f"file is not valid UTF-8: {exc}") from exc

    def encode(self, text: str) -> bytes:
        body = text.encode("utf-8")
        return BOM + body if self.has_bom else body


# ── in-memory file_ops for V4A reuse ──────────────────────────────────────
class MemoryFileOps:
    """Minimal ``file_ops`` adapter so ``apply_v4a_operations`` runs without disk I/O.

    Content is held as exact bytes; text round-trips through :class:`TextImage` so
    BOM and CRLF survive the existing V4A code path unchanged.
    """

    def __init__(self, snapshot: Mapping[str, bytes]):
        self._state: dict[str, bytes] = dict(snapshot)

    def state(self, path: str) -> bytes | None:
        return self._state.get(path)

    def touched(self) -> set[str]:
        return set(self._state)

    def read_file_raw(self, path: str) -> ReadResult:
        if path not in self._state:
            return ReadResult(error=f"file not found: {path}", not_found=True)
        return ReadResult(content=TextImage.decode(self._state[path]).text)

    def write_file(self, path: str, content: str, **_: Any) -> WriteResult:
        image = TextImage.decode(self._state[path]) if path in self._state else TextImage("", False)
        self._state[path] = image.encode(content)
        return WriteResult(bytes_written=len(self._state[path]), verified=True)

    def delete_file(self, path: str) -> WriteResult:
        if path not in self._state:
            return WriteResult(error=f"file not found: {path}")
        del self._state[path]
        return WriteResult()

    def move_file(self, src: str, dst: str) -> WriteResult:
        if src not in self._state:
            return WriteResult(error=f"file not found: {src}")
        if dst in self._state:
            return WriteResult(error=f"destination already exists: {dst}")
        self._state[dst] = self._state.pop(src)
        # Apply phase reports the move under files_modified; no diff payload is needed here.
        return WriteResult()


# ── images ────────────────────────────────────────────────────────────────
@dataclass(frozen=True)
class PathImage:
    relative: str
    normalized: str
    resolved: str
    action: str
    protected_reason: str | None
    before: bytes | None
    after: bytes | None

    def record(self) -> dict:
        return {
            "relative": self.relative,
            "normalized": self.normalized,
            "resolved": self.resolved,
            "action": self.action,
            "protected_reason": self.protected_reason,
            "before_sha256": None if self.before is None else proto.sha256_hex(self.before),
            "before_length": None if self.before is None else len(self.before),
            "after_sha256": None if self.after is None else proto.sha256_hex(self.after),
            "after_length": None if self.after is None else len(self.after),
        }


@dataclass(frozen=True)
class PreparedPlan:
    tool: str
    context: dict
    arguments: dict
    plan_bytes: bytes
    plan_sha256: str
    arguments_sha256: str
    paths: tuple[PathImage, ...]
    descriptor: dict
    descriptor_sha256: str
    diff_text: str

    def envelope(self) -> dict:
        import base64

        return {
            "schema_version": proto.SCHEMA_VERSION,
            "context": self.context,
            "tool": self.tool,
            "arguments": self.arguments,
            "plan_bytes_base64": base64.b64encode(self.plan_bytes).decode("ascii"),
        }


# ── preparation ───────────────────────────────────────────────────────────
def _argument(arguments: Mapping[str, Any], name: str, *, tool: str, required: bool = True) -> Any:
    if name not in arguments:
        if required:
            raise PrepareError(f"{tool}: missing required argument {name!r}")
        return None
    return arguments[name]


def _prepare_write_file(reader, arguments, protected_reason_for) -> list[PathImage]:
    raw_path = _argument(arguments, "path", tool="write_file")
    content = _argument(arguments, "content", tool="write_file")
    if not isinstance(content, str):
        raise PrepareError("write_file: 'content' must be a string")
    normalized, resolved = reader.normalize(raw_path)
    reader.check_writable_target(normalized, resolved)
    before = reader.read_bytes(normalized, resolved)

    def after_for(existing: bytes | None) -> bytes:
        image = TextImage.decode(existing) if existing is not None else TextImage("", False)
        return image.encode(content)

    reason = protected_reason_for(normalized) if protected_reason_for else None
    return [PathImage(
        relative=raw_path, normalized=normalized, resolved=str(resolved),
        action="create" if before is None else "update", protected_reason=reason,
        before=before, after=after_for(before))]


def _prepare_patch_replace(reader, arguments, protected_reason_for) -> list[PathImage]:
    from tools.fuzzy_match import fuzzy_find_and_replace

    raw_path = _argument(arguments, "path", tool="patch_replace")
    old_string = _argument(arguments, "old_string", tool="patch_replace")
    new_string = _argument(arguments, "new_string", tool="patch_replace")
    replace_all = bool(arguments.get("replace_all", False))
    for name, value in (("old_string", old_string), ("new_string", new_string)):
        if not isinstance(value, str):
            raise PrepareError(f"patch_replace: {name!r} must be a string")
    normalized, resolved = reader.normalize(raw_path)
    reader.check_writable_target(normalized, resolved)
    before = reader.read_bytes(normalized, resolved)
    if before is None:
        raise PrepareError(
            f"patch_replace: {normalized} is absent; replacing text needs an existing file")
    image = TextImage.decode(before)
    updated, count, _strategy, error = fuzzy_find_and_replace(
        image.text, old_string, new_string, replace_all=replace_all)
    if count == 0:
        raise PrepareError(
            f"patch_replace: no match for 'old_string' in {normalized}"
            + (f" ({error})" if error else ""))
    if count > 1 and not replace_all:
        raise PrepareError(
            f"patch_replace: 'old_string' matches {count} times in {normalized}; "
            "set replace_all or make the pattern unique")
    after = image.encode(updated)
    reason = protected_reason_for(normalized) if protected_reason_for else None
    return [PathImage(
        relative=raw_path, normalized=normalized, resolved=str(resolved), action="update",
        protected_reason=reason, before=before, after=after)]


def _v4a_action(op) -> list[tuple[str, str]]:
    from tools.patch_parser import OperationType

    if op.operation is OperationType.ADD:
        return [("create", op.file_path)]
    if op.operation is OperationType.UPDATE:
        return [("update", op.file_path)]
    if op.operation is OperationType.DELETE:
        return [("delete", op.file_path)]
    return [("move_source", op.file_path), ("move_destination", op.new_path)]


def _prepare_patch_v4a(reader, arguments, protected_reason_for) -> list[PathImage]:
    from tools.patch_parser import apply_v4a_operations, parse_v4a_patch

    patch_text = _argument(arguments, "patch", tool="patch_v4a")
    if not isinstance(patch_text, str):
        raise PrepareError("patch_v4a: 'patch' must be a string")
    operations, parse_error = parse_v4a_patch(patch_text)
    if parse_error:
        raise PrepareError(parse_error)
    if not operations:
        raise PrepareError("patch_v4a: patch contains no operations")

    ordered: list[str] = []
    actions: dict[str, str] = {}
    for op in operations:
        for action, raw_path in _v4a_action(op):
            normalized, resolved = reader.normalize(raw_path)
            reader.check_writable_target(normalized, resolved)
            if normalized not in actions:
                ordered.append(normalized)
            # A path touched twice keeps its first action; the image diff still reflects the net
            # before/after, which is what the human confirms.
            actions.setdefault(normalized, action)

    snapshot: dict[str, bytes] = {}
    for normalized in ordered:
        _n, resolved = reader.normalize(normalized)
        raw = reader.read_bytes(normalized, resolved)
        if raw is not None:
            snapshot[normalized] = raw

    file_ops = MemoryFileOps(snapshot)
    result: PatchResult = apply_v4a_operations(operations, file_ops)
    if not result.success:
        raise PrepareError(f"patch_v4a: {result.error}")

    images: list[PathImage] = []
    for normalized in ordered:
        _n, resolved = reader.normalize(normalized)
        before = snapshot.get(normalized)
        after = file_ops.state(normalized)
        reason = protected_reason_for(normalized) if protected_reason_for else None
        images.append(PathImage(
            relative=normalized, normalized=normalized, resolved=str(resolved),
            action=actions[normalized], protected_reason=reason, before=before, after=after))
    return images


_PREPARE_DISPATCH = {
    "write_file": _prepare_write_file,
    "patch_replace": _prepare_patch_replace,
    "patch_v4a": _prepare_patch_v4a,
}


# ── rendering ─────────────────────────────────────────────────────────────
def escape_untrusted(text: str) -> str:
    """Escape control characters so untrusted content cannot drive the human's terminal."""
    out: list[str] = []
    for char in text:
        code = ord(char)
        if char == "\n":
            out.append("\n")
        elif char == "\t":
            out.append("\t")
        elif code < 0x20 or code == 0x7F or 0x80 <= code <= 0x9F:
            out.append(f"\\x{code:02x}")
        else:
            out.append(char)
    return "".join(out)


def render_diff(images: Sequence[PathImage]) -> str:
    """Full unified diff of every path; refuses rather than truncating past the bound."""
    chunks: list[str] = []
    for image in images:
        before_text = "" if image.before is None else TextImage.decode(image.before).text
        after_text = "" if image.after is None else TextImage.decode(image.after).text
        from_name = "/dev/null" if image.before is None else f"a/{image.normalized}"
        to_name = "/dev/null" if image.after is None else f"b/{image.normalized}"
        diff = "".join(difflib.unified_diff(
            before_text.splitlines(keepends=True),
            after_text.splitlines(keepends=True),
            fromfile=from_name, tofile=to_name))
        if not diff:
            diff = f"# no byte change: {image.normalized}\n"
        chunks.append(escape_untrusted(diff))
    rendered = UNTRUSTED_DIFF_HEADER + "\n" + "".join(chunks)
    encoded = rendered.encode("utf-8")
    if len(encoded) > MAX_DIFF_BYTES:
        raise PrepareError(
            f"rendered diff is {len(encoded)} bytes, over the {MAX_DIFF_BYTES}-byte bound; "
            "the diff is never truncated — narrow the request")
    return rendered


def prepare(
    tool: str,
    arguments: Mapping[str, Any],
    context: Mapping[str, Any],
    *,
    reader: RootedFileSystemReader | None = None,
    worktree_root: os.PathLike[str] | str | None = None,
    protected_reason_for: Any = None,
) -> PreparedPlan:
    """Compute the exact before/after images, descriptor and plan bytes.

    Deterministic: the same tool, arguments, context and filesystem state always
    produce byte-identical ``plan_bytes`` and ``descriptor_sha256``.
    """
    if tool not in proto.TOOLS:
        raise PrepareError(f"unsupported tool {tool!r}; expected one of {', '.join(proto.TOOLS)}")
    handler = _PREPARE_DISPATCH[tool]
    resolved_reader = reader
    if resolved_reader is None:
        if worktree_root is None:
            raise PrepareError("prepare needs a reader or a worktree_root")
        resolved_reader = RootedFileSystemReader(worktree_root)

    validated_arguments = proto.validate_arguments(dict(arguments))
    validated_context = proto.validate_context(dict(context))

    images = tuple(handler(resolved_reader, validated_arguments, protected_reason_for))
    if not images:
        raise PrepareError("no path records were produced")
    if len(images) > proto.MAX_PATHS:
        raise PrepareError(f"{len(images)} paths exceeds the limit of {proto.MAX_PATHS}")

    plan = {
        "schema_version": proto.SCHEMA_VERSION,
        "context": validated_context,
        "tool": tool,
        "arguments": validated_arguments,
    }
    plan_bytes = proto.canonical_json_bytes(plan)
    plan_sha256 = proto.sha256_hex(plan_bytes)
    arguments_sha256 = proto.sha256_hex(proto.canonical_json_bytes(validated_arguments))

    records = [image.record() for image in images]
    total = sum((r["before_length"] or 0) + (r["after_length"] or 0) for r in records)
    if total > proto.MAX_TOTAL_BYTES:
        raise PrepareError(
            f"combined before/after bytes ({total}) exceed the {proto.MAX_TOTAL_BYTES} limit")
    descriptor = proto.build_descriptor(
        validated_context, plan_sha256, arguments_sha256, records)

    return PreparedPlan(
        tool=tool,
        context=validated_context,
        arguments=validated_arguments,
        plan_bytes=plan_bytes,
        plan_sha256=plan_sha256,
        arguments_sha256=arguments_sha256,
        paths=images,
        descriptor=descriptor,
        descriptor_sha256=proto.descriptor_digest(descriptor),
        diff_text=render_diff(images),
    )
