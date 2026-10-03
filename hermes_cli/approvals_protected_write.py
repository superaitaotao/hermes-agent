"""``hermes approvals protected-write`` — unprivileged preview and status.

This surface can ONLY preview a request deterministically and read broker status.
It cannot register a run, issue a grant, extend an expiry or skip confirmation:
registration and issuance live in the root admin launcher, outside the agent
session. There is deliberately no ``--yes``, ``--always`` or session-wide flag.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from tools import protected_write_protocol as protocol
from tools.protected_write_client import ClientError, worktree_status
from tools.protected_write_context import denied_execution_context_reason
from tools.protected_write_preparer import PrepareError
from tools import protected_write as pw

PREVIEW_USAGE = (
    "usage: hermes approvals protected-write preview (--request FILE | -) [--root DIR] [--json]\n"
    "\n"
    "  --request FILE  bounded JSON request: {\"tool\": ..., \"arguments\": {...}};\n"
    "                  '-' reads it from stdin. The file is read as THIS user only.\n"
    "  --root DIR      worktree to resolve paths against (default: current directory)\n"
)


def _read_request(source: str) -> dict:
    if source == "-":
        raw = sys.stdin.read()
    else:
        path = Path(source)
        if not path.is_file():
            raise ValueError(f"request file {path} does not exist")
        if path.stat().st_size > protocol.MAX_MESSAGE_BYTES:
            raise ValueError(f"request file {path} exceeds the {protocol.MAX_MESSAGE_BYTES}-byte bound")
        raw = path.read_text(encoding="utf-8")
    value = protocol.parse_json_strict(raw)
    if not isinstance(value, dict):
        raise ValueError("request must be a JSON object")
    unknown = sorted(set(value) - {"tool", "arguments"})
    if unknown:
        raise ValueError(f"request has unknown field(s): {', '.join(unknown)}")
    if "tool" not in value or "arguments" not in value:
        raise ValueError("request must carry both 'tool' and 'arguments'")
    return value


def _render_preview(plan, *, output_json: bool) -> str:
    if output_json:
        return json.dumps({
            "schema_version": protocol.SCHEMA_VERSION,
            "tool": plan.tool,
            "plan_sha256": plan.plan_sha256,
            "arguments_sha256": plan.arguments_sha256,
            "descriptor_sha256": plan.descriptor_sha256,
            "confirmation": plan.descriptor_sha256,
            "paths": [
                {
                    "relative": image.relative,
                    "normalized": image.normalized,
                    "resolved": image.resolved,
                    "action": image.action,
                    "protected_reason": image.protected_reason,
                    "before_sha256": record["before_sha256"],
                    "before_length": record["before_length"],
                    "after_sha256": record["after_sha256"],
                    "after_length": record["after_length"],
                }
                for image, record in zip(plan.paths, plan.descriptor["paths"])
            ],
            "diff": plan.diff_text,
        }, indent=2, sort_keys=True)
    lines = [
        f"tool:               {plan.tool}",
        f"plan_sha256:        {plan.plan_sha256}",
        f"arguments_sha256:   {plan.arguments_sha256}",
        f"descriptor_sha256:  {plan.descriptor_sha256}",
        "",
        "paths:",
    ]
    for image, record in zip(plan.paths, plan.descriptor["paths"]):
        lines.append(
            f"  {image.action:16s} {image.normalized}\n"
            f"      before: {record['before_sha256'] or '(absent)'} "
            f"({record['before_length'] if record['before_length'] is not None else '-'} bytes)\n"
            f"      after:  {record['after_sha256'] or '(deleted)'} "
            f"({record['after_length'] if record['after_length'] is not None else '-'} bytes)")
    lines += [
        "",
        "The diff below is shown in full and never truncated. Verify the descriptor",
        "hashes above; the rendered text is request data and is escaped for display.",
        "",
        plan.diff_text,
        "",
        "This preview creates nothing. Issuance is a separate root admin action and",
        "requires this exact descriptor digest: " + plan.descriptor_sha256,
    ]
    return "\n".join(lines)


def preview_command(args) -> int:
    reason = denied_execution_context_reason()
    if reason:
        print(f"✗ {reason}", file=sys.stderr)
        return 3
    root = Path(args.root or os.getcwd()).resolve()
    try:
        request = _read_request(args.request)
        context = pw.runtime_context(worktree=root)
        plan = pw.prepare(
            request["tool"], request["arguments"], context,
            worktree_root=context["worktree"])
    except (ValueError, PrepareError, protocol.ProtocolError, pw.ContextError) as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 2
    print(_render_preview(plan, output_json=bool(args.json)))
    return 0


def status_command(args) -> int:
    root = Path(args.root or os.getcwd()).resolve()
    try:
        context = pw.runtime_context(worktree=root)
        result = worktree_status(context, socket_dir=args.socket_dir)
    except (ClientError, pw.ContextError, protocol.ProtocolError) as exc:
        # An unavailable broker is NOT "unregistered": fail closed and say so.
        payload = {"status": "unavailable", "error": str(exc)}
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(f"✗ protected-write authority unavailable: {exc}", file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"status:      {result['status']}")
        print(f"identity:    {result['identity_key']}")
        print(f"generation:  {result['generation'] if result['generation'] is not None else '-'}")
        for correlation in result["correlations"]:
            print(f"hold:        {correlation['hold_id']} {correlation['reason']}")
    return 0


def protected_write_command(args) -> int:
    sub = getattr(args, "protected_write_command", None)
    if sub == "preview":
        return preview_command(args)
    if sub == "status":
        return status_command(args)
    print(PREVIEW_USAGE, file=sys.stderr)
    return 1
