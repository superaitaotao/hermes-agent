"""``hermes approvals`` subcommand parser."""

from __future__ import annotations

import argparse
from typing import Callable

from hermes_cli.subcommands._shared import add_json_flag


def build_approvals_parser(subparsers, *, cmd_approvals: Callable) -> None:
    """Attach the ``approvals`` subcommand to ``subparsers``."""
    approvals_parser = subparsers.add_parser(
        "approvals", help="Approval-prompt tools (mine history into allowlist proposals)",
        description="Tools for the dangerous-command approval system. "
            "`hermes approvals suggest` mines past approval decisions from "
            "the session database and proposes command_allowlist entries so "
            "repeatedly-approved commands stop prompting.")
    approvals_subparsers = approvals_parser.add_subparsers(
        dest="approvals_command", metavar="<subcommand>")

    suggest_parser = approvals_subparsers.add_parser(
        "suggest", help="Propose command_allowlist entries from past approvals",
        description="Scan the session database for dangerous-classified commands "
            "that ran with user approval, rank the recurring patterns, and "
            "print a numbered allowlist proposal. Nothing is written unless "
            "--apply is given. Destructive classes (recursive delete, sudo, "
            "disk writes, credential edits, ...) are never proposed.")
    suggest_parser.add_argument(
        "--apply", dest="apply_indices", metavar="N[,M...]",
        help="Merge the numbered proposals (from a prior run) into "
        "command_allowlist in config.yaml")
    add_json_flag(suggest_parser, "Emit machine-readable JSON instead of human-readable text")
    suggest_parser.add_argument(
        "--days", type=int, default=90,
        help="How far back to scan session history (default: 90; 0 = all)")
    suggest_parser.add_argument(
        "--min-count", dest="min_count", type=int, default=2,
        help="Minimum approval count for a pattern to be proposed (default: 2)")
    suggest_parser.add_argument(
        "--limit", type=int, default=20, help="Maximum number of proposals to show (default: 20)")
    suggest_parser.add_argument(
        "--db", help="Path to an alternate session database (default: ~/.hermes/state.db)")
    suggest_parser.set_defaults(func=cmd_approvals)

    test_parser = approvals_subparsers.add_parser(
        "test", help="Dry-run the approval verdict for a command (never executes it)",
        description="Evaluate a command against the REAL runtime approval guards — "
            "hardline blocklist, user approvals.deny rules, dangerous-pattern "
            "detection, allowlist, yolo/off bypass — and print the verdict, "
            "the matching rule, and the normalized-command trace, without "
            "executing the command, prompting anyone, or persisting anything. "
            "Exit codes: 0 allow, 2 ask-approval, 3 deny (hardline or user "
            "deny rule). Tip: use `--` before the command so its own flags "
            "aren't parsed: hermes approvals test -- rm -rf ./build")
    test_parser.add_argument(
        "--env-type", dest="env_type", default="local",
        help="Terminal backend type to evaluate against (default: local; "
        "isolated container backends like docker skip the guards)")
    add_json_flag(test_parser, "Emit machine-readable JSON instead of human-readable text")
    test_parser.add_argument(
        "command_words",
        nargs=argparse.REMAINDER,
        metavar="command",
        # NOTE: dest must NOT be "command" — main.py's startup path reads
        # args.command as the top-level subcommand name ("approvals").
        help="The command to evaluate (prefix with -- to protect its flags)")
    test_parser.set_defaults(func=cmd_approvals)

    approvals_parser.set_defaults(func=cmd_approvals)

    protected_parser = approvals_subparsers.add_parser(
        "protected-write",
        help="Preview and inspect protected-write consent (never issues a grant)",
        description="Preview one file-tool operation deterministically and read the "
            "local authority status. This surface cannot register a run, issue a "
            "grant, extend an expiry or bypass confirmation: registration and "
            "issuance are separate root admin actions outside the agent session.")
    protected_subparsers = protected_parser.add_subparsers(
        dest="protected_write_command", metavar="<subcommand>")

    preview_parser = protected_subparsers.add_parser(
        "preview",
        help="Compute the exact diff, hashes and descriptor digest for a request",
        description="Read a bounded JSON request, deterministically prepare the "
            "before/after image of every path, and print the FULL untrusted diff "
            "plus the descriptor digest a human must confirm. Nothing is written "
            "and no grant is created.")
    preview_parser.add_argument(
        "--request", required=True,
        help="Request file, or '-' for stdin: {\"tool\": ..., \"arguments\": {...}}")
    preview_parser.add_argument(
        "--root", help="Worktree to resolve paths against (default: current directory)")
    add_json_flag(preview_parser, "Emit machine-readable JSON instead of human-readable text")
    preview_parser.set_defaults(func=cmd_approvals)

    status_parser = protected_subparsers.add_parser(
        "status",
        help="Read-only local authority status for this worktree",
        description="Ask the local broker for the read-only status of this worktree "
            "(unregistered / registered / held). An unreachable broker is reported "
            "as unavailable and never as unregistered.")
    status_parser.add_argument(
        "--root", help="Worktree to resolve the identity against (default: current directory)")
    status_parser.add_argument(
        "--socket-dir", dest="socket_dir", default="/run/hermes-protected-writes",
        help="Broker socket directory (default: /run/hermes-protected-writes)")
    add_json_flag(status_parser, "Emit machine-readable JSON instead of human-readable text")
    status_parser.set_defaults(func=cmd_approvals)

    protected_parser.set_defaults(func=cmd_approvals)
