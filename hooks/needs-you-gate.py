#!/usr/bin/env python3
"""
needs-you-gate -- Stop hook: make the agent re-check before it hands work back to you.

Agents are quick to end a turn with a "Needs you" list: approvals for things that were
already decided, steps for you to click through that the agent never walked itself,
and chores it could have done on its own. Reminders in memory files do not stop it.
This gate does.

When the reply that just ended hands work to the human (a "Needs you" list, an
approval ask, numbered click-through steps), the hook blocks the stop ONCE and asks
the agent to re-check each item:

  1. Already decided?  Search your decisions file (and memory) for it.
  2. Can the agent do it itself?  A script, an API, a browser it can drive.
  3. Steps?  Only if the agent walked that exact screen itself this session.

The agent then either does the work and drops the item, or ends its turn again with
the same reply. The second stop (`stop_hook_active: true`) always passes, so this can
never loop.

CONFIGURATION (all optional)
    Environment variables win over the config file; the config file wins over defaults.

    NEEDS_YOU_GATE_USER        Who the agent is handing work to.   default: "the user"
    NEEDS_YOU_GATE_DECISIONS   Path to your standing-decisions file.
                               default: "DECISIONS.md"
    NEEDS_YOU_GATE_CONFIG      Path to a JSON config file.
                               default: ~/.claude/needs-you-gate.json

    Config file keys: "user", "decisions_path", "extra_triggers" (a list of regexes,
    case-insensitive, matched against the final reply text).

FAILS OPEN. Bad input, a missing transcript or a broken config file all allow the stop.

SELF-TEST
    python3 hooks/needs-you-gate.py --self-test
"""
import json
import os
import re
import sys

DEFAULTS = {"user": "the user", "decisions_path": "DECISIONS.md", "extra_triggers": []}

TRIGGERS = [
    re.compile(r"(^|\n)\s*(\*\*|#+\s*)?Needs you\b", re.I),
    re.compile(r"\bI recommend (yes|no)\b", re.I),
    re.compile(r"\b(type|say) [\"“]", re.I),
    re.compile(
        r"(^|\n)\s*\d+\.\s+(\*\*)?(Open|Go to|Click|Sign (back )?in|Sign out|Select|Choose|"
        r"Tap|Paste|Invite|Enter)\b",
        re.I,
    ),
]


def load_config() -> dict:
    cfg = dict(DEFAULTS)
    path = os.environ.get("NEEDS_YOU_GATE_CONFIG") or os.path.expanduser(
        "~/.claude/needs-you-gate.json"
    )
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            for key in DEFAULTS:
                if key in data:
                    cfg[key] = data[key]
    except Exception:
        pass  # no file, or a broken one: defaults
    if os.environ.get("NEEDS_YOU_GATE_USER"):
        cfg["user"] = os.environ["NEEDS_YOU_GATE_USER"]
    if os.environ.get("NEEDS_YOU_GATE_DECISIONS"):
        cfg["decisions_path"] = os.environ["NEEDS_YOU_GATE_DECISIONS"]
    return cfg


def triggers(cfg: dict):
    out = list(TRIGGERS)
    for pat in cfg.get("extra_triggers") or []:
        try:
            out.append(re.compile(str(pat), re.I))
        except re.error:
            continue
    return out


def reason(cfg: dict) -> str:
    who = cfg["user"]
    decisions = cfg["decisions_path"]
    return (
        f"needs-you gate: your reply hands work to {who}. Before it stands, check EACH item:\n"
        f"1. Already decided? Search {decisions} and memory. If decided, do it, don't ask.\n"
        "2. Can you do it yourself? A script, an API, a CLI, a browser you can drive. "
        "Only passwords, one-time codes, payment entry and genuine judgment calls "
        f"belong to {who}.\n"
        "3. Steps to follow? Only if you walked that exact screen yourself this session. "
        "If not, walk it first.\n"
        f"Then do every item that fails these checks, and rewrite the reply with only what "
        f"truly needs {who}. If every item already passes, end your turn again with the "
        "same reply."
    )


def last_turn_text(path: str) -> str:
    """Fallback for older Claude Code versions without `last_assistant_message`."""
    texts = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                t = e.get("type")
                msg = e.get("message") or {}
                content = msg.get("content")
                if t == "user":
                    # a real user prompt (not a tool_result) starts a new turn
                    if isinstance(content, str) or (
                        isinstance(content, list)
                        and any(isinstance(c, dict) and c.get("type") == "text" for c in content)
                        and not any(
                            isinstance(c, dict) and c.get("type") == "tool_result"
                            for c in content
                        )
                    ):
                        texts = []
                elif t == "assistant" and isinstance(content, list):
                    for c in content:
                        if isinstance(c, dict) and c.get("type") == "text":
                            texts.append(c.get("text", ""))
    except Exception:
        return ""
    # only the final text message is what the human reads as the reply
    return texts[-1] if texts else ""


def decide(data: dict, cfg: dict) -> str:
    """The block reason, or "" to let the stop through."""
    if not isinstance(data, dict) or data.get("stop_hook_active"):
        return ""
    text = data.get("last_assistant_message")
    if not isinstance(text, str) or not text:
        text = last_turn_text(str(data.get("transcript_path") or ""))
    if not text:
        return ""
    if any(p.search(text) for p in triggers(cfg)):
        return reason(cfg)
    return ""


def main() -> int:
    try:
        data = json.load(sys.stdin)
    except Exception:
        return 0
    try:
        why = decide(data, load_config())
    except Exception as exc:  # FAIL OPEN
        print(f"needs-you-gate: internal error, allowing stop ({exc})", file=sys.stderr)
        return 0
    if why:
        print(json.dumps({"decision": "block", "reason": why}))
    return 0


# ------------------------------------------------------------------- self-test

CASES = [
    # (last_assistant_message, stop_hook_active, should_block, label)
    ("Done. Tests pass.\n\n**Needs you**\n1. Approve the merge", False, True, "Needs you list"),
    ("## Needs you\n- rotate the key", False, True, "Needs you heading"),
    ("Should we ship? I recommend yes.", False, True, "approval ask"),
    ("1. Open the dashboard\n2. Click Settings", False, True, "click-through steps"),
    ('Reply and type "go" when ready.', False, True, "type-this ask"),
    ("**Needs you**\n1. Approve", True, False, "second stop always passes"),
    ("Merged the PR and verified the deploy.", False, False, "plain report"),
    ("1. Fixed the parser\n2. Added tests", False, False, "numbered list of work done"),
    ("", False, False, "empty reply"),
]


def self_test() -> int:
    import subprocess
    import tempfile

    failures = []
    cfg = dict(DEFAULTS)
    for text, active, should_block, label in CASES:
        got = bool(decide({"last_assistant_message": text, "stop_hook_active": active}, cfg))
        if got != should_block:
            failures.append(f"  {'expected BLOCK' if should_block else 'expected ALLOW'}: {label}")

    # transcript fallback: only the FINAL text of the LAST turn counts
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        rows = [
            {"type": "user", "message": {"content": "first prompt"}},
            {"type": "assistant", "message": {"content": [{"type": "text", "text": "**Needs you**\n1. x"}]}},
            {"type": "user", "message": {"content": "second prompt"}},
            {"type": "assistant", "message": {"content": [{"type": "text", "text": "All done."}]}},
        ]
        f.write("\n".join(json.dumps(r) for r in rows))
        transcript = f.name
    if decide({"transcript_path": transcript}, cfg):
        failures.append("  transcript fallback read an EARLIER turn")
    os.unlink(transcript)

    # configuration: user name and decisions path reach the message
    custom = dict(DEFAULTS, user="Sam", decisions_path="docs/decisions.md")
    msg = decide({"last_assistant_message": "**Needs you**\n1. x"}, custom)
    if "Sam" not in msg or "docs/decisions.md" not in msg:
        failures.append("  config values missing from the block reason")
    extra = dict(DEFAULTS, extra_triggers=[r"\bover to you\b"])
    if not decide({"last_assistant_message": "That part is over to you."}, extra):
        failures.append("  extra_triggers not honored")

    # end-to-end through stdin/stdout, with env-var config
    env = dict(os.environ, NEEDS_YOU_GATE_USER="Sam", NEEDS_YOU_GATE_CONFIG="/nonexistent.json")
    proc = subprocess.run(
        [sys.executable, __file__],
        input=json.dumps({"last_assistant_message": "**Needs you**\n1. x"}),
        capture_output=True, text=True, env=env,
    )
    if proc.returncode != 0 or '"block"' not in proc.stdout or "Sam" not in proc.stdout:
        failures.append("  end-to-end block via stdin failed")

    total = len(CASES) + 4
    if failures:
        print(f"FAIL {len(failures)}/{total}\n" + "\n".join(failures))
        return 1
    print(f"PASS {total}/{total} cases")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    sys.exit(main())
