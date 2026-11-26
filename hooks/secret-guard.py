#!/usr/bin/env python3
"""
secret-guard -- UserPromptSubmit hook: stop a pasted credential before it is sent.

WHY THIS EXISTS
    The most common way a secret reaches an agent transcript is not the agent
    reading it. It is the human selecting a line in an `.env` file in the editor,
    and the editor integration forwarding that selection with the prompt.
    Transcripts persist, and rotating a credential does NOT redact the history.

WHAT IT CAN AND CANNOT DO
    A UserPromptSubmit hook cannot REWRITE a prompt. It can only BLOCK. So this
    refuses the submission and says what matched, which is the difference between
    a secret that reached the API and one that did not.

FALSE POSITIVES ARE THE REAL RISK
    A guard that cries wolf gets disabled, and then it protects nothing. Every
    pattern below is deliberately narrow, and the bare-token rule requires the
    token to be ALONE on its line (which is exactly what an editor line selection
    produces) AND to mix upper, lower and digits. That last condition excludes
    git SHAs and UUIDs (lowercase hex), short ids, and hostnames (they carry dots).

NEVER ECHO THE SECRET. The reason string names the pattern and gives a masked
preview only. Hook output can itself land in the transcript.

SELF-TEST
    python3 hooks/secret-guard.py --self-test
"""
import json
import re
import sys

# Vendor-prefixed credentials. High confidence: these prefixes are not
# ambiguous, and a match is a secret essentially every time.
PREFIXED = [
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI-style API key", re.compile(r"\bsk-[A-Za-z0-9]{32,}")),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}")),
    ("GitHub fine-grained PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}")),
    ("Slack token", re.compile(r"\bxox[baprse]-[A-Za-z0-9\-]{10,}")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    # Google refresh tokens start `1//0`. The slash MUST be in the pattern --
    # a redaction regex that omits it misses this entire class.
    ("Google OAuth refresh token", re.compile(r"\b1//0[A-Za-z0-9_\-]{20,}")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.")),
    ("Stripe live key", re.compile(r"\b(?:sk|rk|pk)_live_[A-Za-z0-9]{20,}")),
    ("Stripe webhook secret", re.compile(r"\bwhsec_[A-Za-z0-9]{20,}")),
    ("Resend API key", re.compile(r"\bre_[A-Za-z0-9]{20,}")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]

# `SOMETHING_SECRET=<value>` on one line. Only fires when the NAME itself reads
# as credential-ish, so `PUBLIC_SITE_URL=https://...` is untouched.
ENV_ASSIGNMENT = re.compile(
    r"^\s*(?P<name>[A-Z][A-Z0-9_]*"
    r"(?:SECRET|TOKEN|KEY|PASSWORD|PASSWD|PASS|APIKEY|AUTH|CREDENTIAL|PRIVATE|DSN)"
    r"[A-Z0-9_]*)\s*=\s*[\"']?(?P<value>[A-Za-z0-9+/_\-\.=]{16,})[\"']?\s*$",
    re.MULTILINE,
)

# A bare high-entropy token alone on its line: the editor-line-selection shape.
# Needs upper AND lower AND digit to fire.
BARE_TOKEN = re.compile(r"^[A-Za-z0-9+/_\-]{20,100}$")
UUID_SHAPE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-", re.I)


def mask(value: str) -> str:
    """Enough to identify which credential; never enough to use it."""
    return f"{value[:3]}…{len(value)} chars"


def looks_random(token: str) -> bool:
    return (
        any(c.isupper() for c in token)
        and any(c.islower() for c in token)
        and any(c.isdigit() for c in token)
    )


def findings(prompt: str):
    hits = []
    for label, pattern in PREFIXED:
        m = pattern.search(prompt)
        if m:
            hits.append((label, mask(m.group(0))))

    for m in ENV_ASSIGNMENT.finditer(prompt):
        hits.append((f"env assignment `{m.group('name')}`", mask(m.group("value"))))

    for raw in prompt.splitlines():
        token = raw.strip()
        if (
            BARE_TOKEN.fullmatch(token)
            and looks_random(token)
            and not UUID_SHAPE.match(token)
            and "-" not in token[:9]  # not a slug/branch name
        ):
            hits.append(("bare high-entropy token on its own line", mask(token)))
            break

    # De-duplicate while preserving order.
    seen, out = set(), []
    for label, preview in hits:
        if label not in seen:
            seen.add(label)
            out.append((label, preview))
    return out


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0  # Never break the session over a parse failure.

    prompt = payload.get("prompt") or ""
    if not isinstance(prompt, str) or not prompt:
        return 0

    hits = findings(prompt)
    if not hits:
        return 0

    lines = [f"  · {label} ({preview})" for label, preview in hits]
    reason = (
        "BLOCKED before sending: this prompt looks like it contains a live credential.\n\n"
        + "\n".join(lines)
        + "\n\nTranscripts persist for about 30 days and rotating a secret does NOT "
        "redact the history, so the cheapest fix is to not send it at all.\n\n"
        "If it was an editor line selection from a .env file, deselect and resend. "
        "If the agent genuinely needs this credential, put it in your password manager "
        "or an environment variable and tell it the NAME, rather than pasting it.\n\n"
        "If this is a false positive, resend with the value broken up or described "
        "rather than quoted."
    )

    json.dump(
        {
            "decision": "block",
            "reason": reason,
            "systemMessage": f"secret-guard blocked this prompt ({len(hits)} match). Nothing was sent.",
        },
        sys.stdout,
    )
    return 0



# ------------------------------------------------------------------- self-test
# Test credentials are ASSEMBLED at runtime from harmless pieces, so this file
# never contains a string that a secret scanner (or this hook) would flag.

def _fake(prefix: str, body: str, n: int) -> str:
    return prefix + (body * n)


def _cases():
    tok = "Ab3" * 8  # mixed case + digits, 24 chars
    return [
        # (prompt, should_block, label)
        (_fake("sk-" + "ant-", "A1b2", 10), True, "Anthropic-style key"),
        (_fake("gh" + "p_", "A1b2", 10), True, "GitHub token"),
        (_fake("xo" + "xb-", "1234567890ab", 2), True, "Slack token"),
        (_fake("AK" + "IA", "ABCD2345", 2), True, "AWS access key id"),
        ("-----BEGIN RSA " + "PRIVATE KEY-----", True, "private key block"),
        ("STRIPE_SECRET_KEY=" + tok, True, "credential-named env assignment"),
        ("look at this:\n" + tok + "\nthanks", True, "bare token alone on a line"),
        ("PUBLIC_SITE_URL=https://example.com/some/long/path", False, "non-secret env line"),
        ("commit 3f9a2c1e8b7d6a5f4e3d2c1b0a9f8e7d6c5b4a39", False, "git SHA in prose"),
        ("550e8400-e29b-41d4-a716-446655440000", False, "UUID alone on a line"),
        ("feature-branch-name-that-is-long", False, "slug alone on a line"),
        ("please rotate STRIPE_SECRET_KEY tomorrow", False, "a variable NAME in prose"),
        ("", False, "empty prompt"),
    ]


def self_test() -> int:
    import subprocess
    failures = []
    cases = _cases()
    for prompt, should_block, label in cases:
        blocked = bool(findings(prompt))
        if blocked != should_block:
            failures.append(f"  {'expected BLOCK, allowed' if should_block else 'expected ALLOW, blocked'}: {label}")
    e2e = 0
    for prompt, should_block, label in (cases[0], cases[7]):
        proc = subprocess.run([sys.executable, __file__], input=json.dumps({"prompt": prompt}),
                              capture_output=True, text=True)
        if ('"block"' in proc.stdout) != should_block or proc.returncode != 0:
            failures.append(f"  end-to-end mismatch: {label}")
        if prompt and prompt in proc.stdout:
            failures.append(f"  hook output ECHOED the secret: {label}")
        e2e += 1
    total = len(cases) + e2e
    if failures:
        print(f"FAIL {len(failures)}/{total}\n" + "\n".join(failures))
        return 1
    print(f"PASS {total}/{total} cases")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    sys.exit(main())
