#!/usr/bin/env python3
"""PreToolUse guard: block tool calls that would print or dump SECRET VALUES.

    NAMES ARE FREE. VALUES ARE NOT.

An agent that needs to know which environment variables exist almost never needs
their values, but the obvious commands (`vercel env pull`, `cat .env.local`,
`printenv`) put every value into the session transcript. Transcripts persist, and
rotating a credential does NOT redact the history, so the only cheap fix is to
never read the value in the first place.

This is the outbound twin of secret-guard.py, which is a UserPromptSubmit hook and
only catches secrets a human pastes IN. This one catches secrets an agent pulls OUT.

WHAT IS BLOCKED
    vercel env pull / vercel env get           -> `vercel env ls` (names only)
    printenv, bare `env`, bare `set`/`export`, `export -p`, `declare -p`
    cat/head/tail/less/more/bat/strings/xxd/od/base64/nl/open/cp/scp/rsync on a
      dotenv file (.env, .env.local, .env.production, at any path)
    grep/rg/awk/sed/perl/cut that would PRINT a dotenv line (a variable NAME is a
      legitimate search; the matched LINE carries the value)
    git show / git log -p / git diff targeting a dotenv path (incl. HEAD:.env)
    the same printers on a non-dotenv credential file: ~/.aws/credentials, .netrc,
      .npmrc, .pgpass, ~/.ssh/id_*, ~/.config/gh/hosts.yml, *.pem, *.p12,
      service-account*.json, client_secret*.json  (a *.pub key is public, allowed)
    the evasions of all of the above: `find -exec cat`, `| xargs cat`,
      `cat < .env.local`, `python3 -c "print(open('.env.local').read())"`,
      `node -e "…readFileSync('.env.local')…"`, and a `while read` loop over a
      dotenv
    echo/printf of a secret-named variable, unless it uses the fingerprint idiom
    curl -v / --trace on a request carrying Authorization or a secret-named var
    Read / Edit / NotebookEdit whose file_path is a dotenv or credential file --
      these take no shell command, so they are matched on the path instead. Write
      is allowed: creating a dotenv sends a value OUT of the session, not in.
    supabase secrets list --reveal · gh secret|variable list --json ...,value
    security find-generic-password -w · op read · bw get password
    aws secretsmanager get-secret-value · aws ssm get-parameter --with-decryption
    gcloud secrets versions access · kubectl get secret -o yaml|json
    doppler secrets download · heroku config

WHAT IS EXPLICITLY ALLOWED (all covered by --self-test)
    vercel env ls · vercel env add (value arrives on stdin, never printed)
    grep -rn SOME_NAME lib app          (searching CODE for a variable name)
    grep -c / -l / -q on a dotenv       (count/filename/exit-status, no line)
    grep -oE '^[A-Z_]+' .env.local      (NAMES only -- the recommended read)
    cut -d= -f1 .env.local              (NAMES only)
    node --env-file=.env.local ...      (loads without printing)
    source .env / . .env                (loads without printing)
    echo 'FOO=bar' >> .env.local        (writing a dotenv is fine)
    supabase secrets list · gh secret list · kubectl get secret  (names only)
    compgen -v                          (process env NAMES only)
    printenv | cut -d= -f1              (names -- a name-only filter downstream
                                         makes an env dump safe)
    v="$THE_VAR"; echo "len=${#v} …${v: -4}"    (the fingerprint idiom)

KNOWN GAPS -- honest list, do not assume coverage
    `grep -r SOME_NAME .` recursing over a tree that happens to contain a dotenv.
      Indistinguishable from a legitimate code search, so it is LEFT OPEN on
      purpose: a guard that fires on every code search gets disabled.
    A value already in the transcript. Nothing here retracts it; rotate.
    The override itself: an agent can type it. See OVERRIDE above.

OVERRIDE -- FOR THE HUMAN
    Prefix the command with the opt-in, or export it for the session:

        CLAUDE_ALLOW_SECRET_EXPOSURE=1 vercel env pull .env.local

    The hook honors it inline (as an env prefix anywhere in the command) and from
    its own environment. It is deliberately noisy to type. NOTE: nothing stops an
    agent from typing it too -- this is a speed bump against the accidental case,
    which is every case so far, not a sandbox.

FAILS OPEN. Any internal error prints a note to stderr and exits 0. A guard that
breaks sessions gets deleted, and then it protects nothing.

SELF-TEST
    python3 hooks/secret-exposure-guard.py --self-test
    tests/run-hook-tests.sh
"""
import json
import os
import re
import shlex
import sys

OVERRIDE = "CLAUDE_ALLOW_SECRET_EXPOSURE"
OVERRIDE_INLINE = re.compile(OVERRIDE + r"\s*=\s*[\"']?1")

# ---------------------------------------------------------------- dotenv paths

# A dotenv file that holds real values. `.env.example`/`.sample`/`.template` are
# conventionally placeholder-only, so they are not secrets.
DOTENV_BASE = re.compile(r"^\.env(\.[^/]*)?$|^env\.(local|production|development|staging|test)$")
PLACEHOLDER = re.compile(r"\.(example|sample|template|dist|defaults?)$", re.IGNORECASE)


def is_dotenv(token: str) -> bool:
    """True if a token names a value-bearing dotenv file, at any path or revision."""
    candidates = [token]
    if "=" in token:
        candidates.append(token.split("=", 1)[1])   # --env-file=.env.local
    for part in list(candidates):
        if ":" in part:
            candidates.extend(part.split(":"))      # git HEAD:.env.local
    for cand in candidates:
        base = cand.strip("'\"").rstrip("/").split("/")[-1]
        if DOTENV_BASE.match(base) and not PLACEHOLDER.search(base):
            return True
    return False


def dotenv_args(args) -> bool:
    return any(is_dotenv(a) for a in args)


# Credential files that are not dotenv files. Same leak, different name.
CRED_BASENAME = re.compile(
    r"^(\.netrc|_netrc|\.npmrc|\.pgpass|\.pypirc|\.dockercfg|\.git-credentials)$"
    r"|^id_(rsa|dsa|ecdsa|ed25519)$"
    r"|^(client_secret|service[-_]account)[^/]*\.json$"
    r"|\.(pem|p12|pfx|jks|keystore)$"
)
CRED_PATH = re.compile(
    r"/\.aws/credentials$|/\.ssh/|/\.kube/config$|/\.config/gh/|/\.gnupg/|/\.docker/config\.json$"
)


def is_credential_file(token: str) -> bool:
    cand = token.strip("'\"")
    if cand.endswith(".pub"):
        return False  # public keys are public
    base = cand.rstrip("/").split("/")[-1]
    return bool(CRED_BASENAME.search(base) or CRED_PATH.search(cand))


def secret_file_args(args) -> bool:
    return any(is_dotenv(a) or is_credential_file(a) for a in args)


# A dotenv mentioned anywhere in a raw command, excluding placeholder variants.
DOTENV_MENTION = re.compile(
    r"\.env(?!\.(?:example|sample|template|dist|defaults?)\b)(?:\.[A-Za-z0-9_-]+)?"
)
# Interpreters whose inline code can read a file without ever naming a printer.
INTERPRETERS = {"python", "python3", "ruby", "node", "deno", "bun", "php", "perl"}
READ_CALL = re.compile(
    r"open\s*\(|readFile|read_text|File\.read|file_get_contents|IO\.read|Deno\.readText"
)
# `echo $SOMETHING_TOKEN`. The endorsed fingerprint idiom must not trip.
SECRETY = r"TOKEN|SECRET|KEY|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|OAUTH|BEARER|APIKEY|REFRESH"
ECHO_SECRET = re.compile(r"\$\{?[A-Za-z_]*(?:" + SECRETY + r")[A-Za-z0-9_]*", re.IGNORECASE)
FINGERPRINT = re.compile(r"\$\{#|:\s*-[0-9]|\bfingerprint\b")


# ------------------------------------------------------------- shell splitting

ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
WRAPPERS = {
    "sudo", "command", "builtin", "exec", "nohup", "time", "eval", "nice",
    "stdbuf", "caffeinate", "then", "do", "else", "elif", "if", "while",
    "until", "!", "{", "}", "[[", "test",
}
SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "bash-5.2"}
RUNNERS = {"npx", "pnpm", "yarn", "bunx", "bun", "pnpx"}
SEP_CHARS = set("();|&<>")


def tokenize(text: str):
    """Tokens with quotes resolved and shell operators kept as their own tokens."""
    try:
        lex = shlex.shlex(text, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        return list(lex)
    except ValueError:
        # Unbalanced quotes: fall back to a crude split rather than giving up.
        return [t for t in re.split(r"\s+", re.sub(r"[\"']", " ", text)) if t]


def segments(command: str):
    """Split a compound command into individual simple commands (arg lists)."""
    text = command.replace("`", " ; ")            # backtick substitution
    text = re.sub(r"\\\r?\n", " ", text)          # line continuations
    text = text.replace("\n", " ; ").replace("\r", " ; ")
    out, cur = [], []
    for tok in tokenize(text):
        if tok and all(c in SEP_CHARS for c in tok):
            # `<` feeds a file INTO the current command (`cat < .env.local`), so it
            # is not a boundary. `>` writes, and writing a dotenv is allowed.
            if tok in ("<", "<<", "<<<"):
                continue
            if cur:
                out.append(cur)
            cur = []
        else:
            cur.append(tok)
    if cur:
        out.append(cur)
    return out


def normalize(args):
    """Strip env prefixes, wrappers, runners, paths; expand `bash -c "..."`.

    Returns a list of (head, args) pairs -- more than one when a nested shell
    string is unwrapped.
    """
    args = list(args)
    while args:
        head = args[0].lstrip("\\").strip("'\"")
        base = head.split("/")[-1]
        if ENV_ASSIGN.match(head):
            args.pop(0)
            continue
        if base in WRAPPERS:
            args.pop(0)
            continue
        if base == "env":
            rest = args[1:]
            # bare `env` (or only options) is a full dump; with a command it runs it
            if not [a for a in rest if not a.startswith("-") and not ENV_ASSIGN.match(a)]:
                return [("env", rest)]
            args = rest
            continue
        if base in SHELLS:
            # find the -c payload, incl. combined flags like -lc / -xec
            for i, a in enumerate(args[1:], 1):
                if re.fullmatch(r"-[A-Za-z]*c", a) and i + 1 < len(args):
                    nested = []
                    for seg in segments(args[i + 1]):
                        nested.extend(normalize(seg))
                    return nested or [(base, args[1:])]
            return [(base, args[1:])]
        if base in RUNNERS and len(args) > 1:
            args = [a for a in args[1:] if not a.startswith("-")] or args[1:]
            continue
        return [(base, args[1:])]
    return []


# -------------------------------------------------------------------- the rules

# The alternatives this guard recommends in its block messages.
NAMES_ONLY_ENV = "Names only: `compgen -v` (bash builtin, names without values)."
NAMES_ONLY_FILE = "Names only: `grep -oE '^[A-Z_]+' .env.local | sort -u`."
PRINTERS = {
    "cat", "head", "tail", "less", "more", "bat", "strings", "xxd", "od",
    "hexdump", "base64", "nl", "tac", "open", "pbcopy", "tee", "dotenv",
}
COPIERS = {"cp", "scp", "rsync", "install", "ditto"}
MATCHERS = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "awk", "sed", "perl", "jq"}
QUIET_FLAGS = {"-c", "-l", "-L", "-q", "--count", "--files-with-matches",
               "--files-without-match", "--quiet", "--silent"}

# A downstream stage that keeps only the NAME side of `NAME=value`. Any of these
# at the end of a pipeline makes an otherwise-fatal env dump safe. Keep this list in
# step with the alternatives the block messages recommend, or an agent following the
# advice gets blocked again with no legal move.
NAME_ONLY_FILTER = re.compile(
    r"cut\s+-d['\"]?=['\"]?\s*-f\s*1(\D|$)"
    r"|cut\s+-f\s*1\s+-d['\"]?="
    r"|awk\s+-F['\"]?=[^|;]*\$1"
    r"|grep\s+-[A-Za-z]*o"
    r"|sed\s+['\"]?s/=\.\*//"
)
# `grep -o` is safe only when the match cannot cross the `=`: the pattern must be
# anchored at ^ and carry no literal `=` outside a zero-width lookaround.
LOOKAROUND = re.compile(r"\(\?[=!<][^)]*\)")


def name_anchored(pattern: str) -> bool:
    body = pattern.strip("'\"")
    if not body.startswith("^"):
        return False
    return "=" not in LOOKAROUND.sub("", body)


def check(head: str, args, name_filtered: bool = False) -> str:
    """Return a one-line reason to block, or "" to allow.

    `name_filtered` is True when the whole pipeline ends in a name-only filter,
    which makes an otherwise-fatal env dump safe.
    """
    lower = [a.lower() for a in args]

    # --- Vercel: pull/get write or print every value; ls prints names
    if head == "vercel" and "env" in lower:
        if any(a in ("pull", "get") for a in lower):
            verb = "pull" if "pull" in lower else "get"
            return (f"`vercel env {verb}` exposes every production VALUE. "
                    "Use `vercel env ls` -- it lists NAMES only.")

    # --- Whole-environment dumps
    if head == "printenv":
        real = [a for a in args if not a.startswith("-")]
        if not real:
            if name_filtered:
                return ""  # `printenv | cut -d= -f1` -- names only
            return "`printenv` dumps every environment VALUE into the transcript. " + NAMES_ONLY_ENV
        if any(re.search(r"SECRET|TOKEN|KEY|PASSWORD|PASSWD|CREDENTIAL|PRIVATE|DSN|AUTH",
                         a, re.IGNORECASE) for a in real):
            return f"`printenv {real[0]}` prints a credential VALUE. " + NAMES_ONLY_ENV
    if head == "env" and not [a for a in args if not a.startswith("-")]:
        if name_filtered:
            return ""  # `env | cut -d= -f1`
        return "Bare `env` dumps every environment VALUE. " + NAMES_ONLY_ENV
    if head == "set" and not args:
        return "Bare `set` dumps every shell variable VALUE. " + NAMES_ONLY_ENV
    if head == "export" and (not args or "-p" in args):
        return "`export -p` dumps every exported VALUE. " + NAMES_ONLY_ENV
    if head in ("declare", "typeset") and any(a in ("-p", "-x") for a in args):
        return f"`{head} {args[0]}` dumps variable VALUES. " + NAMES_ONLY_ENV

    # --- Inline interpreter code that reads a secret file
    if head in INTERPRETERS:
        for a in args:
            if (DOTENV_MENTION.search(a) or is_credential_file(a)) and READ_CALL.search(a):
                return (f"`{head}` inline code reads a secret file and prints it. "
                        + NAMES_ONLY_FILE)

    # --- Reading a dotenv or other credential file
    if head in PRINTERS and secret_file_args(args):
        if dotenv_args(args):
            return f"`{head}` on a dotenv file prints live secret VALUES. " + NAMES_ONLY_FILE
        return (f"`{head}` on a credential file prints live secret VALUES. "
                "Confirm it EXISTS instead: `ls -l <path>`.")
    if head in COPIERS and secret_file_args(args[:-1] or args):
        return (f"`{head}` copies a dotenv file's live VALUES somewhere new. "
                "Copy nothing. " + NAMES_ONLY_FILE)
    if head == "cut" and dotenv_args(args):
        fields = " ".join(args)
        if not re.search(r"-f\s*1(\b|$)", fields):
            return ("`cut` on a dotenv selecting anything but field 1 prints VALUES. "
                    + NAMES_ONLY_FILE)
    if head in MATCHERS and dotenv_args(args):
        if head in ("grep", "egrep", "fgrep", "rg", "ag", "ack"):
            if any(a in QUIET_FLAGS for a in args):
                return ""  # -c/-l/-q print a count, a filename or nothing
            # `grep -oE '^[A-Z_]+' .env.local` -- the endorsed names-only read
            if any(re.fullmatch(r"-[A-Za-z]*o[A-Za-z]*", a) for a in args) and any(
                name_anchored(a) for a in args if not a.startswith("-")
            ):
                return ""
        return (f"`{head}` on a dotenv prints the whole matching LINE, which carries "
                "the value. " + NAMES_ONLY_FILE)

    # --- git history of a dotenv
    if head == "git" and args:
        sub = lower[0]
        if sub in ("show", "log", "diff", "cat-file", "stash") and dotenv_args(args):
            return (f"`git {sub}` on a dotenv path replays secret VALUES from history. "
                    + NAMES_ONLY_FILE)

    # --- Secret managers
    if head == "supabase" and "secrets" in lower and "list" in lower:
        if any(a in ("--reveal", "--show", "--show-secrets", "--plain") for a in lower):
            return ("`supabase secrets list --reveal` prints VALUES. Drop the flag -- "
                    "plain `supabase secrets list` shows names and digests.")
    if head == "stripe" and lower[:1] == ["config"] and "--list" in lower:
        return ("`stripe config --list` prints the CLI profile's API keys (VALUES). "
                "To check which account the CLI is on, use a read call such as "
                "`stripe accounts retrieve` instead.")
    if head == "gh" and len(lower) >= 2 and lower[0] in ("secret", "variable") and "list" in lower:
        blob = " ".join(lower)
        if "--json" in blob and re.search(r"--json[= ]\S*value", blob):
            return ("`gh " + lower[0] + " list --json ...,value` reads VALUES. "
                    "Request `--json name` only.")
    if head == "security":
        blob = " ".join(lower)
        if re.search(r"find-(generic|internet)-password", blob) and (
            "-w" in lower or "-g" in lower
        ):
            return ("`security find-…-password -w` prints a Keychain VALUE to the "
                    "transcript. Drop `-w` to confirm the item EXISTS.")
        if "dump-keychain" in lower and "-d" in lower:
            return "`security dump-keychain -d` prints every Keychain VALUE."
    if head == "op" and lower and (
        lower[0] == "read" or (lower[0] == "item" and "--reveal" in lower)
    ):
        return ("1Password `op read` returns the VALUE itself. Use `op item get <item> "
                "--fields label=…` only when a human asked for it.")
    if head == "bw" and lower:
        if lower[0] == "get" and lower[1:2] and lower[1] in (
            "password", "totp", "item", "notes", "username", "uri"
        ):
            return f"`bw get {lower[1]}` prints a Bitwarden VALUE into the transcript."
        if lower[0] == "list" and "items" in lower:
            return "`bw list items` returns full items including VALUES."
    if head == "aws":
        blob = " ".join(lower)
        if "secretsmanager" in lower and "get-secret-value" in lower:
            return ("`aws secretsmanager get-secret-value` returns the VALUE. "
                    "`list-secrets` gives names and ARNs.")
        if "ssm" in lower and "get-parameter" in blob and "--with-decryption" in lower:
            return ("`aws ssm get-parameter --with-decryption` returns the plaintext "
                    "VALUE. Drop the flag, or use `describe-parameters` for names.")
    if head == "gcloud" and "secrets" in lower and "versions" in lower and "access" in lower:
        return ("`gcloud secrets versions access` prints the VALUE. "
                "`gcloud secrets list` gives names.")
    if head == "kubectl" and "get" in lower and any(
        a in ("secret", "secrets") for a in lower
    ):
        blob = " ".join(lower)
        if re.search(r"(-o|--output)[= ]?(yaml|json|jsonpath)", blob):
            return ("`kubectl get secret -o yaml|json` prints base64 VALUES that are "
                    "not encryption. Drop `-o` for names only.")
    # --- Echoing a secret-named variable.
    if head in ("echo", "printf"):
        blob = " ".join(args)
        if ECHO_SECRET.search(blob) and not FINGERPRINT.search(blob):
            return ('`echo` of a secret-named variable puts the VALUE in the transcript. '
                    'Fingerprint instead: `v="$THE_VAR"; echo "len=${#v} …${v: -4}"`.')

    # --- curl -v prints request headers, Authorization included.
    if head == "curl":
        blob = " ".join(args)
        if any(a in ("-v", "--verbose", "--trace", "--trace-ascii") for a in args) and (
            re.search(r"Authorization|" + SECRETY, blob, re.IGNORECASE)
        ):
            return ("`curl -v` prints request headers, so the Authorization value lands "
                    "in the transcript. Use `curl -s -o /dev/null -w '%{http_code}'`.")

    if head == "doppler" and "secrets" in lower and (
        "download" in lower or not [a for a in lower if a not in ("secrets",) and not a.startswith("-")]
    ):
        return ("`doppler secrets` prints VALUES. Use `doppler secrets --only-names`.")
    if head == "heroku" and lower and lower[0] == "config" and not any(
        a in lower for a in ("get",)
    ) and "-s" not in lower:
        return "`heroku config` prints every VALUE. Use `heroku config --json | jq keys`."

    return ""


def decide(command: str) -> str:
    """One-line block reason for a Bash command, or "" to allow."""
    if not command or not isinstance(command, str):
        return ""
    if os.environ.get(OVERRIDE) == "1" or OVERRIDE_INLINE.search(command):
        return ""
    # `find -exec cat {}` and `… | xargs cat` never name the file in the printer's
    # own argv, so the per-segment rules cannot see it. Match on the whole command.
    if DOTENV_MENTION.search(command):
        printers = "|".join(sorted(PRINTERS | COPIERS))
        if re.search(r"-exec(?:dir)?\s+(?:" + printers + r")\b", command) or re.search(
            r"\bxargs\b(?:\s+-[^\s]+)*\s+(?:" + printers + r")\b", command
        ):
            return ("this pipes dotenv files into a printer, which dumps their VALUES. "
                    + NAMES_ONLY_FILE)
        # `while read l; do echo "$l"; done < .env.local` -- an ad-hoc loop that
        # echoes every line, value included.
        if re.search(r"\bwhile\s+read\b", command) and re.search(
            r"<\s*[^\s;|&]*" + DOTENV_MENTION.pattern, command
        ) and re.search(r"\b(echo|printf|cat)\b", command):
            return ("a read-loop over a dotenv echoes its VALUES line by line. "
                    + NAMES_ONLY_FILE)

    name_filtered = bool(NAME_ONLY_FILTER.search(command))
    for seg in segments(command):
        for head, args in normalize(seg):
            reason = check(head, args, name_filtered)
            if reason:
                return reason
    return ""


# ------------------------------------------------------ the file-path tools

# Tools that put a file's CONTENTS into the transcript from a path alone, with no
# shell command for the Bash rules to inspect. Read renders the file; Edit echoes
# the surrounding lines in old_string/new_string and cannot be used without having
# Read the file first.
#
# Write is deliberately NOT here: creating or replacing a dotenv is allowed (the
# value flows OUT of the session into the file, which is the safe direction), and
# blocking it would stop `vercel env add`-style setup work for no gain.
PATH_TOOLS = {
    "Read": "renders the file's contents into the transcript",
    "Edit": "echoes the surrounding lines and requires the file to have been Read",
    "NotebookEdit": "echoes cell contents into the transcript",
}


def decide_path(path: str, tool: str) -> str:
    """One-line block reason for a path-addressed tool call, or "" to allow."""
    if not path or not isinstance(path, str):
        return ""
    if os.environ.get(OVERRIDE) == "1":
        return ""
    what = ""
    if is_dotenv(path):
        what = "a dotenv file"
    elif is_credential_file(path):
        what = "a credential file"
    if not what:
        return ""
    how = PATH_TOOLS.get(tool, "exposes the file's contents")
    hint = (NAMES_ONLY_FILE if what == "a dotenv file"
            else "Confirm it EXISTS instead: `ls -l <path>`.")
    return (f"`{tool}` on {what} {how}, which is the same leak as `cat`. {hint}")


def decide_payload(data) -> str:
    """Route a PreToolUse payload to the command rules or the path rules."""
    ti = data.get("tool_input") or {}
    tool = str(data.get("tool_name") or "")
    command = str(ti.get("command", "") or "")
    if command:
        return decide(command)
    path = str(ti.get("file_path", "") or ti.get("notebook_path", "") or "")
    if path and (tool in PATH_TOOLS or not tool):
        return decide_path(path, tool or "Read")
    return ""


# -------------------------------------------------------------------- hook I/O

def main() -> None:
    try:
        data = json.load(sys.stdin)
    except Exception:
        sys.exit(0)
    try:
        reason = decide_payload(data)
    except Exception as exc:  # FAIL OPEN -- never break a session
        print(f"secret-exposure-guard: internal error, allowing call ({exc})",
              file=sys.stderr)
        sys.exit(0)
    if not reason:
        sys.exit(0)
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": (
                f"Secret VALUE exposure blocked. {reason} "
                f"Names are free, values are not. Human override: prefix "
                f"`{OVERRIDE}=1 ` to a Bash command, or export it for the session "
                f"(the only form the path-addressed tools can honor)."
            ),
        }
    }))
    sys.exit(0)


# ------------------------------------------------------------------- self-test

CASES = [
    # (command, should_block, label)
    # ---- BLOCK: vercel
    ("vercel env pull", True, "vercel env pull"),
    ("vercel env pull .env.local --environment=production", True, "vercel env pull + flags"),
    ("vercel env get STRIPE_SECRET_KEY", True, "vercel env get"),
    ("npx  vercel   env  pull", True, "npx-wrapped vercel env pull"),
    # ---- BLOCK: environment dumps
    ("printenv", True, "bare printenv"),
    ("printenv | rg -i key", True, "printenv piped"),
    ("printenv VERCEL_TOKEN", True, "printenv of a credential name"),
    ("env", True, "bare env"),
    ("env | grep SECRET", True, "bare env piped to grep"),
    ("set", True, "bare set"),
    ("export -p", True, "export -p"),
    ("declare -p", True, "declare -p"),
    # ---- BLOCK: dotenv readers
    ("cat .env", True, "cat .env"),
    ("cat /home/user/project/.env.local", True, "cat absolute dotenv"),
    ("head -5 .env.production", True, "head dotenv"),
    ("tail -n 20 .env.local", True, "tail dotenv"),
    ("less .env", True, "less dotenv"),
    ("more .env.local", True, "more dotenv"),
    ("bat .env.production", True, "bat dotenv"),
    ("strings .env.local", True, "strings dotenv"),
    ("xxd .env", True, "xxd dotenv"),
    ("base64 .env.local", True, "base64 dotenv"),
    ("cp .env.local /tmp/x", True, "cp dotenv out"),
    ("scp .env.production host:/tmp", True, "scp dotenv out"),
    ("rsync -a .env.local /tmp/", True, "rsync dotenv out"),
    ("open .env.local", True, "open dotenv"),
    ("cat ../worktrees/feature-x/.env.local", True, "dotenv inside a worktree"),
    # ---- BLOCK: matchers that print the line
    ("grep VERCEL_TOKEN .env.local", True, "grep a name in a dotenv"),
    ("rg STRIPE .env", True, "rg a dotenv"),
    ("awk -F= '{print $2}' .env.local", True, "awk a dotenv"),
    ("sed -n '1,5p' .env", True, "sed a dotenv"),
    ("cut -d= -f2 .env.local", True, "cut field 2 = the value"),
    # ---- BLOCK: git history
    ("git show HEAD:.env.local", True, "git show a dotenv revision"),
    ("git log -p -- .env", True, "git log -p a dotenv"),
    # ---- BLOCK: secret managers
    ("supabase secrets list --reveal", True, "supabase secrets list --reveal"),
    ("gh secret list --json name,value", True, "gh secret list --json with value"),
    ("security find-generic-password -w -s anthropic", True, "keychain -w"),
    ("op read op://Private/Stripe/credential", True, "op read"),
    ("stripe config --list", True, "stripe config --list prints keys"),
    ("stripe invoices retrieve in_123", False, "stripe API read"),
    ("bw get password vercel", True, "bw get password"),
    ("aws secretsmanager get-secret-value --secret-id prod/db", True, "aws secretsmanager"),
    ("aws ssm get-parameter --name /prod/key --with-decryption", True, "ssm with-decryption"),
    ("gcloud secrets versions access latest --secret=api-key", True, "gcloud secrets access"),
    ("kubectl get secret app -o yaml", True, "kubectl -o yaml"),
    ("kubectl get secrets -o json", True, "kubectl -o json"),
    # ---- BLOCK: the two deliberately tricky ones
    ('bash -lc "  export  -p  |  grep  TOKEN "', True,
     "TRICKY 1: nested bash -lc, combined flags, extra spaces, pipeline"),
    ('FOO=1 \\command   cat   "$HOME/project/.env.production"', True,
     "TRICKY 2: env prefix + backslash-escaped head + quoted path"),
    ("ls && printenv && echo done", True, "TRICKY 3: dump hidden mid-chain"),
    ("env cat .env.local", True, "TRICKY 4: env used as a wrapper, not a dump"),
    ("(cd /tmp; cat .env.local)", True, "TRICKY 5: subshell"),
    # ---- ALLOW
    ("vercel env ls", False, "vercel env ls (names only)"),
    ("vercel env ls production", False, "vercel env ls scoped"),
    ("vercel env add STRIPE_SECRET_KEY production", False, "vercel env add (stdin)"),
    ("grep -rn VERCEL_TOKEN lib app", False, "grep a NAME in code"),
    ("grep -rn NEXT_PUBLIC_SITE_URL lib app scripts", False, "grep a name across code dirs"),
    ("node --env-file=.env.local scripts/x.ts", False, "node --env-file loads, prints nothing"),
    ("npx tsx --env-file=.env.local scripts/y.ts", False, "tsx --env-file"),
    ("source .env.local", False, "source loads, prints nothing"),
    ("echo 'FOO=bar' >> .env.local", False, "writing to a dotenv"),
    ("cat .env.example", False, "placeholder dotenv is not a secret"),
    ("cut -d= -f1 .env.local", False, "cut field 1 = NAMES only"),
    ("grep -c VERCEL_TOKEN .env.local", False, "grep -c prints a count"),
    ("grep -l STRIPE .env.local", False, "grep -l prints a filename"),
    ("grep -q STRIPE .env.local", False, "grep -q prints nothing"),
    ("compgen -v", False, "compgen -v = env NAMES"),
    ("supabase secrets list", False, "supabase secrets list (names + digests)"),
    ("gh secret list", False, "gh secret list (names only)"),
    ("gh variable list --json name", False, "gh --json name only"),
    ("kubectl get secret app", False, "kubectl get secret (names only)"),
    ("env FOO=bar npm run build", False, "env as a wrapper with a command"),
    ("set -euo pipefail", False, "set with flags"),
    ("export FOO=bar", False, "export an assignment"),
    ("git log --oneline -5", False, "ordinary git log"),
    ("ls -la .env.local", False, "ls does not print contents"),
    ("git diff --stat", False, "git diff stat"),
    ("CLAUDE_ALLOW_SECRET_EXPOSURE=1 vercel env pull", False, "explicit human override"),
    # ---- ALLOW: the names-only idioms. If these were blocked, an agent following
    #      the block message's own advice would have no legal move.
    ("grep -oE '^[A-Z_]+' .env.local | sort -u", False,
     "COMPAT: names-only grep -oE"),
    ("grep -oE '^[A-Z_]+(?==)' .env.local", False,
     "COMPAT: names-only grep -o with a zero-width lookahead"),
    ("printenv | cut -d= -f1 | sort", False,
     "COMPAT: printenv piped to a names-only filter"),
    ("env | cut -d= -f1", False, "COMPAT: env piped to a names-only filter"),
    ("grep -c '^SLACK_BOT_TOKEN=' .env.local", False, "COMPAT: presence as 0/1"),
    # ---- and the value-side versions of those must still fail
    ("grep -o 'sk-.*' .env.local", True, "grep -o an unanchored value pattern"),
    ("grep -oE '^ANTHROPIC_API_KEY=.*' .env.local", True, "grep -o crossing the ="),
    ("printenv | cut -d= -f2", True, "printenv piped to the VALUE side"),
    # ---- BLOCK: evasions found by probing the first version of this hook
    ("find . -name .env.local -exec cat {} ;", True, "find -exec cat"),
    ('find . -name ".env*" | xargs cat', True, "xargs cat"),
    ("python3 -c \"print(open('.env.local').read())\"", True, "python inline read"),
    ("node -e \"console.log(require('fs').readFileSync('.env.local','utf8'))\"", True,
     "node inline read"),
    ("cat < .env.local", True, "stdin redirect into cat"),
    ("cat ~/.aws/credentials", True, "AWS credentials file"),
    ("cat ~/.npmrc", True, "npmrc (carries an auth token)"),
    ("cat ~/.config/gh/hosts.yml", True, "gh hosts.yml (carries an oauth token)"),
    ("cat ~/.ssh/id_ed25519", True, "private ssh key"),
    ("cat /srv/keys/service-account.json", True, "GCP service-account json"),
    ("echo $ANTHROPIC_API_KEY", True, "echo a secret-named variable"),
    ('echo "${SLACK_BOT_TOKEN}"', True, "echo a braced secret-named variable"),
    ('curl -v -H "Authorization: Bearer $TOKEN" https://api.example.com', True,
     "curl -v with an Authorization header"),
    # ---- ALLOW: the near-misses of those same rules
    ("cat ~/.ssh/id_ed25519.pub", False, "public key is public"),
    ('v="$ANTHROPIC_API_KEY"; echo "len=${#v} …${v: -4}"', False,
     "the endorsed fingerprint idiom"),
    ("echo $PATH", False, "echo a non-secret variable"),
    ("echo 'ANTHROPIC_API_KEY is unset'", False, "echo a name as prose"),
    ("curl -s -o /dev/null -w '%{http_code}' https://api.example.com", False,
     "curl without -v"),
    ('curl -v https://example.com', False, "curl -v with no auth material"),
    ("node --env-file=.env.local -e \"console.log('ok')\"", False,
     "node --env-file with inline code that reads nothing"),
    ("find . -name '.env*' -maxdepth 2", False, "find that only LISTS dotenv files"),
    ("cat package.json", False, "ordinary file"),
    ('while read l; do echo "$l"; done < .env.local', True,
     "read-loop over a dotenv"),
    ('while read l; do echo "$l"; done < names.txt', False,
     "read-loop over an ordinary file"),
]


# (tool, file_path, should_block, label) -- the path-addressed tools.
PATH_CASES = [
    ("Read", ".env.local", True, "Read a dotenv"),
    ("Read", "/home/user/project/.env.production", True,
     "Read an absolute dotenv"),
    ("Read", "../worktrees/x/.env", True, "Read a dotenv in a worktree"),
    ("Read", "/home/user/.aws/credentials", True, "Read AWS credentials"),
    ("Read", "/home/user/.ssh/id_ed25519", True, "Read a private ssh key"),
    ("Read", "/home/user/.npmrc", True, "Read npmrc"),
    ("Read", "/home/user/.config/gh/hosts.yml", True, "Read gh hosts.yml"),
    ("Edit", ".env.local", True, "Edit a dotenv (requires a prior Read)"),
    ("NotebookEdit", ".env.local", True, "NotebookEdit a dotenv"),
    # ---- allow
    ("Read", ".env.example", False, "Read a placeholder dotenv"),
    ("Read", "/home/user/.ssh/id_ed25519.pub", False, "Read a public key"),
    ("Read", "lib/redis.ts", False, "Read ordinary source"),
    ("Read", "package.json", False, "Read package.json"),
    ("Read", "docs/environment.md", False, "a path merely containing 'env'"),
    ("Write", ".env.local", False, "Write a dotenv (the safe direction)"),
    ("Read", "", False, "empty path"),
]


def self_test() -> int:
    failures = []
    for tool, path, should_block, label in PATH_CASES:
        payload = {"tool_name": tool, "tool_input": {"file_path": path}}
        blocked = bool(decide_payload(payload))
        if blocked != should_block:
            failures.append(
                f"  {'expected BLOCK, allowed' if should_block else 'expected ALLOW, blocked'}: "
                f"{label}\n      {tool}({path!r})"
            )
    for command, should_block, label in CASES:
        reason = decide(command)
        blocked = bool(reason)
        if blocked != should_block:
            failures.append(
                f"  {'expected BLOCK, allowed' if should_block else 'expected ALLOW, blocked'}: "
                f"{label}\n      $ {command}" + (f"\n      -> {reason}" if reason else "")
            )
    # end-to-end through the real stdin/stdout contract
    e2e = 0
    for command, should_block, label in (CASES[0], CASES[-2], CASES[-1]):
        import subprocess
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command}})
        proc = subprocess.run([sys.executable, __file__], input=payload,
                              capture_output=True, text=True)
        denied = '"deny"' in proc.stdout
        if denied != should_block or proc.returncode != 0:
            failures.append(f"  end-to-end mismatch: {label}\n      $ {command}")
        e2e += 1
    # end-to-end for a path tool too
    import subprocess
    for tool, path, should_block, label in (PATH_CASES[0], PATH_CASES[-2]):
        payload = json.dumps({"tool_name": tool, "tool_input": {"file_path": path}})
        proc = subprocess.run([sys.executable, __file__], input=payload,
                              capture_output=True, text=True)
        if ('"deny"' in proc.stdout) != should_block or proc.returncode != 0:
            failures.append(f"  end-to-end mismatch: {label}\n      {tool}({path!r})")
        e2e += 1
    total = len(CASES) + len(PATH_CASES) + e2e
    blocks = sum(1 for _, b, _ in CASES if b) + sum(1 for _, _, b, _ in PATH_CASES if b)
    allows = total - blocks - e2e
    if failures:
        print(f"FAIL {len(failures)}/{total}\n" + "\n".join(failures))
        return 1
    print(f"PASS {total}/{total} cases ({blocks} block, {allows} allow, {e2e} end-to-end)")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    main()
