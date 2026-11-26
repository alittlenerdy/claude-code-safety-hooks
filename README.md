# claude-code-safety-hooks

Stop your AI agent from reading secret values out of `.env`, `vercel env pull`, `printenv` and 30+ workarounds. **Names are free, values are not.**

Three small, dependency-free Python hooks for [Claude Code](https://code.claude.com/docs/en/hooks):

| Hook | Event | What it does |
|---|---|---|
| `secret-exposure-guard.py` | `PreToolUse` | Blocks Bash commands and file reads that would put a secret **value** into the transcript, and tells the agent the names-only alternative. |
| `secret-guard.py` | `UserPromptSubmit` | Blocks a prompt that contains a pasted credential (the classic case: an editor line selection from `.env`). |
| `needs-you-gate.py` | `Stop` | When the agent ends a turn by handing work back to you ("Needs you", approval asks, click-through steps), makes it re-check once whether it could do the work itself. |

## Why

An agent that needs to know which environment variables exist almost never needs their values. But the obvious commands (`vercel env pull`, `cat .env.local`, `printenv`) dump every value into the session transcript. Transcripts persist, and rotating a credential does not scrub history. The cheap fix is to never read the value at all.

Telling the agent "be careful with `.env` files" does not hold up. It works around the instruction with `grep`, `python -c "open(...)"`, `find -exec cat` or a `while read` loop. These hooks enforce the rule at the tool-call boundary, and every block message hands the agent a safe command, so it can keep working.

## Install

Requires Python 3.9+ on your `PATH` as `python3`. No packages.

```bash
git clone https://github.com/alittlenerdy/claude-code-safety-hooks.git
mkdir -p ~/.claude/hooks
cp claude-code-safety-hooks/hooks/*.py ~/.claude/hooks/
```

Then merge this into `~/.claude/settings.json` (global) or `.claude/settings.json` (one project). The same block is in [`examples/settings.json`](examples/settings.json). Use only the hooks you want.

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [ { "type": "command", "command": "python3 \"$HOME/.claude/hooks/secret-guard.py\"", "timeout": 10 } ] }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash|Read|Edit|NotebookEdit",
        "hooks": [ { "type": "command", "command": "python3 \"$HOME/.claude/hooks/secret-exposure-guard.py\"", "timeout": 10 } ]
      }
    ],
    "Stop": [
      { "hooks": [ { "type": "command", "command": "python3 \"$HOME/.claude/hooks/needs-you-gate.py\"", "timeout": 10 } ] }
    ]
  }
}
```

Notes, checked against the [hooks reference](https://code.claude.com/docs/en/hooks):

- The `PreToolUse` matcher must list `Read`, `Edit` and `NotebookEdit` as well as `Bash`. Those tools take a file path rather than a shell command, so they leak a dotenv just as `cat` does.
- `Stop` and `UserPromptSubmit` do not take a matcher.
- Run `/hooks` inside Claude Code to confirm they loaded.

Verify the install:

```bash
HOOKS_DIR=~/.claude/hooks claude-code-safety-hooks/tests/run-hook-tests.sh
```

## What `secret-exposure-guard` blocks

- `vercel env pull` and `vercel env get` (use `vercel env ls`)
- Whole-environment dumps: `printenv`, bare `env`, bare `set`, `export -p`, `declare -p`
- Printers on a dotenv (`.env`, `.env.local`, `.env.production` at any path): `cat`, `head`, `tail`, `less`, `more`, `bat`, `strings`, `xxd`, `od`, `base64`, `nl`, `open`, `tee`, `pbcopy`
- Copiers on a dotenv: `cp`, `scp`, `rsync`, `install`, `ditto`
- Matchers that print the matching line, which carries the value: `grep`, `rg`, `awk`, `sed`, `perl`, `jq`, and `cut` on any field but 1
- `git show`, `git log -p` and `git diff` on a dotenv path, including `HEAD:.env`
- The same readers on other credential files: `~/.aws/credentials`, `.netrc`, `.npmrc`, `.pgpass`, `.pypirc`, `.git-credentials`, `~/.ssh/id_*`, `~/.config/gh/hosts.yml`, `~/.kube/config`, `*.pem`, `*.p12`, `service-account*.json`, `client_secret*.json` (`*.pub` keys are allowed)
- Evasions: `find -exec cat`, `| xargs cat`, `cat < .env.local`, `python3 -c "print(open('.env.local').read())"`, `node -e "...readFileSync('.env.local')..."`, a `while read` loop over a dotenv, `bash -lc "..."` wrappers, env-var prefixes, backslash-escaped commands, subshells and chains
- `echo` or `printf` of a secret-named variable (`$API_KEY`, `${SLACK_BOT_TOKEN}`)
- `curl -v` or `--trace` on a request that carries an Authorization header
- Secret managers: `supabase secrets list --reveal`, `gh secret list --json ...,value`, `security find-generic-password -w`, `op read`, `bw get password`, `aws secretsmanager get-secret-value`, `aws ssm get-parameter --with-decryption`, `gcloud secrets versions access`, `kubectl get secret -o yaml|json`, `doppler secrets`, `heroku config`, `stripe config --list`
- The `Read`, `Edit` and `NotebookEdit` tools on a dotenv or credential file. `Write` is allowed, because creating a dotenv sends a value out of the session, not in.

**Explicitly allowed** (covered by the self-test, so agents always have a legal move):

```bash
vercel env ls                              # names only
grep -oE '^[A-Z_]+' .env.local | sort -u   # names only
grep -c '^STRIPE_SECRET_KEY=' .env.local   # is it set? 0 or 1
cut -d= -f1 .env.local                     # names only
printenv | cut -d= -f1                     # names only
compgen -v                                 # shell variable names
node --env-file=.env.local script.js       # loads without printing
source .env.local                          # loads without printing
v="$API_KEY"; echo "len=${#v} ...${v: -4}" # fingerprint, not value
grep -rn API_KEY src/                      # searching code for a name
```

**Known gaps, on purpose:** `grep -r SOME_NAME .` across a tree that happens to contain a dotenv looks exactly like a legitimate code search. A guard that fires on every code search gets switched off, so this one stays open. And nothing here can retract a value that has already reached a transcript. If that happens, rotate it.

## Override

The human can bypass `secret-exposure-guard` deliberately:

```bash
CLAUDE_ALLOW_SECRET_EXPOSURE=1 vercel env pull .env.local
```

The hook honors the variable inline, as a prefix anywhere in the command, or exported in the environment Claude Code runs in. The exported form is the only one the path-addressed tools (`Read`, `Edit`) can see. Nothing stops an agent from typing the prefix itself. This is a speed bump against accidents, which covers almost every real leak, not a sandbox.

## Configuring `needs-you-gate`

It works with no configuration. To personalize it:

| Env var | Default | Meaning |
|---|---|---|
| `NEEDS_YOU_GATE_USER` | `the user` | Who the agent is handing work to |
| `NEEDS_YOU_GATE_DECISIONS` | `DECISIONS.md` | Your standing-decisions file, which the agent is told to search first |
| `NEEDS_YOU_GATE_CONFIG` | `~/.claude/needs-you-gate.json` | Optional JSON config file |

Config file:

```json
{ "user": "Sam", "decisions_path": "docs/DECISIONS.md", "extra_triggers": ["\\bover to you\\b"] }
```

Environment variables override the file. The gate blocks at most once per turn: the second stop (`stop_hook_active: true`) always goes through, so it cannot loop.

## Design rules

- **Fail open.** Malformed input, an internal error or a missing file allows the call. A guard that breaks sessions gets deleted.
- **Never echo the secret.** Block messages name the pattern, never the value. `secret-guard` shows at most a three-character masked preview.
- **Every block names a safe alternative**, and the self-test covers each alternative, so the guard cannot block its own advice.

## Tests

```bash
tests/run-hook-tests.sh
```

This runs every hook's `--self-test`, then checks that each hook fails open on malformed stdin. CI runs the same script on Linux and macOS with Python 3.9, 3.12 and 3.13.

## License

MIT. See [LICENSE](LICENSE).

---

Built by [Playground Giants](https://playgroundgiants.com) · [@j1mmyhackett](https://x.com/j1mmyhackett)
