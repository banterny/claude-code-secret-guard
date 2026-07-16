# claude-code-secret-guard

A [Claude Code](https://claude.com/claude-code) `PreToolUse` hook that blocks
`git commit`/`git push` when the change contains a hardcoded secret (API key,
token, private key, etc.), detected with [gitleaks](https://github.com/gitleaks/gitleaks).

## Why this instead of a general secret/security-guard tool

Tools that scan *every* Bash call for risky content are appealing but pay
their cost in the wrong place: the check that matters most — scanning a diff
for secrets before it enters git history — only applies to the rare
`git commit`/`git push` invocation, yet a scan-everything hook runs its full
pipeline on every `ls`, `cat`, and `npm install` too.

This hook does one thing: it matches on the command *before* deciding whether
to scan anything, so non-git Bash calls cost ~20-30ms (a jq parse and a word
check, no gitleaks fork), and the gitleaks scan only runs on an actual
commit/push.

## What it catches

- `git commit` — scans the staged diff (`gitleaks protect --staged`).
- `git commit -a` / `-am` / `--all` — scans the full working-tree diff
  instead, since those flags fold in unstaged tracked changes that
  `--staged` alone can't see yet.
- `git push` — scans commits not yet on the upstream branch (falling back to
  `origin/HEAD`, or the tip commit alone if neither is available).

Trigger matching is deliberately loose (word "git" + word "commit"/"push"
anywhere in the command, regardless of flag order or position). A false
trigger just costs one extra fast gitleaks scan before allowing; a missed
trigger would let a real secret slip into history. Over-matching is the safe
direction here, so that's the one this hook takes.

## Install

Requires [`gitleaks`](https://github.com/gitleaks/gitleaks) and `jq` on `PATH`:

```sh
brew install gitleaks jq   # macOS; see gitleaks releases for other platforms
```

Copy `deny-secret-commit.sh` somewhere durable and make it executable, then
wire it into your Claude Code settings (`~/.claude/settings.json` for a
user-wide hook, or `.claude/settings.json`/`.claude/settings.local.json` for
a project-scoped one) as a `Bash`-matched `PreToolUse` hook:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "\"/path/to/deny-secret-commit.sh\"" }
        ]
      }
    ]
  }
}
```

Restart the session (or start a new one) for the hook to take effect.

## Test

```sh
./test-secret-commit-guard.sh
```

Builds a real scratch git repo and exercises the hook against it — trigger
matching, staged/unstaged/committed secrets, push-range fallbacks, and a
non-git working directory. No network access, nothing touches your real
repos.

## Limitations

- **Fails open, silently.** If `gitleaks`, `jq`, or `git` aren't on `PATH`,
  the hook exits 0 (allow) with no warning. This is the right failure
  direction — a broken dependency shouldn't block every commit — but it
  means "installed" isn't a permanent guarantee. Don't assume protection is
  active without checking `gitleaks version` works.
- **Format-based detection, not exhaustive.** gitleaks matches known secret
  *shapes* (AWS keys, GitHub tokens, private key headers, high-entropy
  strings, etc.). A bare `password = "..."` or an unrecognized vendor format
  can slip through its default ruleset. Treat this as raising the floor, not
  a guarantee.
- **First push of a brand-new branch scans only the tip commit.** With no
  upstream and no resolvable `origin/HEAD`, there's no reference point to
  diff against, so the hook falls back to scanning just the most recent
  commit. A secret buried in an earlier, non-tip commit on that first push
  won't be caught at push time — commit-time scanning is the primary
  control; push-time scanning is a backstop for history the hook didn't see
  committed (e.g. commits made outside Claude Code, or before this hook was
  installed).
- **cwd, not `-C`.** The hook reads the working directory from the
  `PreToolUse` payload's `cwd` field, which is reliable for ordinary
  invocations. A command that explicitly targets another directory via
  `git -C /other/path commit` will still be scanned against the hook's own
  `cwd`, not `/other/path`.

Tested on macOS with gitleaks 8.30.1, using POSIX `sh` and extended-regex
(`grep -E`) throughout; not yet verified on Linux.

## License

MIT — see [LICENSE](LICENSE).
