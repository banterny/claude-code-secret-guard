# claude-code-secret-guard

A [Claude Code](https://claude.com/claude-code) `PreToolUse` hook that blocks
`git commit`/`git push` when the change contains a hardcoded secret (API key,
token, private key, etc.), detected with [gitleaks](https://github.com/gitleaks/gitleaks).

> Using [OpenCode](https://opencode.ai) instead? See the sibling port
> [opencode-secret-guard](https://github.com/banterny/opencode-secret-guard) —
> same design, `tool.execute.before` plugin.
>
> Want to stop personal data (your email address, for instance) leaking out of
> an agent into web requests as well? See
> [agent-privacy-guard](https://github.com/banterny/agent-privacy-guard), for
> Claude Code, Codex and OpenCode.

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

- `git commit` — scans the staged diff (`gitleaks git --pre-commit --staged`),
  from the top of the repo, so a commit made from a subfolder is scanned in
  full. A command that starts with `cd <folder> &&` (or `;`), or uses
  `git -C <folder>`, is scanned in that folder as well as in the session's
  own, and a finding in either blocks, so a decoy `cd` can't steer the scan
  away.
- `git commit -a` / `-i` / `-o` (or `--all`, `--include`, `--only`, also
  inside a cluster such as `-am`), or a `git add` / `git stage` earlier in
  the same command — also scans lines added by unstaged changes to tracked
  files, and untracked files that aren't git-ignored (piped into
  `gitleaks stdin`), since these fold in changes `--staged` alone can't see
  yet. Removed lines are not scanned, so a commit that deletes a leaked
  secret goes through. Git-ignored files (build output such as `.next/`)
  can't be committed and are never scanned.
- `git push` — scans every commit on HEAD, a local branch or a tag that no
  remote has yet, so `git push origin <other branch>`, `--all`, `--tags`
  and a push from a detached HEAD are covered as well as the current
  branch. On a first push, with no
  remote-tracking branches, that is the whole history.

It also refuses to let the scan be switched off from inside the repo or
the command. The git-level hooks below do the same.

- A `gitleaks:allow` note on a line does not exempt it
  (`--ignore-gitleaks-allow`).
- The `GITLEAKS_CONFIG` and `GITLEAKS_CONFIG_TOML` environment variables
  are ignored.
- gitleaks reads `.gitleaks.toml` and `.gitleaksignore` from the folder it
  scans and skips what they say. Copies committed exactly as they are are
  trusted, but never a link (git doesn't track what it points to). A
  commit or push is refused while either file is new, edited, uncommitted
  or a link, and a commit that changes either is refused too: you
  check the change and commit it yourself (with `git commit --no-verify`
  when the git-level hooks are installed).

Trigger matching is deliberately loose (word "git" + word "commit"/"push"
anywhere in the command, regardless of flag order or position). A false
trigger just costs one extra fast gitleaks scan before allowing; a missed
trigger would let a real secret slip into history. Over-matching is the safe
direction here, so that's the one this hook takes.

## Install

Requires [`gitleaks`](https://github.com/gitleaks/gitleaks) 8.19.0 or later
(for its `git` and `stdin` commands) and `jq` on `PATH`:

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

## Git-level hooks (any agent, or you)

`git-hooks/pre-commit` and `git-hooks/pre-push` are the same check done by
git itself instead of by the agent's harness. Git runs them for every
commit and push, whoever issued the command — Claude Code, OpenCode, Codex,
a GUI client, or you at a terminal — so they cover what an agent-specific
hook can't.

They also see the commit as it really is, because git runs them at the
moment of the commit, from the root of the working tree, after any
`git add` has happened:

- `pre-commit` scans exactly what is about to be committed
  (`gitleaks git --pre-commit --staged`), including for `commit -a` and
  `commit <path>`, for a file staged by a `git add` chained ahead of the
  commit, and for a commit made from a subfolder. It looks at added lines
  only, so a commit that removes a leaked secret goes through.
- `pre-push` scans every commit being pushed, using the list of refs git
  gives it — on a brand-new branch, all of its unpushed commits, not just
  the tip.

Install them for every repo on the machine by copying the folder somewhere
durable and pointing git's global `core.hooksPath` at it:

```sh
mkdir -p ~/.agents/hooks/git-hooks
cp git-hooks/pre-commit git-hooks/pre-push ~/.agents/hooks/git-hooks/
chmod +x ~/.agents/hooks/git-hooks/pre-commit ~/.agents/hooks/git-hooks/pre-push
git config --global core.hooksPath ~/.agents/hooks/git-hooks
```

Use them alongside the Claude Code hook, not instead of it: the Claude Code
hook stops the command before it runs and is not skipped by `--no-verify`;
the git hooks catch everything else.

Things to know:

- **`core.hooksPath` replaces each repo's own `.git/hooks` folder.** These
  two hooks hand on to the repo's own `pre-commit` / `pre-push` if it has
  them, but a repo's other hooks (`commit-msg`, `post-checkout`, …) stop
  running unless you add them to the global folder too.
- **A repo that sets its own `core.hooksPath` switches these off for that
  repo.** [husky](https://typicode.github.io/husky/) does this. Call the
  hooks from that repo's own hook scripts if you need both.
- **`git commit --no-verify` / `git push --no-verify` skip them**, as with
  any git hook.
- **Merges and rebases don't run `pre-commit`.** The `pre-push` scan is
  what covers commits made that way.
- **Fails open, with a warning.** If `gitleaks` isn't on `PATH` the commit
  or push goes ahead, and the hook says on stderr that it was not scanned.

## Test

```sh
./test-secret-commit-guard.sh
./test-git-hooks.sh
```

`test-secret-commit-guard.sh` builds a real scratch git repo and exercises
the Claude Code hook against it — trigger
matching, staged/unstaged/untracked/committed secrets, a secret in a
git-ignored build folder (must not block), a repo with no commits yet,
pushes of other branches, a non-git working directory, commits run from a
subfolder or after `cd`, chained `git add`, and each way of switching the
scan off (allow notes, settings files, environment variables).

`test-git-hooks.sh` runs real `git commit` and `git push` commands, against
scratch repos and a scratch bare remote, with the git-level hooks wired in.

No network access, nothing touches your real repos or your git
configuration (both scripts tell git to ignore your global config, so an
installed copy of the git-level hooks doesn't interfere with their
fixtures). Both make their scratch repos in `/tmp` and stop at once if
they can't, so inside a sandbox that blocks `/tmp` (such as Claude Code's)
run them outside it.

## Limitations

These are limits of the Claude Code hook. The git-level hooks above don't
share the last two (reading the command, unpushed branches).

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
- **Settings files already committed are trusted.** A `.gitleaks.toml` or
  `.gitleaksignore` committed before this hook was installed (or committed
  by you with `--no-verify`) is used as it is. Read a repo's copies before
  relying on the scan there.
- **Reading the command is approximate.** The hook starts from the
  `PreToolUse` payload's `cwd` and follows a leading `cd <folder>` and a
  `git -C <folder>`. A folder reached any other way, a commit through a git
  alias, or `git commit <path>` with no flag (which commits that file's
  unstaged changes) is not seen as it really is. The git-level hooks run
  inside git itself and cover these.
- **A secret on any unpushed branch blocks every push.** The push scan
  covers every local commit that no remote has, so a secret left on one
  unpushed branch also blocks pushing a different, clean one. Remove the
  secret from that branch (or delete the branch) first.
- **The push scan trusts git's local record of what each remote holds**
  (`refs/remotes/…`). A command that rewrites that record could hide
  commits from it; the git-level `pre-push` hook relies on the same record.

Tested on macOS with gitleaks 8.30.1, using POSIX `sh` and extended-regex
(`grep -E`) throughout; not yet verified on Linux.

## License

MIT — see [LICENSE](LICENSE).
