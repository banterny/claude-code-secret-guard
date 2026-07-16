#!/usr/bin/env sh
# Blocks `git commit`/`git push` when the change being committed or pushed
# contains a hardcoded secret (API key, token, private key, etc.), detected
# via gitleaks. Wired as its own PreToolUse hook, matched only on Bash.
#
# Deliberately loose trigger match (word "git" + word "commit"/"push"
# anywhere in the command, regardless of flag order/position): a false
# trigger just costs one extra fast gitleaks scan before allowing, but a
# missed trigger would let a real secret slip into git history. This keeps
# the expensive scan off every other Bash call (ls, cat, npm, etc.) while
# never under-matching an actual commit/push.
#
# Block: exit 2 + reason on stderr (Claude Code PreToolUse contract).
# Allow: exit 0, silent (including when jq/gitleaks/git are unavailable,
# the command isn't a git commit/push, or there's nothing to scan).

command -v jq >/dev/null 2>&1 || exit 0
command -v gitleaks >/dev/null 2>&1 || exit 0
command -v git >/dev/null 2>&1 || exit 0

INPUT=$(cat)
TOOL=$(printf '%s' "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null)
[ "$TOOL" = "Bash" ] || exit 0

cmd=$(printf '%s' "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)
[ -n "$cmd" ] || exit 0

# The hook process's own inherited cwd is not reliable (session/tool
# plumbing can launch it from elsewhere); the PreToolUse payload carries
# the session's actual working directory explicitly, so use that.
hook_cwd=$(printf '%s' "$INPUT" | jq -r '.cwd // empty' 2>/dev/null)
[ -n "$hook_cwd" ] && cd "$hook_cwd" 2>/dev/null

has_word() {
  printf '%s\n' "$cmd" | grep -qE "(^|[^a-zA-Z0-9_])$1([^a-zA-Z0-9_]|\$)"
}

is_commit=0
is_push=0
has_word git && has_word commit && is_commit=1
has_word git && has_word push && is_push=1

[ "$is_commit" = "1" ] || [ "$is_push" = "1" ] || exit 0

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || exit 0

if [ "$is_commit" = "1" ]; then
  # `-a`/`--all` (bare or combined into a short-flag cluster like `-am`)
  # folds unstaged tracked changes into the commit, which `--staged` alone
  # would miss (the diff isn't in the index yet when this hook fires) —
  # this check is loose the same way the git/commit/push checks above are:
  # matching `-a` anywhere in the command can over-trigger the fuller scan
  # on an unrelated flag elsewhere in a chained command, but that only
  # costs scanning a wider (still-correct) diff, never a missed secret.
  is_all=0
  printf '%s\n' "$cmd" | grep -qE '(^|[[:space:]])(--all|-[a-zA-Z]*a[a-zA-Z]*)([[:space:]]|$)' && is_all=1
  if [ "$is_all" = "1" ]; then
    report=$(git diff HEAD 2>/dev/null | gitleaks detect --no-git --pipe --no-banner --redact --no-color 2>&1)
  else
    report=$(gitleaks protect --staged --no-banner --redact --no-color 2>&1)
  fi
  rc=$?
  if [ "$rc" = "1" ]; then
    echo "Blocked by the secret-commit guard (deny-secret-commit.sh): changes being committed appear to contain a secret (gitleaks detected a match). Do not retry or work around this; unstage/revert the file, rotate the credential, and explain the block to the user. Details:" >&2
    printf '%s\n' "$report" >&2
    exit 2
  fi
fi

if [ "$is_push" = "1" ]; then
  # Note: `git rev-parse` can print a best-effort guess to stdout even when
  # it exits non-zero (e.g. an unresolvable `origin/HEAD` echoes back
  # literally), so branch on the command's own exit status via `&&`, not on
  # whether the captured string is non-empty.
  if upstream=$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null) && [ -n "$upstream" ]; then
    range="${upstream}..HEAD"
  elif origin_head=$(git rev-parse --abbrev-ref origin/HEAD 2>/dev/null) && [ -n "$origin_head" ]; then
    range="${origin_head}..HEAD"
  else
    range="-1"
  fi
  report=$(gitleaks detect --no-banner --redact --no-color --log-opts="$range" 2>&1)
  rc=$?
  if [ "$rc" = "1" ]; then
    echo "Blocked by the secret-commit guard (deny-secret-commit.sh): commit(s) about to be pushed appear to contain a secret (gitleaks detected a match). Do not retry or work around this; rotate the credential and explain the block to the user. Details:" >&2
    printf '%s\n' "$report" >&2
    exit 2
  fi
fi

exit 0
