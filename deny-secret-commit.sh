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

# gitleaks also takes its settings from these environment variables, which
# would let them replace the rules this scan relies on.
unset GITLEAKS_CONFIG GITLEAKS_CONFIG_TOML
GITLEAKS_FLAGS="--no-banner --redact --no-color --ignore-gitleaks-allow"

# Which repos the command may act on: the session's folder, plus the folder
# of a leading `cd <dir> &&` (or `;`) and of a `git -C <dir>`, each relative
# to where it applies. A folder may be quoted. All of them are scanned, and
# any finding blocks, so a decoy `cd` cannot steer the scan away from the
# repo the commit really lands in. Anything cleverer than that is left to
# the git-level hooks.
Q="'"
DIR_RE="(\"([^\"]*)\"|${Q}([^${Q}]*)${Q}|([^[:space:];&|\"${Q}]+))"
expand_home() {
  case "$1" in
    "~") printf '%s' "$HOME" ;;
    "~/"*) printf '%s/%s' "$HOME" "${1#\~/}" ;;
    *) printf '%s' "$1" ;;
  esac
}
resolve_dir() { # $1 = base folder, $2 = folder as written; prints the full path
  (cd "$1" 2>/dev/null && cd "$(expand_home "$2")" 2>/dev/null && pwd)
}
start=$(pwd)
candidates=$start
c_base=$start
cd_dir=$(printf '%s\n' "$cmd" | sed -nE "1s/^[[:space:]]*cd[[:space:]]+${DIR_RE}[[:space:]]*(&&|;).*/\\2\\3\\4/p")
if [ -n "$cd_dir" ] && d=$(resolve_dir "$start" "$cd_dir"); then
  candidates="$candidates
$d"
  c_base=$d
fi
c_dir=$(printf '%s\n' "$cmd" | grep -oE "(^|[^a-zA-Z0-9_])git[[:space:]]+-C[[:space:]]+${DIR_RE}" | head -n 1 |
  sed -E "s/.*git[[:space:]]+-C[[:space:]]+${DIR_RE}.*/\\2\\3\\4/")
if [ -n "$c_dir" ] && d=$(resolve_dir "$c_base" "$c_dir"); then
  candidates="$candidates
$d"
fi
# The top of each work tree among them. Scans run from there: from a
# subfolder, gitleaks only looks at that subfolder's changes, and reads its
# settings files from there.
tops=$(printf '%s\n' "$candidates" | while IFS= read -r d; do
  (cd "$d" 2>/dev/null && git rev-parse --show-toplevel 2>/dev/null)
done | sort -u)
[ -n "$tops" ] || exit 0

# gitleaks reads .gitleaks.toml and .gitleaksignore from the folder it scans
# and skips whatever they tell it to, so anyone who can edit them can switch
# the scan off. Only copies exactly as committed are trusted, and never a
# link, whose target git does not track; this prints any others.
is_settled() { # $1 = file; tracked, unchanged since the last commit, not a link
  [ ! -L "$1" ] && [ -e "$1" ] &&
    git ls-files --error-unmatch -- "$1" >/dev/null 2>&1 &&
    git diff --quiet HEAD -- "$1" >/dev/null 2>&1
}
# The `path` in a settings file's [extend] table, if any. An inline
# `extend = { ... }` table is reported as "/", which is never trusted.
extend_path() {
  awk -v q="'" -v dq='"' '
    /^[[:space:]]*[[]/ { s = $0; gsub(/[[:space:]]/, "", s); next }
    /^[[:space:]]*extend[[:space:]]*=/ { print "/"; exit }
    s == "[extend]" && /^[[:space:]]*path[[:space:]]*=/ {
      v = $0; sub(/^[^=]*=[[:space:]]*/, "", v); sub(/[[:space:]]*(#.*)?$/, "", v)
      gsub("^[" dq q "]+|[" dq q "]+$", "", v); print v; exit
    }' "$1" 2>/dev/null
}
unsettled_settings() {
  for f in .gitleaks.toml .gitleaksignore; do
    { [ -e "$f" ] || [ -L "$f" ]; } || continue
    is_settled "$f" || printf '%s\n' "$f"
  done
  # A trusted .gitleaks.toml can still pull in another file through
  # `[extend] path`. That file must be inside the repo, trusted the same
  # way, and must not extend anything further.
  if [ -f .gitleaks.toml ]; then
    p=$(extend_path .gitleaks.toml)
    case "$p" in
      "") ;;
      /*|"~"*|*..*) printf '%s\n' .gitleaks.toml ;;
      *) { is_settled "$p" && [ -z "$(extend_path "$p")" ]; } || printf '%s\n' .gitleaks.toml ;;
    esac
  fi
}
# Settings files whose staged copy differs from the last commit.
staged_settings() {
  if git rev-parse -q --verify HEAD >/dev/null 2>&1; then
    git diff --cached --name-only HEAD -- .gitleaks.toml .gitleaksignore 2>/dev/null
  else
    git ls-files --cached -- .gitleaks.toml .gitleaksignore 2>/dev/null
  fi
}
settings_block() { # $1 = the files
  echo "Blocked by the secret-commit guard ($0): gitleaks's settings file(s) $(printf '%s' "$1" | tr '\n' ' ')in $(pwd) are new, changed or a link, pull in a file that is, or this commit changes them. gitleaks reads these files to decide what to skip, so a change to them can switch the secret scan off. Do not edit, delete or work around them; explain the block to the user, who can check the change and commit it themselves." >&2
  exit 2
}

scan_repo() { # $1 = top of a work tree; exits 2 to block
  cd "$1" || return 0

  if [ "$is_commit" = "1" ]; then
    bad=$({ unsettled_settings; staged_settings; } | sort -u)
    [ -n "$bad" ] && settings_block "$bad"

    # Changes that are not staged yet but could still end up in this
    # commit: `-a`/`--all`, `-i`/`--include` and `-o`/`--only` (bare or
    # inside a short-flag cluster like `-am`), or a `git add`/`git stage`
    # earlier in the same command, which has not run yet when this hook
    # fires. Matched loosely: an unrelated flag elsewhere in a chained
    # command only costs scanning a wider (still-correct) diff, never a
    # missed secret.
    is_wide=0
    printf '%s\n' "$cmd" | grep -qE '(^|[[:space:]])(--all|--include|--only|-[a-zA-Z]*[aio][a-zA-Z]*)([[:space:]]|$)' && is_wide=1
    printf '%s\n' "$cmd" | grep -qE '(^|[^a-zA-Z0-9_])git([[:space:]]+-[^[:space:]]+([[:space:]]+[^-[:space:]][^[:space:]]*)?)*[[:space:]]+(add|stage)([[:space:]]|$)' && is_wide=1
    # The staged scan always runs, so the wider scan can only add coverage.
    report=$(gitleaks git --pre-commit --staged $GITLEAKS_FLAGS 2>&1)
    rc=$?
    if [ "$rc" != "1" ] && [ "$is_wide" = "1" ]; then
      # Wider scan: lines added by unstaged changes to tracked files (`git
      # diff`, which unlike `git diff HEAD` also works before the first
      # commit; added lines only, so a commit that removes a secret is not
      # refused), plus untracked files that are not git-ignored. Piped into
      # `gitleaks stdin` so only that text is scanned: `detect --no-git
      # --pipe` ignores the pipe and scans the whole folder, git-ignored
      # build output included.
      report=$({
        git diff --no-ext-diff --no-color -U0 | sed -n 's/^+//p'
        git ls-files --others --exclude-standard -z -- ':/' | xargs -0 cat --
      } 2>/dev/null | gitleaks stdin $GITLEAKS_FLAGS 2>&1)
      rc=$?
    fi
    if [ "$rc" = "1" ]; then
      echo "Blocked by the secret-commit guard ($0): changes being committed in $(pwd) appear to contain a secret (gitleaks detected a match). Do not retry or work around this; unstage/revert the file, rotate the credential, and explain the block to the user. Details:" >&2
      printf '%s\n' "$report" >&2
      exit 2
    fi
  fi

  if [ "$is_push" = "1" ]; then
    bad=$(unsettled_settings | sort -u)
    [ -n "$bad" ] && settings_block "$bad"

    # Every commit on HEAD (even when it is not on a branch), a local branch
    # or a tag that no remote has yet. Reading the command for which
    # branches it pushes (`git push origin feature`, `--all`, `--tags`) is
    # easy to get wrong, so this covers them all; the cost is that a secret
    # on an unpushed branch also blocks pushing another. With no
    # remote-tracking branches at all, that is the whole history, which is
    # what a first push publishes. HEAD is left out when it has no commit
    # yet (a new, empty branch): git would refuse the whole list, and the
    # scan would find nothing.
    revs="--branches --tags"
    git rev-parse -q --verify HEAD >/dev/null 2>&1 && revs="HEAD $revs"
    report=$(gitleaks git $GITLEAKS_FLAGS --log-opts="$revs --not --remotes" 2>&1)
    rc=$?
    if [ "$rc" = "1" ]; then
      echo "Blocked by the secret-commit guard ($0): commit(s) in $(pwd) that are not on any remote yet appear to contain a secret (gitleaks detected a match). Do not retry or work around this; rotate the credential and explain the block to the user. Details:" >&2
      printf '%s\n' "$report" >&2
      exit 2
    fi
  fi
}

set -f
old_ifs=$IFS
IFS='
'
for top in $tops; do
  IFS=$old_ifs
  scan_repo "$top"
  IFS='
'
done

exit 0
