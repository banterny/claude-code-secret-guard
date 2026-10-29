#!/usr/bin/env bash
# Test harness for the git-level hooks in git-hooks/ (pre-commit, pre-push).
# Builds real scratch repos plus a scratch bare "remote" and runs real
# `git commit` / `git push` commands with the hooks wired in, so git's own
# hook plumbing (temporary index for `commit -a`, pre-push stdin) gets
# exercised, not just the gitleaks commands. No network access, nothing
# touches your real repos or your git configuration.
set -u
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
HOOKS="$SCRIPT_DIR/git-hooks"
pass=0
fail=0

# Hermetic: ignore the user's and the system's git config, so an installed
# copy of these hooks (core.hooksPath) cannot interfere with the fixtures.
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1

# Generated at runtime, not a literal, so this file itself never contains a
# real token-shaped string (it would trip gitleaks/GitHub push protection).
TOK="ghp_$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 36)"

# Stop if the scratch folder can't be made: carrying on would run the
# fixtures in whatever folder this script was started from.
BASE=$(mktemp -d /tmp/git-hooks-test.XXXXXX) || exit 1
OUT="$BASE/out.txt"

# git with the hooks under test. Plain `git` (no hooks) is for fixtures.
g() { git -c core.hooksPath="$HOOKS" "$@"; }

newrepo() { # $1 = name; leaves cwd in the new repo
  mkdir "$BASE/$1" && cd "$BASE/$1" || exit 1
  git init -q -b main
  git config user.email test@test.com
  git config user.name test
  echo "hello" > README.md
  git add README.md
  git commit -qm init
}

check() { # $1 = expected: block|allow, $2 = description, $3... = command
  local expected="$1" desc="$2" rc verdict
  shift 2
  "$@" >"$OUT" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then verdict="allow"; else verdict="block"; fi
  if [ "$verdict" = "$expected" ]; then
    pass=$((pass+1))
  else
    fail=$((fail+1))
    echo "FAIL expected=$expected got=$verdict : $desc"
    sed 's/^/    /' "$OUT" | head -12
  fi
}

expect() { # $1 = description, $2... = test command that must succeed
  local desc="$1"
  shift
  if "$@"; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL $desc"; fi
}

head_is() { [ "$(git rev-parse HEAD)" = "$1" ]; }
output_has() { grep -q -- "$1" "$OUT"; }

for h in pre-commit pre-push; do
  expect "git-hooks/$h exists and is executable" test -x "$HOOKS/$h"
done

# ======================= pre-commit =======================
newrepo commits
echo "build/" > .gitignore
mkdir sub other
echo "x" > sub/a.txt
echo "y" > other/b.txt
git add .gitignore sub other
git commit -qm "layout"

# ---- clean staged change -> commit goes through ----
echo "clean content" > clean1.txt
git add clean1.txt
before=$(git rev-parse HEAD)
check allow "clean staged change" g commit -qm "clean"
expect "clean commit was actually made" test "$(git rev-parse HEAD)" != "$before"

# ---- secret staged -> blocked, no commit made, file named in the report ----
echo "TOKEN=$TOK" > secret1.txt
git add secret1.txt
before=$(git rev-parse HEAD)
check block "secret staged" g commit -qm "add token"
expect "no commit was made when blocked" head_is "$before"
expect "report names the file" output_has "secret1.txt"
expect "report does not print the secret" test "$(grep -c -- "$TOK" "$OUT")" = "0"
git reset -q -- secret1.txt
rm -f secret1.txt

# ---- commit -a: secret in an UNSTAGED tracked-file modification -> blocked ----
# (git gives the hook a temporary index holding what -a will commit)
echo "TOKEN=$TOK" >> README.md
check block "commit -am, secret unstaged in a tracked file" g commit -qam "update readme"
git checkout -q -- README.md

# ---- commit <path>: unstaged secret committed by naming the file -> blocked ----
echo "TOKEN=$TOK" >> README.md
check block "commit <path>, secret unstaged in that file" g commit -qm "update readme" README.md
git checkout -q -- README.md

# ---- brand-new file, staged just before the commit -> blocked ----
# (the agent-level guards fire before a chained `git add` has run; git's
# own hook fires after it)
echo "TOKEN=$TOK" > new-secret.txt
git add -A
check block "new file staged by an earlier git add" g commit -qm "add new file"
git reset -q -- new-secret.txt
rm -f new-secret.txt

# ---- commit run from a subfolder, secret staged elsewhere -> blocked ----
echo "TOKEN=$TOK" > other/s.txt
git add other/s.txt
check block "run from sub/, secret staged in other/" g -C sub commit -qm "from subfolder"
git reset -q -- other/s.txt
rm -f other/s.txt

# ---- secret only in a git-ignored folder -> commit goes through ----
mkdir build
echo "TOKEN=$TOK" > build/generated.js
echo "clean content 2" > clean2.txt
git add clean2.txt
check allow "secret only in git-ignored folder" g commit -qm "clean 2"

# ---- commit that only REMOVES a secret already in history -> goes through ----
echo "TOKEN=$TOK" > old-secret.txt
git add old-secret.txt
git commit -qm "fixture: a secret committed before the hook existed"
echo "nothing to see" > old-secret.txt
check allow "commit -am that removes a secret" g commit -qam "remove token"

# ---- the repo's own .git/hooks/pre-commit still runs (after the scan) ----
printf '#!/bin/sh\ntouch "%s/local-pre-commit-ran"\n' "$BASE" > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
echo "clean content 3" > clean3.txt
git add clean3.txt
check allow "clean change, repo has its own pre-commit hook" g commit -qm "clean 3"
expect "repo's own pre-commit hook was run" test -e "$BASE/local-pre-commit-ran"

printf '#!/bin/sh\necho "local hook says no" >&2\nexit 1\n' > .git/hooks/pre-commit
echo "clean content 4" > clean4.txt
git add clean4.txt
check block "repo's own pre-commit hook refuses" g commit -qm "clean 4"
expect "repo's own refusal is passed on" output_has "local hook says no"
rm -f .git/hooks/pre-commit
git reset -q -- clean4.txt
rm -f clean4.txt

# ---- gitleaks not on PATH -> commit allowed, with a visible warning ----
gl_dir=$(dirname "$(command -v gitleaks)")
if [ "$(dirname "$(command -v git)")" != "$gl_dir" ]; then
  no_gl_path=$(printf '%s' "$PATH" | tr ':' '\n' | grep -v -x -- "$gl_dir" | paste -sd: -)
  echo "TOKEN=$TOK" > secret2.txt
  git add secret2.txt
  check allow "gitleaks missing: fails open" env PATH="$no_gl_path" git -c core.hooksPath="$HOOKS" commit -qm "unscanned"
  expect "gitleaks missing: warning is shown" output_has "NOT scanned"
else
  echo "note: git and gitleaks share a folder; skipping the gitleaks-missing test"
fi

# ======================= pre-push =======================
git init -q --bare "$BASE/remote.git"
newrepo pushes
git remote add origin "$BASE/remote.git"
remote_ref() { git -C "$BASE/remote.git" rev-parse --verify -q "refs/heads/$1"; }

# ---- first push of a clean branch -> goes through ----
check allow "first push, clean history" g push -q origin main
expect "clean push reached the remote" test "$(remote_ref main)" = "$(git rev-parse main)"

# ---- clean new commit -> goes through ----
echo "clean" > p1.txt
git add p1.txt
git commit -qm "clean push commit"
check allow "push a clean new commit" g push -q origin main

# ---- secret in a commit being pushed -> blocked, remote untouched ----
git checkout -q -b leaky
echo "TOKEN=$TOK" > leak.txt
git add leak.txt
git commit -qm "fixture: leak commit"
remote_main=$(remote_ref main)
check block "push a commit containing a secret (new branch)" g push -q origin leaky
expect "blocked push did not reach the remote" test -z "$(remote_ref leaky)"
expect "report names the file" output_has "leak.txt"

# ---- new branch whose secret is NOT in the tip commit -> still blocked ----
echo "removed" > leak.txt
git commit -qam "fixture: remove the leak again"
check block "new branch, secret in an earlier commit, clean tip" g push -q origin leaky
expect "blocked push did not reach the remote" test -z "$(remote_ref leaky)"

# ---- same commits pushed onto an existing branch -> blocked ----
check block "push leak commits onto an existing remote branch" g push -q origin leaky:main
expect "remote branch unchanged" test "$(remote_ref main)" = "$remote_main"

# ---- a clean new branch is unaffected by the leaky one -> goes through ----
git checkout -q main
git checkout -q -b tidy
echo "clean" > p2.txt
git add p2.txt
git commit -qm "clean branch commit"
check allow "push a clean new branch" g push -q origin tidy

# ---- deleting a remote branch pushes no commits -> goes through ----
check allow "delete a remote branch" g push -q origin :tidy
expect "remote branch was deleted" test -z "$(remote_ref tidy)"

# ---- the repo's own .git/hooks/pre-push still runs and gets git's input ----
printf '#!/bin/sh\ncat > "%s/local-pre-push-stdin"\necho "$1" > "%s/local-pre-push-arg"\n' "$BASE" "$BASE" > .git/hooks/pre-push
chmod +x .git/hooks/pre-push
check allow "clean push, repo has its own pre-push hook" g push -q origin tidy
expect "repo's own pre-push hook got the list of refs" grep -q "refs/heads/tidy" "$BASE/local-pre-push-stdin"
expect "repo's own pre-push hook got the remote name" grep -q -x "origin" "$BASE/local-pre-push-arg"
rm -f .git/hooks/pre-push

# ==== gaps found in review (Oct 2026) ====
printf '[allowlist]\npaths = [".*"]\n' > "$BASE/allow-all.toml"
newrepo settings

# ---- a gitleaks:allow note on the line does not exempt it ----
echo "TOKEN=$TOK # gitleaks:allow" > s.txt
git add s.txt
check block "secret marked gitleaks:allow" g commit -qm "x"
git reset -q -- s.txt

# ---- GITLEAKS_CONFIG set by the command is ignored ----
echo "TOKEN=$TOK" > s.txt
git add s.txt
check block "GITLEAKS_CONFIG pointing at an allow-all config" env GITLEAKS_CONFIG="$BASE/allow-all.toml" git -c core.hooksPath="$HOOKS" commit -qm "x"

# ---- settings files that are not committed exactly as they are ----
cp "$BASE/allow-all.toml" .gitleaks.toml
check block "untracked allow-all .gitleaks.toml" g commit -qm "x"
expect "report names the settings file" output_has ".gitleaks.toml"
rm .gitleaks.toml
echo "s.txt:github-pat:1" > .gitleaksignore
check block "untracked .gitleaksignore" g commit -qm "x"
rm .gitleaksignore
git reset -q -- s.txt

# ---- a commit that changes them is refused; the user's route is --no-verify ----
printf '[extend]\nuseDefault = true\n[allowlist]\npaths = ["fixtures/"]\n' > .gitleaks.toml
git add .gitleaks.toml
check block "commit that adds .gitleaks.toml" g commit -qm "settings"
check allow "same commit with --no-verify" g commit -q --no-verify -m "settings"
mkdir fixtures
echo "TOKEN=$TOK" > fixtures/sample.txt
git add fixtures
check allow "committed settings are trusted" g commit -qm "fixture"
git add s.txt
check block "committed settings skip only what they say" g commit -qm "x"
cp "$BASE/allow-all.toml" .gitleaks.toml
check block "committed .gitleaks.toml edited to allow everything" g commit -qm "x"
git checkout -q -- .gitleaks.toml
git reset -q -- s.txt
rm -f s.txt

# ---- pre-push: the same three ways round the scan ----
git init -q --bare "$BASE/remote2.git"
newrepo pushes2
git remote add origin "$BASE/remote2.git"
git checkout -q -b marked
echo "TOKEN=$TOK # gitleaks:allow" > s.txt
git add s.txt
git commit -qm "fixture: leak marked gitleaks:allow"
check block "push of a commit whose secret is marked gitleaks:allow" g push -q origin marked
check block "push with GITLEAKS_CONFIG pointing at an allow-all config" env GITLEAKS_CONFIG="$BASE/allow-all.toml" git -c core.hooksPath="$HOOKS" push -q origin marked
git checkout -q main
git checkout -q -b clean2
echo "clean" > c.txt
git add c.txt
git commit -qm "clean commit"
cp "$BASE/allow-all.toml" .gitleaks.toml
check block "push with an untracked allow-all .gitleaks.toml" g push -q origin clean2
rm .gitleaks.toml
check allow "same push once the settings file is gone" g push -q origin clean2

# ---- a settings file that is a link to a file outside the repo ----
newrepo linked-settings
printf '[extend]\nuseDefault = true\n' > "$BASE/outside.toml"
ln -s "$BASE/outside.toml" .gitleaks.toml
git add .gitleaks.toml
git commit -qm "fixture: settings as a link"
cp "$BASE/allow-all.toml" "$BASE/outside.toml"
echo "TOKEN=$TOK" > s.txt
git add s.txt
check block "commit with .gitleaks.toml linked to an allow-all file" g commit -qm "x"

echo ""
echo "passed: $pass, failed: $fail"
cd / && rm -rf "$BASE"
[ "$fail" -eq 0 ] || exit 1
