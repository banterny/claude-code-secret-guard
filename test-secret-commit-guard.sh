#!/usr/bin/env bash
# Test harness for deny-secret-commit.sh. Builds a real scratch git repo so
# the trigger-matching AND the actual gitleaks scan get exercised, not just
# the regex.
set -u
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
GUARD="$SCRIPT_DIR/deny-secret-commit.sh"
pass=0
fail=0

# Hermetic: ignore the user's and the system's git config, so the fixture
# commits below are not refused by a globally installed git hook (such as
# git-hooks/pre-commit from this repo, via core.hooksPath).
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1

# Generated at runtime, not a literal, so this file itself never contains a
# real token-shaped string (it would trip gitleaks/GitHub push protection).
TOK="ghp_$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 36)"

# Each scratch folder must be made, or the script stops: carrying on would
# run the fixtures (commits, file overwrites) in whatever folder it was
# started from, such as this repo.
REPO=$(mktemp -d /tmp/secret-guard-test.XXXXXX) || exit 1
cd "$REPO" || exit 1
git init -q
git config user.email test@test.com
git config user.name test
echo "hello" > README.md
git add README.md
git commit -qm init >/dev/null

check() { # $1 = expected: block|allow, $2 = command string, $3 = cwd (default $REPO)
  local expected="$1" cmd="$2" dir="${3:-$REPO}" rc verdict
  jq -cn --arg c "$cmd" --arg d "$dir" '{tool_name:"Bash", tool_input:{command:$c}, cwd:$d}' | "$GUARD" >/tmp/guard-out.$$ 2>&1
  rc=$?
  if [ "$rc" -eq 2 ]; then verdict="block"; else verdict="allow"; fi
  if [ "$verdict" = "$expected" ]; then
    pass=$((pass+1))
  else
    fail=$((fail+1))
    echo "FAIL expected=$expected got=$verdict : $cmd"
    sed 's/^/    /' /tmp/guard-out.$$
  fi
  rm -f /tmp/guard-out.$$
}

check_non_bash() {
  jq -cn '{tool_name:"Read", tool_input:{file_path:"secret.txt"}}' | "$GUARD" >/dev/null 2>&1
  rc=$?
  if [ "$rc" -eq 0 ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL non-bash tool should always allow"; fi
}

# ---- trigger matching: must ALLOW without touching git state ----
check allow 'ls -la'
check allow 'git status'
check allow 'git log --oneline'
check allow "echo \"let's commit this\""
check allow 'docker push myimage'
check_non_bash

# ---- git commit: clean staged state -> allow ----
echo "clean content" > clean1.txt
git add clean1.txt
check allow 'git commit -m "clean commit"'
git reset -q

# ---- git commit: secret staged -> block ----
echo "TOKEN=$TOK" > secret1.txt
git add secret1.txt
check block 'git commit -m "add token"'
git reset -q
rm -f secret1.txt

# ---- git commit: chained command with secret staged -> block ----
echo "TOKEN=$TOK" > secret2.txt
git add secret2.txt
check block 'npm test && git add -A && git commit -m "message"'
git reset -q
rm -f secret2.txt

# ---- git commit: -C flag variant, clean state -> allow ----
echo "clean content 2" > clean2.txt
git add clean2.txt
check allow 'git -C '"$REPO"' commit -m "x"'
git reset -q

# ---- git commit -am: secret in an UNSTAGED tracked-file modification ----
# (-a folds working-tree changes into the commit; --staged alone can't see
# them yet since the index hasn't been touched when this hook fires)
echo "TOKEN=$TOK" >> README.md
git status --short >/dev/null
check block 'git commit -am "update readme"'
git checkout -q -- README.md

# ---- git commit -am: clean unstaged tracked-file modification -> allow ----
echo "a harmless readme edit" >> README.md
check allow 'git commit -am "update readme"'
git checkout -q -- README.md

# ---- hook cwd is a non-git directory -> allow (skip silently, no crash) ----
check allow 'git commit -m "x"' /tmp

# ---- commit the clean files so history is clean going into push tests ----
git add clean1.txt clean2.txt >/dev/null 2>&1
git commit -qm "clean history" >/dev/null 2>&1 || true

# ---- git push: clean unpushed commit -> allow ----
echo "clean push content" > clean3.txt
git add clean3.txt
git commit -qm "clean push commit" >/dev/null
check allow 'git push'

# ---- git push: secret in unpushed commit -> block ----
echo "TOKEN=$TOK" > secret3.txt
git add secret3.txt
git commit -qm "leak commit" >/dev/null
check block 'git push origin main'

# ==== wider-scan regressions ====
# The `-a` scan must look at the change being committed, not at the folder.
# Second scratch repo with a git-ignored build folder holding a fake secret
# (the shape of Next.js's `.next/`): nothing in it can ever be committed, so
# it must never cause a block.
REPO2=$(mktemp -d /tmp/secret-guard-test.XXXXXX) || exit 1
cd "$REPO2" || exit 1
git init -q
git config user.email test@test.com
git config user.name test
echo "build/" > .gitignore
echo "hello" > README.md
git add .gitignore README.md
git commit -qm init >/dev/null
mkdir build
echo "TOKEN=$TOK" > build/generated.js

# ---- clean staged change, unrelated `-a` later in the chain -> allow ----
echo "clean content" > file.txt
git add file.txt
check allow 'git add file.txt && git commit -m "x" && git branch -a' "$REPO2"

# ---- not a commit at all: a file search naming `.git` and "commit" -> allow ----
check allow 'find . -maxdepth 3 -name "deny-secret-commit.sh" -not -path "./.git/*"' "$REPO2"

# ---- clean unstaged tracked-file modification under -a -> allow ----
echo "a harmless readme edit" >> README.md
check allow 'git commit -am "x"' "$REPO2"
git checkout -q -- README.md

# ---- real secret under -a (tracked file, modified, not staged) -> block ----
echo "TOKEN=$TOK" >> README.md
check block 'git commit -am "x"' "$REPO2"
git checkout -q -- README.md

# ---- real secret, staged -> block ----
echo "TOKEN=$TOK" > secret4.txt
git add secret4.txt
check block 'git commit -m "x"' "$REPO2"
git reset -q -- secret4.txt
rm -f secret4.txt

# ---- brand-new untracked secret file, added earlier in the same chain ----
# (not in any diff yet when the hook fires, so the wider scan has to read
# untracked files that are not git-ignored)
echo "TOKEN=$TOK" > new-secret.txt
check block 'git add --all && git commit -m "x"' "$REPO2"
check block 'git add . && git commit -am "x"' "$REPO2"
rm -f new-secret.txt

# ---- git push: clean commit, secret only in the ignored folder -> allow ----
git commit -qm "clean commit" >/dev/null
check allow 'git push' "$REPO2"

# ---- git push: real secret in a commit being pushed -> block ----
echo "TOKEN=$TOK" > secret5.txt
git add secret5.txt
git commit -qm "leak commit" >/dev/null
check block 'git push origin main' "$REPO2"

# ---- repo with no commits yet (no HEAD to diff against) ----
REPO3=$(mktemp -d /tmp/secret-guard-test.XXXXXX) || exit 1
cd "$REPO3" || exit 1
git init -q
git config user.email test@test.com
git config user.name test

# secret staged, commit -am -> block
echo "TOKEN=$TOK" > first.txt
git add first.txt
check block 'git commit -am "first"' "$REPO3"

# file staged clean, secret added afterwards (unstaged), commit -am -> block
echo "clean" > first.txt
git add first.txt
echo "TOKEN=$TOK" >> first.txt
check block 'git commit -am "first"' "$REPO3"

# ==== gaps found in review (Oct 2026) ====
NEW=$(mktemp -d /tmp/secret-guard-test.XXXXXX) || exit 1
newrepo() { # $1 = folder name (may contain spaces); leaves cwd in the new repo
  mkdir -p "$NEW/$1" && cd "$NEW/$1" || exit 1
  git init -q
  git config user.email test@test.com
  git config user.name test
  echo "hello" > README.md
  git add README.md
  git commit -qm init >/dev/null
}
ALLOW_ALL='[allowlist]
paths = [".*"]'

# ---- a gitleaks:allow note on the line does not exempt it ----
newrepo allow-note
echo "TOKEN=$TOK # gitleaks:allow" > s.txt
git add s.txt
check block 'git commit -m "x"' "$PWD"

# ---- gitleaks settings files not committed exactly as they are ----
newrepo settings
printf '%s\n' "$ALLOW_ALL" > .gitleaks.toml
echo "TOKEN=$TOK" > s.txt
git add s.txt
check block 'git commit -m "x"' "$PWD"          # untracked allow-all .gitleaks.toml
check block 'git push' "$PWD"
rm .gitleaks.toml
echo "s.txt:github-pat:1" > .gitleaksignore
check block 'git commit -m "x"' "$PWD"          # untracked .gitleaksignore
rm .gitleaksignore
git reset -q
printf '[extend]\nuseDefault = true\n[allowlist]\npaths = ["fixtures/"]\n' > .gitleaks.toml
git add .gitleaks.toml
check block 'git commit -m "add scanner settings"' "$PWD"   # a commit that changes them
git commit -qm "settings, committed by the user" >/dev/null
mkdir fixtures
echo "TOKEN=$TOK" > fixtures/sample.txt
git add fixtures
check allow 'git commit -m "x"' "$PWD"          # committed settings are trusted...
git add s.txt
check block 'git commit -m "x"' "$PWD"          # ...and skip only what they say
printf '%s\n' "$ALLOW_ALL" > .gitleaks.toml
check block 'git commit -m "x"' "$PWD"          # committed settings, edited in place
git checkout -q -- .gitleaks.toml

# ---- GITLEAKS_CONFIG in the environment is ignored ----
printf '%s\n' "$ALLOW_ALL" > "$NEW/allow-all.toml"
export GITLEAKS_CONFIG="$NEW/allow-all.toml"
check block 'git commit -m "x"' "$PWD"
unset GITLEAKS_CONFIG
git reset -q
rm -rf s.txt fixtures

# ---- a `git add` earlier in the command; the new file isn't staged yet ----
newrepo chained-add
echo "TOKEN=$TOK" > new.txt
check block 'git add . && git commit -m "x"' "$PWD"
check block 'git add -A && git commit -m "x"' "$PWD"
check block 'git stage new.txt && git commit -m "x"' "$PWD"
check block 'git -C . add new.txt && git commit -m "x"' "$PWD"
check allow 'git commit -m "add the token later"' "$PWD"   # "add" in a message isn't a git add
rm new.txt
# removing a committed secret is not refused, even by the wider scan
echo "TOKEN=$TOK" > old.txt
git add old.txt
git commit -qm "fixture: a secret committed earlier" >/dev/null
echo "gone" > old.txt
check allow 'git add . && git commit -m "remove token"' "$PWD"
check allow 'git commit -am "remove token"' "$PWD"
git checkout -q -- old.txt

# ---- commit run from a subfolder, secret staged at the top ----
newrepo subfolder
mkdir sub
echo "x" > sub/a.txt
git add sub
git commit -qm layout >/dev/null
echo "TOKEN=$TOK" > root.txt
git add root.txt
check block 'git commit -m "x"' "$PWD/sub"
check block 'cd subfolder && git commit -m "x"' "$NEW"
git reset -q
rm root.txt

# ---- the command moves into the repo itself ----
newrepo "with space"
echo "TOKEN=$TOK" > s.txt
git add s.txt
check block "cd \"$PWD\" && git commit -m x" "$NEW"
check block "cd '$PWD'; git commit -m x" "$NEW"
check block 'cd "with space" && git commit -m x' "$NEW"
check block "git -C \"$PWD\" commit -m x" "$NEW"
check allow 'cd "no such folder" && git commit -m x' "$NEW"   # stays outside any repo
git reset -q
rm s.txt
check allow "cd \"$PWD\" && git commit -m x" "$NEW"

# ---- push of a branch other than the current one ----
newrepo pushes
git init -q --bare "$NEW/remote.git"
git remote add origin "$NEW/remote.git"
git push -q origin HEAD:main 2>/dev/null
check allow 'git push' "$PWD"                   # everything is already on the remote
git checkout -q -b feature
echo "TOKEN=$TOK" > s.txt
git add s.txt
git commit -qm "fixture: leak commit" >/dev/null
git checkout -q -
check block 'git push origin feature' "$PWD"
check block 'git push --all' "$PWD"
# a push from a detached HEAD (the commit is on no branch)
git checkout -q --detach
git rm -q s.txt 2>/dev/null; echo "TOKEN=$TOK" > detached.txt
git add detached.txt
git commit -qm "fixture: leak on a detached HEAD" >/dev/null
git branch -q -D feature
check block 'git push origin HEAD:main' "$PWD"

# ---- a decoy cd or -C into a folder that is not a repo ----
newrepo decoy
echo "TOKEN=$TOK" > s.txt
git add s.txt
mkdir -p "$NEW/not-a-repo"
check block "cd \"$NEW/not-a-repo\" && cd \"$PWD\" && git commit -m x" "$PWD"
check block "git -C \"$NEW/not-a-repo\" status; git commit -m x" "$PWD"
git reset -q
rm s.txt

# ---- a settings file that is a link to a file outside the repo ----
newrepo linked-settings
printf '[extend]\nuseDefault = true\n' > "$NEW/outside.toml"
ln -s "$NEW/outside.toml" .gitleaks.toml
git add .gitleaks.toml
git commit -qm "fixture: settings as a link" >/dev/null
printf '%s\n' "$ALLOW_ALL" > "$NEW/outside.toml"
echo "TOKEN=$TOK" > s.txt
git add s.txt
check block 'git commit -m "x"' "$PWD"

# ---- a committed settings file that pulls in a file outside the repo ----
newrepo extended-settings
printf '[extend]\nuseDefault = true\n' > "$NEW/outside2.toml"
printf '[extend]\npath = "%s"\n' "$NEW/outside2.toml" > .gitleaks.toml
git add .gitleaks.toml
git commit -qm "fixture: settings extend an outside file" >/dev/null
printf '%s\n' "$ALLOW_ALL" > "$NEW/outside2.toml"
echo "TOKEN=$TOK" > s.txt
git add s.txt
check block 'git commit -m "x"' "$PWD"
git reset -q
rm s.txt
# ...while one inside the repo, committed as it is, is trusted
mkdir cfg fixtures
printf '[extend]\nuseDefault = true\n[allowlist]\npaths = ["fixtures/"]\n' > cfg/base.toml
printf '[extend]\npath = "cfg/base.toml"\n' > .gitleaks.toml
git add cfg .gitleaks.toml
git commit -qm "fixture: settings extend a file in the repo" >/dev/null
echo "TOKEN=$TOK" > fixtures/f.txt
git add fixtures
check allow 'git commit -m "x"' "$PWD"
printf '%s\n' "$ALLOW_ALL" > cfg/base.toml
check block 'git commit -m "x"' "$PWD"          # the extended file, edited in place
git checkout -q -- cfg/base.toml
git reset -q
# a commit that stages a change to the extended file, with the working copy
# put back as committed
printf '%s\n' "$ALLOW_ALL" > cfg/base.toml
git add cfg/base.toml
git show HEAD:cfg/base.toml > cfg/base.toml
check block 'git commit -m "tweak scanner settings"' "$PWD"
git reset -q

# ---- other spellings of extend that gitleaks honours ----
newrepo dotted-extend
printf '%s\n' "$ALLOW_ALL" > "$NEW/outside3.toml"
printf 'extend.path = "%s"\n' "$NEW/outside3.toml" > .gitleaks.toml
git add .gitleaks.toml
git commit -qm "fixture: dotted extend key" >/dev/null
echo "TOKEN=$TOK" > s.txt
git add s.txt
check block 'git commit -m "x"' "$PWD"
git reset -q
rm s.txt
# an extended file whose name contains "=" is still read
printf '[extend]\npath = "%s"\n' "$NEW/outside3.toml" > 'a=b.toml'
printf '[extend]\npath = "a=b.toml"\n' > .gitleaks.toml
git add 'a=b.toml' .gitleaks.toml
git commit -qm "fixture: extend a file named with =" >/dev/null
echo "TOKEN=$TOK" > s.txt
git add s.txt
check block 'git commit -m "x"' "$PWD"
git reset -q

# ---- push while HEAD is a new, empty branch ----
newrepo unborn
git checkout -q -b leaky
echo "TOKEN=$TOK" > s.txt
git add s.txt
git commit -qm "fixture: leak commit" >/dev/null
git checkout -q --orphan empty
check block 'git push origin leaky' "$PWD"

cd / && rm -rf "$NEW"

echo ""
echo "passed: $pass, failed: $fail"
rm -rf "$REPO" "$REPO2" "$REPO3"
[ "$fail" -eq 0 ] || exit 1
