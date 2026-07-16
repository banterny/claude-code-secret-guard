#!/usr/bin/env bash
# Test harness for deny-secret-commit.sh. Builds a real scratch git repo so
# the trigger-matching AND the actual gitleaks scan get exercised, not just
# the regex.
set -u
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
GUARD="$SCRIPT_DIR/deny-secret-commit.sh"
pass=0
fail=0

# Generated at runtime, not a literal, so this file itself never contains a
# real token-shaped string (it would trip gitleaks/GitHub push protection).
TOK="ghp_$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 36)"

REPO=$(mktemp -d /tmp/secret-guard-test.XXXXXX)
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

echo ""
echo "passed: $pass, failed: $fail"
rm -rf "$REPO"
[ "$fail" -eq 0 ] || exit 1
