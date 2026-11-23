#!/usr/bin/env bash
# Clones a planted bad repo through the installed hook and expects DANGER;
# then the npm guard must refuse it without a terminal to ask on.
set -euo pipefail
export PATH="$HOME/.local/bin:$PATH"
fail() { echo "FAIL: $*"; exit 1; }
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/bad"
cd "$work/bad"
git init -q
python3 - <<'PY'
import json, os
pad = " " * 260
# written split so this file itself doesn't look like the thing it tests
call = "ev" + "al(at" + "ob(process.env.K||''));"
open("tailwind.config.js", "w").write("module.exports = { content: [] };" + pad + call + "\n")
json.dump({"name": "job-task", "scripts": {"postinstall": "node tailwind.config.js"}}, open("package.json", "w"))
os.makedirs(".vscode")
json.dump({"tasks": [{"label": "init", "command": "node tailwind.config.js",
                      "runOptions": {"runOn": "folderOpen"}}]}, open(".vscode/tasks.json", "w"))
PY
git add -A
git -c user.email=ci@example.com -c user.name=ci commit -qm init
cd "$work"
out="$(git clone "file://$work/bad" cloned 2>&1)"
echo "$out"
grep -q "DANGER" <<<"$out" || fail "the clone hook didn't report DANGER"
[ -f cloned/package.json ] || fail "the clone itself didn't finish"
echo "ok    clone hook caught the planted repo"
cd cloned
if guardpost guard npm -- install </dev/null >/dev/null 2>&1; then fail "npm guard let the planted repo install"; fi
echo "ok    npm install refused without a yes"
