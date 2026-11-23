#!/usr/bin/env bash
# Checks an installed guardpost (CI runs it after install.sh).
set -euo pipefail
fail() { echo "FAIL: $*"; exit 1; }
ok() { echo "ok    $*"; }
here="$(cd "$(dirname "$0")/.." && pwd)"
data="${XDG_DATA_HOME:-$HOME/.local/share}/guardpost"
cfg="${XDG_CONFIG_HOME:-$HOME/.config}/guardpost"
export PATH="$HOME/.local/bin:$PATH"

[ "$(guardpost --version)" = "guardpost $(cat "$here/VERSION")" ] || fail "guardpost --version: $(guardpost --version)"
ok "command, version $(cat "$here/VERSION")"
[ -L "$data/app/current" ] && [ -f "$data/app/current/install.sh" ] || fail "no versioned install in $data/app"
ok "versioned install: $(readlink "$data/app/current")"
[ "$(git config --global --get init.templateDir)" = "$cfg/git-template" ] || fail "init.templateDir not set"
[ -x "$cfg/git-template/hooks/post-checkout" ] || fail "post-checkout hook missing"
ok "git clone hook"
grep -q "# guardpost$" "$HOME/.bashrc" || fail "bash wrappers not in ~/.bashrc"
ok "bash wrappers"
python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$cfg/config.json" || fail "config.json"
ok "settings"
guardpost scan "$here" >/dev/null || fail "guardpost scan of its own source said DANGER"
ok "guardpost scans its own source as not dangerous"
