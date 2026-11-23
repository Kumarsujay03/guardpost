#!/usr/bin/env bash
# Removes guardpost. Keeps your reports in ~/.local/state/guardpost and your
# settings in ~/.config/guardpost/config.json.
set -uo pipefail
data="${XDG_DATA_HOME:-$HOME/.local/share}/guardpost"
cfg="${XDG_CONFIG_HOME:-$HOME/.config}/guardpost"
units="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
if command -v systemctl >/dev/null; then
    systemctl --user disable --now guardpost-boot.service guardpost-sweep.timer guardpost-update.timer >/dev/null 2>&1
fi
for u in guardpost-boot.service guardpost-sweep.service guardpost-sweep.timer guardpost-update.service guardpost-update.timer; do
    rm -f "$units/$u"
done
command -v systemctl >/dev/null && systemctl --user daemon-reload 2>/dev/null
[ "$(git config --global --get init.templateDir)" = "$cfg/git-template" ] && git config --global --unset init.templateDir
rm -rf "$cfg/git-template" "$data/app"
rm -f "$HOME/.config/fish/conf.d/guardpost.fish" "$HOME/.local/bin/guardpost"
for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [ -f "$rc" ] && sed -i '/# guardpost$/d' "$rc"
done
echo "guardpost removed. Clones made while it was on keep a post-checkout hook;"
echo "it does nothing now that the guardpost command is gone."
