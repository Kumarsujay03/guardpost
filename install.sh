#!/usr/bin/env bash
# guardpost installer. No root needed; everything goes in your home folder.
#   ./install.sh            install, or update to this copy
#   ./install.sh --update   used by `guardpost update` (no first-run output)
# Remove with: guardpost uninstall  (or ./uninstall.sh)
set -euo pipefail
src="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
mode="${1:-}"
version="$(cat "$src/VERSION")"
data="${XDG_DATA_HOME:-$HOME/.local/share}/guardpost"
cfg="${XDG_CONFIG_HOME:-$HOME/.config}/guardpost"
units="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
say() { [ "$mode" = "--update" ] || echo "$@"; }

command -v python3 >/dev/null || { echo "guardpost needs python3 (3.10 or newer)"; exit 1; }
python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' || { echo "guardpost needs Python 3.10 or newer"; exit 1; }
command -v git >/dev/null || { echo "guardpost needs git"; exit 1; }

say "== guardpost $version"
# each version in its own folder; `current` points at the one in use
app="$data/app/$version"
if [ "$src" != "$app" ]; then
    rm -rf "$app.new"
    mkdir -p "$data/app"
    cp -r "$src" "$app.new"
    rm -rf "$app.new/.git" "$app"
    mv "$app.new" "$app"
fi
ln -sfn "$app" "$data/app/current.new"
mv -T "$data/app/current.new" "$data/app/current"
cur="$data/app/current"
# keep the two newest versions, so a bad update can be rolled back by hand
find "$data/app" -mindepth 1 -maxdepth 1 -type d -name '[0-9]*' | sort -V | head -n -2 | while read -r old; do
    [ "$old" = "$app" ] || rm -rf "$old"
done

say "== command: ~/.local/bin/guardpost"
mkdir -p "$HOME/.local/bin" "$cfg"
ln -sfn "$cur/bin/guardpost" "$HOME/.local/bin/guardpost"
case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) say "   add ~/.local/bin to your PATH" ;; esac

say "== check every git clone (post-checkout hook in git's template folder)"
tmpl="$cfg/git-template"
existing="$(git config --global --get init.templateDir || true)"
if [ -n "$existing" ] && [ "$existing" != "$tmpl" ]; then
    say "   git already uses the template folder $existing; link $cur/hooks/post-checkout into its hooks/ yourself"
else
    mkdir -p "$tmpl/hooks"
    if [ -d /usr/share/git-core/templates ]; then
        cp -rn /usr/share/git-core/templates/. "$tmpl/" 2>/dev/null || true
    fi
    ln -sfn "$cur/hooks/post-checkout" "$tmpl/hooks/post-checkout"
    git config --global init.templateDir "$tmpl"
    say "   on for new clones (check older ones with: guardpost scan <folder>)"
fi

say "== check npm/pip/yarn/pnpm/bun/uv/cargo/make installs"
if command -v fish >/dev/null; then
    mkdir -p "$HOME/.config/fish/conf.d"
    ln -sfn "$cur/shell/guardpost.fish" "$HOME/.config/fish/conf.d/guardpost.fish"
    say "   fish: on"
fi
line="[ -f '$cur/shell/guardpost.bash' ] && . '$cur/shell/guardpost.bash'  # guardpost"
touch "$HOME/.bashrc"
if grep -q "# guardpost$" "$HOME/.bashrc"; then
    sed -i "/# guardpost\$/c\\$line" "$HOME/.bashrc"
else
    printf '\n%s\n' "$line" >> "$HOME/.bashrc"
fi
say "   bash: on"
if [ -f "$HOME/.zshrc" ] && ! grep -q "# guardpost$" "$HOME/.zshrc"; then
    printf '\n%s\n' "[ -f '$cur/shell/guardpost.bash' ] && . '$cur/shell/guardpost.bash'  # guardpost" >> "$HOME/.zshrc"
    say "   zsh: on"
fi

if [ ! -f "$cfg/config.json" ]; then
    owner="$(gh api user --jq .login 2>/dev/null || git config --global --get github.user || true)"
    cat > "$cfg/config.json" <<EOF
{
  "quiet_hours": [3, 8],
  "owners": [],
  "trusted_owners": [${owner:+\"$owner\"}],
  "auto_update": true
}
EOF
    say "== settings: $cfg/config.json"
fi

if command -v systemctl >/dev/null && systemctl --user show-environment >/dev/null 2>&1; then
    mkdir -p "$units"
    for u in guardpost-boot.service guardpost-sweep.service guardpost-sweep.timer \
             guardpost-update.service guardpost-update.timer; do
        ln -sfn "$cur/system/$u" "$units/$u"
    done
    systemctl --user daemon-reload
    systemctl --user enable guardpost-boot.service >/dev/null 2>&1 || true
    systemctl --user enable --now guardpost-sweep.timer guardpost-update.timer >/dev/null 2>&1 || true
    say "== timers: boot check at login, sweep weekly, updates daily"
else
    say "== no systemd user session: run 'guardpost boot', 'guardpost sweep' and 'guardpost update' yourself"
fi

if [ "$mode" != "--update" ]; then
    for tool in yara clamscan; do
        command -v "$tool" >/dev/null || echo "   optional: install ${tool/clamscan/clamav} for its malware signatures (see README)"
    done
    echo "== first baseline"
    "$HOME/.local/bin/guardpost" boot >/dev/null 2>&1 || true
    "$HOME/.local/bin/guardpost" update --feeds-only --quiet || true
    echo "   done. Open a new terminal so the install checks start."
fi
