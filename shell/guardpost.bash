# guardpost: check code before package managers install it, and what landed after.
# Skip once with: GUARDPOST_OFF=1 npm install
if [[ $- == *i* ]] && command -v guardpost >/dev/null; then
    _gp_check() {
        local a
        [[ $1 == yarn && $# -eq 1 ]] && return 0
        for a in "${@:2}"; do
            case $a in install|i|add|ci) return 0 ;; esac
        done
        return 1
    }
    _gp_run() {
        local tool=$1; shift
        if _gp_check "$tool" "$@"; then
            guardpost guard "$tool" -- "$@" || return 1
            local started code
            started=$(date +%s)
            command "$tool" "$@"; code=$?
            [ $code -eq 0 ] && guardpost after --since "$started" "$tool" -- "$@"
            return $code
        fi
        command "$tool" "$@"
    }
    for _gp_tool in npm pnpm yarn bun pip pip3 uv make cargo; do
        eval "$_gp_tool() { _gp_run $_gp_tool \"\$@\"; }"
    done
    unset _gp_tool
fi
