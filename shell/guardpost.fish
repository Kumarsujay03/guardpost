# guardpost: check code before package managers install it, and what landed after.
# Skip once with: GUARDPOST_OFF=1 npm install
if status is-interactive
    for tool in npm pnpm yarn bun pip pip3 uv make cargo
        function $tool --inherit-variable tool --wraps $tool
            # only installs are checked; everything else goes straight through
            if contains -- install $argv; or contains -- i $argv; or contains -- add $argv; or contains -- ci $argv; or begin; test $tool = yarn; and test (count $argv) -eq 0; end
                guardpost guard $tool -- $argv; or return 1
                set -l started (date +%s)
                command $tool $argv
                set -l code $status
                test $code -eq 0; and guardpost after --since $started $tool -- $argv
                return $code
            end
            command $tool $argv
        end
    end
end
