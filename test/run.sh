#!/bin/bash
# Runs pas against the test app and checks its output.
#
#   test/run.sh                         against the system JavaScriptCore
#   test/run.sh <WebKitBuild/Release>   against a JavaScriptCore you built
#
# Each run builds the test app with MTE off and on. The MTE half is skipped when the app's pointers
# come back untagged: on a Mac without MTE (before M5), or with a JavaScriptCore built without it.
set -euo pipefail
cd "$(dirname "$0")"
build=${1:+$(cd "$1" && pwd)}
work=$(mktemp -d)
trap 'kill $(jobs -p) 2> /dev/null || true; rm -rf "$work"' EXIT
failures=0

expect() { # expect <output> <text>...
    local output=$1
    shift
    for text in "$@"; do
        if grep -qF -- "$text" <<< "$output"; then echo "  ok    $text"; else echo "  FAIL  $text"; failures=$((failures + 1)); fi
    done
}

address() { awk -v name="$1" '$1 == name { print $2 }' "$work/addresses.txt"; }

python_check() { # python_check <description> <python code> [arguments]...
    local description=$1
    shift
    if python3 -c "$@"; then echo "  ok    $description"; else echo "  FAIL  $description"; failures=$((failures + 1)); fi
}

check() { # check <command> "[--page] <allocation> [file]" <expected text>...
    local output words=() word
    for word in $2; do
        case $word in --page|/*) words+=("$word") ;; *) words+=("$(address "$word")") ;; esac
    done
    output=$(../pas.py "$pid" "$1" ${words[@]+"${words[@]}"})
    echo "$output"
    shift 2
    expect "$output" "$@"
}

build_app() { # build_app <entitlements>
    if [ -n "$build" ]; then
        xcrun clang -arch arm64 -O1 app.c -F "$build" -framework JavaScriptCore -o "$work/app"
    else
        xcrun clang -arch arm64e -O1 app.c -framework JavaScriptCore -o "$work/app"
    fi
    codesign -s - -f --entitlements "$1.plist" "$work/app" 2> /dev/null
}

start_app() { # start_app [mode]
    DYLD_FRAMEWORK_PATH="${frameworks:-$build}" "$work/app" "$@" > "$work/addresses.txt" &
    pid=$!
    while [ "$(wc -l < "$work/addresses.txt")" -lt 6 ]; do sleep 0.1; done
}

stop_app() {
    kill "$pid" 2> /dev/null || true
    wait "$pid" 2> /dev/null || true
}

for variant in mte plain; do
    echo "== $variant${build:+ ($build)}"
    build_app "$variant"
    start_app
    if [ "$variant" = mte ] && [ $(( $(address small) >> 56 )) -eq 0 ]; then
        echo "  skipped: the app's pointers aren't tagged, so MTE isn't on"
        stop_app
        continue
    fi
    if [ "$variant" = mte ]; then
        check info small "Common Primitive (" "small bitfit, 16 KiB" "bytes, allocated" "tags match"
        check info freed "bytes, free" "tags differ"
        check info medium "medium bitfit, 512 KiB" "bytes, allocated" "tags match"
        check info larger "medium bitfit, 512 KiB" "bytes, allocated" "tags match"
        check info large "(large object)" "bytes, allocated"
        check explain freed "likely use after free"
    else
        check info small "Common Primitive (bmalloc)" "small segregated, 16 KiB" "bytes, allocated" "address not tagged"
        check info freed "bytes, free"
        check info medium "medium segregated, 128 KiB" "bytes, allocated"
        check info larger "medium bitfit, 512 KiB" "bytes, allocated"
        check info large "marge bitfit, 4 MiB" "bytes, allocated"
        check explain freed "address not tagged"
    fi
    check info malloc "not in libpas"
    check page small "<- $(printf '%#018x' "$(address small)")"
    check refs small "object $(printf '%#x' $(( $(address medium) & 0x00ffffffffffffff ))) +0x8" "(1 found)"
    check heap "" "Common Primitive" "total"
    check dump "medium $work/medium.bin" "wrote the 3072-byte object at"
    # The app stored a pointer to the small object at +8 in the medium one.
    python_check "the dump holds the stored pointer, and its JSON file matches" '
import json, sys
data, about = open(sys.argv[1], "rb").read(), json.load(open(sys.argv[1] + ".json"))
mask = (1 << 56) - 1
assert len(data) == about["size"] == 3072 and about["dumped"] == "object"
assert int.from_bytes(data[8:16], "little") & mask == int(sys.argv[2], 16) & mask' "$work/medium.bin" "$(address small)"
    check dump "--page small $work/page.bin" "wrote the 16384-byte page at"
    stop_app

    if [ "$variant" = plain ]; then
        # Frees on segregated pages wait in the thread's deallocation log, so break right after one.
        echo "== $variant, deallocation log under LLDB"
        start_app deallocation-log
        output=$(perl -e 'alarm 60; exec @ARGV' xcrun lldb --batch -p "$pid" -o "command script import ../pas.py" \
            -o "breakpoint set -n checkpoint" -o continue -o "pas log" -o "pas info *(void**)&last_freed" \
            -o "process kill" 2>&1 | sed -n '/^(lldb) pas log/,$p')
        echo "$output"
        expect "$output" "1 pending free" "Common Primitive, small segregated" "freed, waiting in thread 1's deallocation log"
        stop_app
    fi

    if [ "$variant" = mte ]; then
        for mode in use-after-free out-of-bounds; do
            echo "== $variant, $mode under LLDB"
            start_app "$mode"
            # perl's alarm limits the run to a minute in case LLDB doesn't return.
            output=$(perl -e 'alarm 60; exec @ARGV' xcrun lldb --batch -p "$pid" -o "command script import ../pas.py" -o continue \
                -k "pas explain" -k "process kill" 2>&1 | sed -n '/^fault /,/^cause /p')
            echo "$output"
            expect "$output" "EXC_ARM_MTE_TAG_FAULT" "likely ${mode//-/ }"
            stop_app
        done
    fi
done

if [ -n "$build" ]; then
    # Without debug info, pas falls back to built-in offsets, picked by checking which set fits.
    echo "== plain, without debug info ($build)"
    frameworks="$work/stripped"
    mkdir -p "$frameworks"
    cp -R "$build/JavaScriptCore.framework" "$frameworks/"
    strip -S "$frameworks/JavaScriptCore.framework/Versions/A/JavaScriptCore" 2> /dev/null
    codesign -s - -f "$frameworks/JavaScriptCore.framework" 2> /dev/null
    build_app plain
    start_app
    check info small "offsets, which fit its memory" "Common Primitive (bmalloc)" "bytes, allocated"
    check refs small "(1 found)"
    check heap "" "Common Primitive" "total"
    stop_app
fi

[ "$failures" -eq 0 ] && echo "all checks passed" || { echo "$failures checks failed"; exit 1; }
