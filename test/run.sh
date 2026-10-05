#!/bin/bash
# Builds the test app with MTE on and off, runs pas on each by PID, and checks the output.
# Needs a Mac with MTE (M5 or later) for the tag checks.
set -euo pipefail
cd "$(dirname "$0")"
work=$(mktemp -d)
trap 'kill $(jobs -p) 2> /dev/null || true; rm -rf "$work"' EXIT
failures=0

address() { awk -v name="$1" '$1 == name { print $2 }' "$work/addresses.txt"; }

check() { # check info|page <allocation> <expected text>...
    local output
    output=$(../pas.py "$pid" "$1" "$(address "$2")")
    echo "$output"
    shift 2
    for text in "$@"; do
        if grep -qF -- "$text" <<< "$output"; then echo "  ok    $text"; else echo "  FAIL  $text"; failures=$((failures + 1)); fi
    done
}

for variant in mte plain; do
    echo "== $variant"
    xcrun clang -arch arm64e -O1 app.c -framework JavaScriptCore -o "$work/app"
    codesign -s - -f --entitlements "$variant.plist" "$work/app" 2> /dev/null
    "$work/app" > "$work/addresses.txt" &
    pid=$!
    while [ "$(wc -l < "$work/addresses.txt")" -lt 6 ]; do sleep 0.1; done

    if [ "$variant" = mte ]; then
        check info small "small bitfit page" "bytes, allocated" "tags match"
        check info freed "bytes, free" "tags differ"
        check info medium "medium bitfit page" "bytes, allocated" "tags match"
        check info larger "medium bitfit page" "bytes, allocated" "tags match"
    else
        check info small "small segregated page" "bytes, allocated" "address not tagged"
        check info freed "bytes, free"
        check info medium "medium segregated page" "bytes, allocated"
        check info larger "medium bitfit page" "bytes, allocated"
        check info large "marge bitfit page" "bytes, allocated"
    fi
    check info malloc "not in a bmalloc page"
    check page small "<- $(printf '%#018x' "$(address small)")"
    kill "$pid"
    wait "$pid" 2> /dev/null || true
done

[ "$failures" -eq 0 ] && echo "all checks passed" || { echo "$failures checks failed"; exit 1; }
