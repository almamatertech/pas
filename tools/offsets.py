#!/usr/bin/env python3
"""Generate pas offsets from a WebKit checkout.

pas needs to know where some libpas struct fields are. Builds with debug info tell it, but shipped
builds don't, so pas loads offsets for them from offsets/, one JSON file per set. This script
generates a set: it compiles a small program against the checkout's libpas headers that prints each
offset and size pas.py lists in FIELDS and SIZED, and writes them to offsets/<name>.json.

    tools/offsets.py <WebKit checkout> [name]

The name defaults to the checkout's tag, or its commit. Only Source/bmalloc of the checkout is
needed. Fields that don't exist in that version of libpas are left out, and pas treats them as
absent. If the file already exists, its "builds" list, the JavaScriptCore build IDs the set was
checked against, is kept, and git diff shows whether anything else changed.
"""
import ast
import json
import os
import re
import subprocess
import sys
import tempfile

PAS = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "pas.py")
OFFSETS = os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "offsets")
HEADERS = ("pas_heap.h", "pas_heap_config.h", "pas_segregated_page.h", "pas_bitfit_page.h",
           "pas_segregated_exclusive_view.h", "pas_segregated_size_directory.h", "pas_bitfit_view.h",
           "pas_bitfit_directory.h", "pas_segregated_heap.h", "pas_page_header_table.h",
           "pas_lock_free_read_ptr_ptr_hashtable.h", "pas_fast_megapage_table.h", "pas_large_map.h",
           "pas_first_level_tiny_large_map_entry.h", "pas_thread_local_cache.h", "pas_thread_local_cache_node.h",
           "bmalloc_type.h")


def read_pas():
    """FIELDS and SIZED from pas.py, read without importing it, which would need LLDB."""
    values = {}
    for node in ast.parse(open(PAS).read()).body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) in ("FIELDS", "SIZED"):
            values[node.targets[0].id] = ast.literal_eval(node.value)
    return values["FIELDS"], values["SIZED"]


def program(items):
    lines = ['#include "pas_config.h"']
    for header in HEADERS:
        lines += [f'#if __has_include("{header}")', f'#include "{header}"', "#endif"]
    lines += ["#include <stddef.h>", "#include <stdio.h>", "int main(void)", "{"]
    rows = {}
    for struct, path in items:
        rows[len(lines) + 1] = (struct, path)
        if path is None:
            lines.append(f'    printf("{struct} - %zu\\n", sizeof({struct}));')
        else:
            lines.append(f'    printf("{struct} {path} %zu\\n", offsetof({struct}, {path}));')
    lines += ["    return 0;", "}"]
    return "\n".join(lines) + "\n", rows


def measure(checkout, fields, sized):
    """Compile and run the program, dropping fields this libpas doesn't have."""
    libpas = os.path.join(checkout, "Source/bmalloc/libpas/src/libpas")
    if not os.path.isdir(libpas):
        sys.exit(f"no libpas in {checkout}")
    items = [(struct, path) for struct, paths in fields.items() for path in paths] + [(s, None) for s in sized]
    with tempfile.TemporaryDirectory() as work:
        source, binary = os.path.join(work, "offsets.c"), os.path.join(work, "offsets")
        while True:
            text, rows = program(items)
            open(source, "w").write(text)
            build = subprocess.run(["xcrun", "clang", "-std=gnu11", "-w", "-DPAS_BMALLOC=1", "-DPAS_ENABLE_MTE=0",
                                    "-I", libpas, "-I", os.path.join(checkout, "Source/bmalloc/bmalloc"),
                                    source, "-o", binary], capture_output=True, text=True)
            if build.returncode == 0:
                break
            # An error on a field's line means this libpas doesn't have that field.
            missing = {rows[int(line)] for line in re.findall(r"offsets\.c:(\d+):\d+: error", build.stderr)
                       if int(line) in rows}
            if not missing:
                sys.exit(build.stderr)
            items = [item for item in items if item not in missing]
        output = subprocess.run([binary], capture_output=True, text=True, check=True).stdout
    offsets = {"fields": {}, "sizes": {}}
    for line in output.splitlines():
        struct, path, value = line.split()
        if path == "-":
            offsets["sizes"][struct] = int(value)
        else:
            offsets["fields"].setdefault(struct, {})[path] = int(value)
    return offsets


def source_name(checkout):
    """The checkout's tag if it's on one, else its short commit."""
    for command in (["git", "describe", "--tags", "--exact-match"], ["git", "rev-parse", "--short=12", "HEAD"]):
        result = subprocess.run(command, cwd=checkout, capture_output=True, text=True)
        if result.returncode == 0:
            return result.stdout.strip()
    return os.path.basename(os.path.abspath(checkout))


def main(arguments):
    if len(arguments) not in (1, 2):
        sys.exit("usage: tools/offsets.py <WebKit checkout> [name]")
    checkout = arguments[0]
    source = source_name(checkout)
    name = arguments[1] if len(arguments) == 2 else source
    path = os.path.join(OFFSETS, name + ".json")
    builds = json.load(open(path)).get("builds", []) if os.path.exists(path) else []
    data = {"source": source, "builds": builds, **measure(checkout, *read_pas())}
    os.makedirs(OFFSETS, exist_ok=True)
    with open(path, "w") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    print(f"wrote {os.path.relpath(path)}")


if __name__ == "__main__":
    main(sys.argv[1:])
