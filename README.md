# pas

Looks up an address in libpas, the memory allocator inside WebKit, and shows its MTE tags.
Give it a pointer from a live process and it tells you which libpas page and object the pointer
falls in, whether that object is allocated or free, and whether the pointer's tag matches the
memory's tag.

MTE is Arm's Memory Tagging Extension, the hardware feature behind Apple's Memory Integrity
Enforcement. It gives every 16 bytes of memory a 4-bit tag, and each pointer carries a tag too.
When a program reads or writes memory through a pointer whose tag doesn't match, the access fails
with a tag-check fault.

`pas` only reads memory. It never calls functions in the process or writes to it.

`pas` came out of research for [Tagging WebKit](https://almamatertech.com/notes/mte-1-mie-arrives/),
a series on how WebKit uses MTE.

## Example

A 24-byte allocation from `fastMalloc`, WebKit's general allocation function, and its freed
neighbour, in a process with MTE enabled, on an M6 Mac running macOS 27.0.1:

```
$ pas 5046 info 0x01000001100004f0
pointer   0x01000001100004f0   tag 1
heap      bmalloc, small bitfit page
page      0x110000000   16 KiB
object    0x1100004f0 - 0x110000510   32 bytes, allocated
offset    +0x0
memory    1 1
result    tags match

$ pas 5046 info 0x0c00000110000510
pointer   0x0c00000110000510   tag c
heap      bmalloc, small bitfit page
page      0x110000000   16 KiB
object    0x110000510 - 0x110000530   32 bytes, free
offset    +0x0
memory    2 2
result    tags differ: pointer c, memory 2
```

The freed object's memory was retagged from `c` to `2`, so the old pointer no longer matches.
`page` lists the objects around an address, with the tag of each 16-byte granule:

```
$ pas 5046 page 0x0c00000110000510
page 0x110000000   bmalloc, small bitfit, 16 KiB

address         bytes  state      tags
...
0x1100004d0        32  allocated  2 2
0x1100004f0        32  allocated  1 1
0x110000510        32  free       2 2   <- 0x0c00000110000510
0x110000530        32  allocated  8 8
0x110000550        32  allocated  1 1
...
(17 of 65 entries)
```

## Usage

From a shell, by process ID:

```
pas.py <pid> info <address>
pas.py <pid> page <address>
```

`pas` attaches with LLDB, reads what it needs, and detaches. The process pauses for about a second.

Inside LLDB, for example when stopped at a crash:

```
(lldb) command script import /path/to/pas.py
(lldb) pas info $x0
(lldb) pas page (char*)buffer + 64
```

The address can be any LLDB expression. To load `pas` in every session, add the
`command script import` line to `~/.lldbinit`. To run it as `pas`, link it onto your `PATH` with
`ln -s "$PWD/pas.py" /usr/local/bin/pas`.

## Requirements

- macOS with Xcode or the Command Line Tools. `pas` runs on the Python that comes with LLDB.
- A process LLDB can attach to: your own builds signed with `get-task-allow`, a local `jsc`, or
  a local MiniBrowser. Safari and other system processes need System Integrity Protection (SIP)
  turned off.
- A Mac with MTE (M5 or later) to see tags. Elsewhere `pas` still finds pages and objects, and
  shows memory as `not tagged`.

## What it covers

`pas` understands the `bmalloc` and `tagged_bmalloc` heaps, where `WTF::fastMalloc` and most of
WebKit's C++ objects are allocated. It handles all five libpas page kinds: small and medium
segregated, and small, medium and marge bitfit. Anything else (large libpas objects, the JIT heap,
system malloc, stacks) is reported as `not in a bmalloc page`, with the memory tag at the address.

Struct offsets and page sizes come from WebKit
[`814bf42b6770`](https://github.com/WebKit/WebKit/tree/814bf42b67703b979ecce989e6624b9c3b44d8dc/Source/bmalloc/libpas)
and were checked against the shipped JavaScriptCore in macOS 27.0.1 (26A434). On other builds `pas`
prints a note, because libpas layouts can change between releases.

Limits:

- Live processes only, no core files.
- A segregated page shared by several object sizes has no fixed object size, so `pas` can't show
  object boundaries in it.
- While a thread allocates from a segregated page, objects waiting in that thread's cache count
  as allocated. `info` prints a note when this applies.
- The shipped build above puts tagged allocations in the `bmalloc` heap. `pas` reads
  `tagged_bmalloc` the same way, but hasn't been tested against a process that uses it.

## Testing

`test/run.sh` builds a small program that allocates with `fastMalloc`, once with MTE enabled and
once without, and checks `pas`'s output for each page kind. It needs an MTE Mac.

Licensed under [MIT](LICENSE).
