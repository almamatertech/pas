# pas

Inspects libpas, the memory allocator inside WebKit, from LLDB. Give it an address and it tells
you which heap, page and object the address falls in, and whether the object is allocated or
free. It can also list every libpas heap in a process, find the objects that point to an object,
and, on a Mac with MTE, explain a tag-check fault.

MTE is Arm's Memory Tagging Extension, the hardware feature behind Apple's Memory Integrity
Enforcement. It gives every 16 bytes of memory a 4-bit tag, and each pointer carries a tag too.
When a program reads or writes memory through a pointer whose tag doesn't match, the access fails
with a tag-check fault.

`pas` only reads memory. It never calls functions in the process or writes to it. It works with
the JavaScriptCore that ships with macOS and with JavaScriptCore you build yourself.

Tested on a Mac mini (Mac18,5) with an M6 chip running macOS 27.0.1 (26A434), with the
JavaScriptCore that ships with it and with WebKit built from source. [Testing](#testing) has the
details.

`pas` came out of research for [Tagging WebKit](https://almamatertech.com/notes/mte-1-mie-arrives/),
a series on how WebKit uses MTE.

## Commands

| Command | What it shows |
| --- | --- |
| `info <address>` | The heap, page and object at an address, and the pointer and memory tags |
| `page <address>` | The objects around an address in its page, with their tags |
| `heap` | Every libpas heap in the process: pages, objects and bytes in use |
| `refs <address>` | Allocated libpas objects that hold a pointer into the object at an address |
| `log` | Each thread's recent frees that libpas hasn't returned to their pages yet |
| `explain [address]` | Why a pointer's tag doesn't match its memory, and the likely bug |

## Examples

A 24-byte allocation from `fastMalloc`, WebKit's general allocation function, in a process with
MTE enabled, on an M6 Mac running macOS 27.0.1:

```
$ pas 16239 info 0x01000001120004f0
pointer   0x01000001120004f0   tag 1
heap      Common Primitive (bmalloc)
page      0x112000000   small bitfit, 16 KiB
object    0x1120004f0 - 0x112000510   32 bytes, allocated
offset    +0x0
memory    1 1
result    tags match

$ pas 16239 refs 0x01000001120004f0
pointers to 0x1120004f0 - 0x112000510, in allocated libpas objects:
  0x113000008   object 0x113000000 +0x8  (Common Primitive) -> +0x0
(1 found)
```

libpas keeps objects in two kinds of pages. Segregated pages hold same-size objects in fixed
slots, and bitfit pages hold objects of different sizes, tracked with a bit for every 16 bytes.
Pages come in small, medium and marge sizes, marge being libpas's word for medium-large.

The same program reading one byte past that object's neighbour, stopped at the fault in LLDB:

```
(lldb) pas explain
fault     EXC_ARM_MTE_TAG_FAULT (code=262, address=0xb0000010e0004f0)
pointer   0x0b0000010e0004f0   tag b
heap      Common Primitive (bmalloc)
page      0x10e000000   small bitfit, 16 KiB
object    0x10e0004f0 - 0x10e000510   32 bytes, allocated
offset    +0x0
memory    e
result    tags differ: pointer b, memory e
cause     likely out of bounds: the allocated 32-byte object at 0x10e0004d0 has the pointer's tag, and the address is just past the end of it
```

`explain` compares the pointer's tag with the tags of the objects around the address. A
neighbour with the pointer's tag suggests an out-of-bounds access from that neighbour. A free
object at the address, or one reallocated with a new tag, suggests a use after free.

The heaps of a `jsc` shell built from source, holding 200,000 small objects:

```
$ pas 40481 heap
heap                                 pages  page bytes  objects      in use  large
Compact Primitive                      589    83017728   211203    80089408      1
Common Primitive                       180    12222464    19184     4576992      0
TZone bucket 84, 141024-byte types       0           0        1      141024      1
TZone bucket 76, 3280-byte types         1      131072       36      129024      0
TZone bucket 74, 3120-byte types         1      131072       36      129024      0
...
total                                  840    97140736   249178    86167232      3
(58 heaps. Objects and bytes in use include large objects, which libpas keeps outside pages.)
```

Heaps are named after their type. TZone, WebKit's way of keeping C++ types apart in separate
heaps, names its heaps, or buckets, with just a running number, on purpose. `pas` shows that number
and the object size each bucket serves.

Freeing an object on a segregated page doesn't update the page right away. libpas appends the
object to the thread's deallocation log and returns logged objects to their pages in batches.
Until then the page still marks the object allocated. So `pas` reads the logs too. `info`, `page`,
`heap`, `refs` and `explain` treat a logged object as freed, and `log` lists them:

```
(lldb) pas log
thread 1: 1 pending free
  0x1100004e0   32 bytes   Common Primitive, small segregated
(newest first, and libpas returns these objects to their pages in batches)
(lldb) pas info *(void**)&last_freed
...
object    0x1100004e0 - 0x110000500   32 bytes, freed, waiting in thread 1's deallocation log
```

libpas's background cleanup thread, the scavenger, empties idle threads' logs within moments, so
the log is most useful from a breakpoint or a crash, where the process stopped right after the
free.

## Usage

From a shell, by process ID:

```
pas.py <pid> info|page|refs|explain <address>
pas.py <pid> heap|log
```

`pas` attaches with LLDB, reads what it needs, and detaches. The process pauses while it does, for
about a second with most commands and longer with `heap` and `refs` on a large heap.

Inside LLDB, for example when stopped at a crash:

```
(lldb) command script import /path/to/pas.py
(lldb) pas info $x0
(lldb) pas page (char*)buffer + 64
(lldb) pas explain
```

The address can be any LLDB expression. With no address, `explain` uses the tag-check fault the
current thread stopped at. To load `pas` in every session, add the `command script import` line to
`~/.lldbinit`. To run it as `pas`, link it onto your `PATH` with
`ln -s "$PWD/pas.py" /usr/local/bin/pas`.

## Requirements

- macOS with Xcode or the Command Line Tools. `pas` runs on the Python that comes with LLDB.
- A process LLDB can attach to. Your own programs need the `com.apple.security.get-task-allow`
  entitlement (see `test/plain.plist`). If LLDB can't attach to a `jsc` you built, re-sign it
  with that entitlement. Safari and other system processes need System Integrity Protection
  (SIP) turned off. To attach from SSH, or another session where macOS can't ask for your
  password, turn on developer mode with `sudo DevToolsSecurity -enable`.
- For tags, a Mac with MTE (M5 or later) and a process with MTE enabled. JavaScriptCore built from
  source with the public SDK leaves MTE off, so `pas` shows its memory as `not tagged`. To turn MTE
  on in your build, see
  [JavaScriptCore with MTE, from source](#javascriptcore-with-mte-from-source).

## How `pas` knows libpas's layout

`pas` finds things the way libpas does. It finds a page through libpas's lookup tables, the
objects in it through the page's bits, its heap through the page's owner, objects outside pages
through libpas's table of large objects, and objects freed but not yet returned through each
thread's deallocation log. It reads page sizes from libpas's heap settings in the process.

For struct layouts, `pas` uses the build's debug info when it has some, as JavaScriptCore built
from source does. Shipped builds have none, so `pas` falls back to a built-in table checked against
the JavaScriptCore in macOS 27.0.1 (26A434). On other shipped builds `pas` prints a note, because
libpas layouts change between releases.

## Limits

- Live processes only, no core files.
- `pas` covers the `bmalloc` and `tagged_bmalloc` heaps, where `fastMalloc`, TZone and most of
  WebKit's C++ objects live. Other memory (system malloc, the JIT heap, JavaScript objects in
  JavaScriptCore's garbage-collected heap) is reported as `not in libpas`.
- While a thread allocates from a segregated page, objects waiting in that thread's cache count
  as allocated. `info` prints a note when this applies.
- `refs` only searches allocated libpas objects, not stacks, registers or other memory.
- `explain` gives the likely cause from tags alone. A tag can match a neighbour by chance, so
  treat it as a lead.

## JavaScriptCore with MTE, from source

JavaScriptCore built from source with the public SDK leaves MTE off, because libpas's MTE code
includes two headers that only Apple's internal SDK has. `mte-headers/` has minimal versions of
both. To build with MTE on, from a WebKit checkout:

```
WEBKIT_OUTPUTDIR=$PWD/WebKitBuild-MTE Tools/Scripts/build-jsc --release \
    "OTHER_CFLAGS=\$(inherited) -DBENABLE_MTE=1 -DPAS_ENABLE_MTE=1 -isystem /path/to/pas/mte-headers"
```

Run a program against it with `DYLD_FRAMEWORK_PATH=WebKitBuild-MTE/Release`, signed with the
entitlements in `test/mte.plist`, on a Mac with MTE. Its fastMalloc allocations then come from the
`tagged_bmalloc` heap. This was tested with WebKit 814bf42b6770 on macOS 27.0.1. Apple's builds may
set other MTE options differently.

## Testing

`test/run.sh` builds a small program that allocates with `fastMalloc` and checks each command's
output, with MTE off and on. The MTE half includes real tag-check faults under LLDB, and is skipped
when the program's pointers come back untagged. Without arguments the test uses the system
JavaScriptCore, and `test/run.sh <WebKitBuild/Release>` uses one you built.

On an M6 Mac running macOS 27.0.1, the tests pass against the system JavaScriptCore, whose MTE
allocations live in the `bmalloc` heap, and against WebKit 814bf42b6770 built from source, both as
is and [with MTE on](#javascriptcore-with-mte-from-source), where MTE allocations live in the
`tagged_bmalloc` heap. Every command was also run against Safari's WebContent, GPU and Networking
processes on the same Mac, with SIP off.

Licensed under [MIT](LICENSE).
