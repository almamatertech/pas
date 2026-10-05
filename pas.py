#!/usr/bin/xcrun python3
"""pas: look up an address in WebKit's libpas heap and its MTE tags.

Inside LLDB:    command script import pas.py
                pas info <address>
                pas page <address>
From a shell:   pas.py <pid> info|page <address>

pas only reads memory. It never calls functions in the process or writes to it.
"""
import re
import struct
import subprocess
import sys

try:
    import lldb
except ImportError:
    sys.path.insert(0, subprocess.run(["xcrun", "lldb", "-P"], capture_output=True, text=True).stdout.strip())
    import lldb

# Struct offsets and page configs come from WebKit 814bf42b6770 (Source/bmalloc/libpas) and were
# checked against the shipped JavaScriptCore builds listed here.
CHECKED_BUILDS = {"E372D8E6-F575-3601-BFF2-6ECD1827918F"}  # macOS 27.0.1 (26A434)

ADDRESS_MASK = (1 << 56) - 1
TAG_GRANULE = 16
TAG_READ_LIMIT = 1024 * TAG_GRANULE  # debugserver returns at most 1024 tags per read
MEGAPAGE_SHIFT = 24
SMALL_PAGE = 0x4000

# The two bmalloc heap configs. tagged_bmalloc is the MTE heap in recent WebKit.
HEAPS = ("bmalloc", "tagged_bmalloc")

# Page kinds (pas_page_kind) and their page configs: page size, allocation unit, and where the
# first object may start. Small pages keep their header at the start of the page. Medium and marge
# pages keep it elsewhere and are found through a page header table.
PAGES = {
    1: ("small segregated", SMALL_PAGE, 16, 0xac),
    2: ("medium segregated", 0x20000, 512, 0),
    3: ("small bitfit", SMALL_PAGE, 16, 0x110),
    4: ("medium bitfit", 0x80000, 512, 0),
    5: ("marge bitfit", 0x400000, 4096, 0),
}
HEADER_TABLES = (("medium_segregated", 0x20000), ("medium_bitfit", 0x80000), ("marge", 0x400000))

# pas_segregated_page
SEGREGATED_OBJECT_SIZE = 0x4
SEGREGATED_OWNER = 0x20
SEGREGATED_ALLOC_BITS = 0x2c
SEGREGATED_IN_USE = 0x1
# pas_bitfit_page: free bits, then object end bits, one bit per allocation unit.
BITFIT_BITS = 0x10
BITFIT_BITS_BYTES = 0x80


class Reader:
    def __init__(self, target, process):
        self.target = target
        self.process = process

    def read(self, address, size):
        error = lldb.SBError()
        data = self.process.ReadMemory(address, size, error)
        if not error.Success():
            raise LookupError(f"cannot read {size} bytes at {address:#x}: {error.GetCString()}")
        return data

    def u8(self, address):
        return self.read(address, 1)[0]

    def u32(self, address):
        return struct.unpack("<I", self.read(address, 4))[0]

    def u64(self, address):
        return struct.unpack("<Q", self.read(address, 8))[0]

    def symbol(self, name):
        for context in self.target.FindSymbols(name):
            address = context.GetSymbol().GetStartAddress().GetLoadAddress(self.target)
            if address != lldb.LLDB_INVALID_ADDRESS:
                return address
        return None

    def tags(self, begin, end):
        """Memory tags of the 16-byte granules in [begin, end), or None if the memory isn't tagged."""
        tags = []
        interpreter = self.target.GetDebugger().GetCommandInterpreter()
        for chunk in range(begin, end, TAG_READ_LIMIT):
            result = lldb.SBCommandReturnObject()
            interpreter.HandleCommand(f"memory tag read {chunk:#x} {min(end, chunk + TAG_READ_LIMIT):#x}", result)
            if not result.Succeeded():
                return None
            tags += [int(tag, 16) for tag in re.findall(r"^\[0x[0-9a-f]+, 0x[0-9a-f]+\): (0x[0-9a-f]+)",
                                                        result.GetOutput(), re.M)]
        return tags


class Page:
    def __init__(self, heap, kind, boundary, header):
        self.heap = heap
        self.kind = kind
        self.boundary = boundary
        self.header = header
        self.name, self.size, self.unit, self.payload = PAGES[kind]

    @property
    def bitfit(self):
        return self.kind >= 3


def megapage_kind(reader, table, address):
    """0: not a small page, 1: small segregated, 2: small segregated or bitfit (read the header)."""
    index = address >> MEGAPAGE_SHIFT
    if index < (1 << 19) and reader.u32(table + (index >> 5) * 4) >> (index & 31) & 1:
        return 1
    instance = reader.u64(table + 0x10000)
    begin, end = reader.u64(instance), reader.u64(instance + 8)
    if not begin <= index < end:
        return 0
    index -= begin
    return reader.u32(instance + 0x18 + (index >> 4) * 4) >> ((index & 15) * 2) & 3


def header_table_lookup(reader, table, boundary):
    hashtable = reader.u64(table + 8)
    if not hashtable:
        return None
    size = reader.u32(hashtable + 8)
    entries = reader.read(hashtable + 0x20, size * 16)
    for key, value in struct.iter_unpack("<QQ", entries):
        if key == boundary:
            return value
    return None


def find_page(reader, address):
    for heap in HEAPS:
        table = reader.symbol(f"{heap}_megapage_table")
        if table is None:
            continue
        kind = megapage_kind(reader, table, address)
        if kind:
            boundary = address & ~(SMALL_PAGE - 1)
            return Page(heap, 1 if kind == 1 else reader.u8(boundary), boundary, boundary)
        for name, size in HEADER_TABLES:
            header_table = reader.symbol(f"{heap}_{name}_page_header_table")
            if header_table is None:
                continue
            boundary = address & ~(size - 1)
            header = header_table_lookup(reader, header_table, boundary)
            if header:
                return Page(heap, reader.u8(header), boundary, header)
    return None


def first_segregated_object(page, object_size):
    """Offset of a segregated page's first object: libpas packs objects against whichever end of
    the page leaves the most room (pas_segregated_page_best_hugging_mode)."""
    left_first = -(-page.payload // object_size) * object_size
    left_end = page.size // object_size * object_size
    right_first = page.size - (page.size - page.payload) // object_size * object_size
    return left_first if left_end - left_first >= page.size - right_first else right_first


def entries(reader, page):
    """The page's objects and free runs as (begin, size, state), in address order."""
    if page.bitfit:
        bits = reader.read(page.header + BITFIT_BITS, 2 * BITFIT_BITS_BYTES)
        def bit(offset, index):
            return bits[offset + index // 8] >> (index % 8) & 1
        units = page.size // page.unit
        index = page.payload // page.unit
        while index < units:
            start = index
            if bit(0, index):
                while index < units and bit(0, index):
                    index += 1
                state = "free"
            else:
                while index < units - 1 and not bit(BITFIT_BITS_BYTES, index):
                    index += 1
                index += 1
                state = "allocated"
            yield page.boundary + start * page.unit, (index - start) * page.unit, state
        return
    owner = reader.u64(page.header + SEGREGATED_OWNER)
    object_size = reader.u32(page.header + SEGREGATED_OBJECT_SIZE)
    if owner & 7 > 1 or not object_size:
        return  # A page shared by several size classes: no fixed object size.
    shift = page.unit.bit_length() - 1
    bits = reader.read(page.header + SEGREGATED_ALLOC_BITS, page.size >> shift >> 3)
    offset = first_segregated_object(page, object_size)
    while offset + object_size <= page.size:
        index = offset >> shift
        state = "allocated" if bits[index // 8] >> (index % 8) & 1 else "free"
        yield page.boundary + offset, object_size, state
        offset += object_size


def show_tags(tags):
    if tags is None:
        return "not tagged"
    if len(tags) > 8 and len(set(tags)) == 1:
        return f"{tags[0]:x} x{len(tags)}"
    text = " ".join(f"{tag:x}" for tag in tags[:8])
    return text + (f" ... ({len(tags)} granules)" if len(tags) > 8 else "")


def size_text(size):
    return f"{size // 1024} KiB" if size >= 1024 and size % 1024 == 0 else f"{size} bytes"


def check_build(target, out):
    for module in target.module_iter():
        if module.GetFileSpec().GetFilename() == "JavaScriptCore":
            uuid = module.GetUUIDString()
            if uuid not in CHECKED_BUILDS:
                out.append(f"note: pas hasn't been checked against JavaScriptCore {uuid}")
            return


def info(reader, pointer, out):
    address = pointer & ADDRESS_MASK
    tag = pointer >> 56 & 0xf
    out.append(f"pointer   {pointer:#018x}   tag {tag:x}")
    page = find_page(reader, address)
    entry = None
    if page:
        out.append(f"heap      {page.heap}, {page.name} page")
        out.append(f"page      {page.boundary:#x}   {size_text(page.size)}")
        if address < page.boundary + page.payload:
            out.append("object    none, the address is in the page header")
        else:
            rows = list(entries(reader, page))
            entry = next((e for e in rows if e[0] <= address < e[0] + e[1]), None)
            if not rows:
                out.append("object    unknown, the page is shared by several object sizes")
            elif not entry:
                out.append("object    none, the address is in padding between the page's objects")
            else:
                begin, size, state = entry
                out.append(f"object    {begin:#x} - {begin + size:#x}   {size} bytes, {state}")
                out.append(f"offset    +{address - begin:#x}")
                if not page.bitfit and state == "allocated" and reader.u8(page.header + SEGREGATED_IN_USE):
                    out.append("note      a thread is allocating from this page, so some allocated slots "
                               "may be free in its cache")
    else:
        out.append("heap      not in a bmalloc page (a large object, system malloc, or other memory)")
    begin, end = (entry[0], entry[0] + entry[1]) if entry else (address, address + 1)
    begin &= ~(TAG_GRANULE - 1)
    tags = reader.tags(begin, end)
    out.append(f"memory    {show_tags(tags)}")
    if tags is None:
        out.append("result    address not tagged")
        return
    memory_tag = tags[(address - begin) // TAG_GRANULE]
    out.append("result    tags match" if memory_tag == tag
               else f"result    tags differ: pointer {tag:x}, memory {memory_tag:x}")


def page_listing(reader, pointer, out, around=8):
    address = pointer & ADDRESS_MASK
    page = find_page(reader, address)
    if not page:
        out.append(f"{address:#x} is not in a bmalloc page")
        return
    out.append(f"page {page.boundary:#x}   {page.heap}, {page.name}, {size_text(page.size)}")
    rows = list(entries(reader, page))
    if not rows:
        out.append("objects unknown, the page is shared by several object sizes")
        return
    here = next((i for i, (begin, size, _) in enumerate(rows) if begin <= address < begin + size), 0)
    first, last = max(0, here - around), min(len(rows), here + around + 1)
    shown = rows[first:last]
    tags = reader.tags(shown[0][0], shown[-1][0] + shown[-1][1])
    out.append("")
    out.append(f"{'address':<14}{'bytes':>7}  {'state':<10} tags")
    for begin, size, state in shown:
        own = None if tags is None else tags[(begin - shown[0][0]) // TAG_GRANULE:
                                              (begin + size - shown[0][0]) // TAG_GRANULE]
        marker = f"   <- {pointer:#018x}" if begin <= address < begin + size else ""
        out.append(f"{begin:<#14x}{size:>7}  {state:<10} {show_tags(own)}{marker}")
    out.append(f"({last - first} of {len(rows)} entries)")


COMMANDS = {"info": info, "page": page_listing}
USAGE = "usage: pas info|page <address>"


def run(target, process, command, value, out):
    check_build(target, out)
    try:
        COMMANDS[command](Reader(target, process), value, out)
    except LookupError as error:
        out.append(f"error: {error}")


def lldb_command(debugger, arguments, result, _):
    words = arguments.split(None, 1)
    if len(words) != 2 or words[0] not in COMMANDS:
        result.SetError(USAGE)
        return
    target = debugger.GetSelectedTarget()
    frame = target.GetProcess().GetSelectedThread().GetSelectedFrame()
    value = frame.EvaluateExpression(words[1]) if frame.IsValid() else target.EvaluateExpression(words[1])
    if not value.GetError().Success():
        result.SetError(f"cannot evaluate {words[1]}: {value.GetError().GetCString()}")
        return
    out = []
    run(target, target.GetProcess(), words[0], value.GetValueAsUnsigned(), out)
    result.AppendMessage("\n".join(out))


def __lldb_init_module(debugger, _):
    debugger.HandleCommand(f"command script add -o -f {__name__}.lldb_command pas")


def main(arguments):
    if len(arguments) != 3 or arguments[1] not in COMMANDS:
        sys.exit("usage: pas.py <pid> info|page <address>")
    pid, command, address = int(arguments[0]), arguments[1], int(arguments[2], 0)
    debugger = lldb.SBDebugger.Create()
    debugger.SetAsync(False)
    target = debugger.CreateTarget("")
    error = lldb.SBError()
    process = target.AttachToProcessWithID(debugger.GetListener(), pid, error)
    if not error.Success():
        sys.exit(f"cannot attach to {pid}: {error.GetCString()}")
    out = []
    try:
        run(target, process, command, address, out)
    finally:
        process.Detach()
    print("\n".join(out))


if __name__ == "__main__":
    main(sys.argv[1:])
