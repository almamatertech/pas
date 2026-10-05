#!/usr/bin/xcrun python3
"""pas: inspect WebKit's libpas heap, and MTE tags, from LLDB.

Inside LLDB:    command script import pas.py
                pas info|page|refs|explain <address>
                pas heap|log
                pas explain               (at a tag-check fault)
From a shell:   pas.py <pid> info|page|refs|explain <address>
                pas.py <pid> heap|log

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

# Struct layouts for builds without debug info for libpas, as shipped builds are. They match the
# JavaScriptCore in macOS 27.0.1 (26A434), checked against its disassembly and against libpas just
# before WebKit c8cb35beacac, which later changed pas_heap. Builds with debug info use their own.
CHECKED_BUILDS = {"E372D8E6-F575-3601-BFF2-6ECD1827918F"}
LAYOUT = {
    "pas_heap_config": {"small_segregated_config": 0x38, "medium_segregated_config": 0xf0,
                        "small_bitfit_config": 0x1a8, "medium_bitfit_config": 0x250, "marge_bitfit_config": 0x2f8},
    "pas_segregated_page_config": {"base.is_enabled": 0x0, "base.min_align_shift": 0x20, "base.page_size": 0x28,
                                   "exclusive_payload_offset": 0x88},
    "pas_bitfit_page_config": {"base.is_enabled": 0x0, "base.min_align_shift": 0x20, "base.page_size": 0x28,
                               "page_object_payload_offset": 0x70},
    "pas_fast_megapage_table": {"instances": 0x10000},
    "pas_fast_megapage_table_impl": {"index_begin": 0x0, "index_end": 0x8, "bits": 0x18},
    "pas_page_header_table": {"page_size": 0x0, "hashtable": 0x8},
    "pas_lock_free_read_ptr_ptr_hashtable_table": {"table_size": 0x8, "array": 0x20},
    "pas_segregated_page": {"is_in_use_for_allocation": 0x1, "object_size": 0x4, "owner": 0x20, "alloc_bits": 0x2c},
    "pas_bitfit_page": {"owner": 0x4, "bits": 0x10},
    "pas_segregated_exclusive_view": {"page_boundary": 0x0, "directory": 0x8, "is_owned": 0xb},
    "pas_bitfit_view": {"page_boundary": 0x0, "directory": 0x8, "is_owned": 0xb},
    "pas_segregated_size_directory": {"heap": 0x10},
    "pas_bitfit_directory": {"heap": 0x30},
    "pas_segregated_heap": {"parent_heap": 0x8},
    "pas_heap": {"megapage_large_heap": 0x30, "large_heap": 0x48, "type": 0x60, "heap_ref": 0x68},
    "pas_large_heap": {"is_megapage_heap": 0x14},
    "bmalloc_type": {"size": 0x0, "name": 0x8},
    "pas_large_map": {"large_map_hashtable": 0x0, "small_large_map_hashtable": 0x38, "tiny_large_map_hashtable": 0x70},
    "pas_large_map_hashtable": {"table": 0x0, "table_size": 0x8},
    "pas_first_level_tiny_large_map_entry": {"hashtable": 0x8},
    "pas_thread_local_cache_node": {"next": 0x8, "cache": 0x18},
    "pas_thread_local_cache": {"deallocation_log": 0x0, "deallocation_log_index": 0x320, "node": 0x330,
                               "thread": 0x348},
}
SIZES = {"bmalloc_type": 0x10, "pas_large_map": 0xc8, "pas_large_map_entry": 0x20, "pas_small_large_map_entry": 0xc,
         "pas_tiny_large_map_entry": 0x5, "pas_first_level_tiny_large_map_entry": 0x10}

ADDRESS_MASK = (1 << 56) - 1
TAG_GRANULE = 16
TAG_READ_LIMIT = 1024 * TAG_GRANULE  # debugserver returns at most 1024 tags per read
MEGAPAGE_SHIFT = 24
MIN_ALIGN_SHIFT = 4  # PAS_MIN_ALIGN_SHIFT, used by the packed large map entries
EXC_ARM_MTE_TAGCHECK_FAIL = 0x106
LOG_ADDRESS_MASK = (1 << 48) - 1  # deallocation log entries keep the page config kind above bit 48
LOG_LIMIT = 1024  # PAS_DEALLOCATION_LOG_SIZE is 100, so a much larger index isn't real

HEAP_CONFIGS = ("bmalloc", "tagged_bmalloc")
# pas_page_kind values and the heap config member that describes each kind of page.
PAGE_KINDS = {1: ("small segregated", "small_segregated_config"), 2: ("medium segregated", "medium_segregated_config"),
              3: ("small bitfit", "small_bitfit_config"), 4: ("medium bitfit", "medium_bitfit_config"),
              5: ("marge bitfit", "marge_bitfit_config")}
HEADER_TABLES = ("medium_segregated", "medium_bitfit", "marge")


class LayoutError(Exception):
    """pas doesn't know where a libpas field is in this build."""


class Reader:
    """Memory, symbols, tags and struct layouts of the target."""

    def __init__(self, target, process):
        self.target = target
        self.process = process
        self.fields = {}
        self.symbols = {}
        self.debug_info = self.target.FindFirstType("pas_segregated_page").IsValid()
        base = self.symbol("pas_compact_heap_reservation_base")
        self.compact_base = self.u64(base) if base else 0

    def read(self, address, size):
        error = lldb.SBError()
        data = self.process.ReadMemory(address, size, error) if size else b""
        if not error.Success():
            raise LookupError(f"cannot read {size} bytes at {address:#x}: {error.GetCString()}")
        return data

    def u8(self, address):
        return self.read(address, 1)[0]

    def u32(self, address):
        return struct.unpack("<I", self.read(address, 4))[0]

    def u64(self, address):
        return struct.unpack("<Q", self.read(address, 8))[0]

    def string(self, address):
        error = lldb.SBError()
        text = self.process.ReadCStringFromMemory(address, 256, error)
        return text if error.Success() else None

    def compact(self, address, size):
        """Follow a libpas compact pointer: an index of 8-byte units from the compact heap base."""
        index = int.from_bytes(self.read(address, size), "little")
        return self.compact_base + index * 8 if index else 0

    def symbol(self, name):
        if name not in self.symbols:
            self.symbols[name] = None
            for context in self.target.FindSymbols(name):
                address = context.GetSymbol().GetStartAddress().GetLoadAddress(self.target)
                if address != lldb.LLDB_INVALID_ADDRESS:
                    self.symbols[name] = address
                    break
        return self.symbols[name]

    def symbol_at(self, address):
        """The name of the symbol that starts exactly at address, if any."""
        symbol = self.target.ResolveLoadAddress(address).GetSymbol()
        if symbol.IsValid() and symbol.GetStartAddress().GetLoadAddress(self.target) == address:
            return symbol.GetName()
        return None

    def field(self, struct_name, path, optional=False):
        """Byte offset of a struct field: from debug info when the build has it, else from LAYOUT.
        An optional field may not exist in this version of libpas, and then this returns None."""
        key = (struct_name, path)
        if key not in self.fields:
            if self.debug_info:
                self.fields[key] = self.debug_field(struct_name, path)
            else:
                self.fields[key] = LAYOUT.get(struct_name, {}).get(path)
        if self.fields[key] is None and not optional:
            raise LayoutError(f"don't know where {struct_name}.{path} is in this build")
        return self.fields[key]

    def debug_type(self, struct_name):
        """The complete definition of a struct in the debug info. Some lookups only find a
        declaration, and some structs are defined as __name and typedef'd."""
        for name in (struct_name, "__" + struct_name):
            for kind in self.target.FindTypes(name):
                kind = kind.GetCanonicalType()
                if kind.GetNumberOfFields():
                    return kind
        return None

    def debug_field(self, struct_name, path):
        kind = self.debug_type(struct_name)
        if kind is None:
            return None
        bits = 0
        for name in path.split("."):
            member = next((kind.GetFieldAtIndex(i) for i in range(kind.GetNumberOfFields())
                           if kind.GetFieldAtIndex(i).GetName() == name), None)
            if member is None:
                return None
            bits += member.GetOffsetInBits()
            kind = member.GetType().GetCanonicalType()
        return bits // 8

    def size(self, struct_name):
        kind = self.debug_type(struct_name) if self.debug_info else None
        return kind.GetByteSize() if kind else SIZES[struct_name]

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


class PageConfig:
    def __init__(self, reader, heap_config, kind):
        self.name, member = PAGE_KINDS[kind]
        self.bitfit = kind >= 3
        struct_name = "pas_bitfit_page_config" if self.bitfit else "pas_segregated_page_config"
        base = heap_config + reader.field("pas_heap_config", member)
        self.enabled = reader.u8(base + reader.field(struct_name, "base.is_enabled"))
        self.shift = reader.u8(base + reader.field(struct_name, "base.min_align_shift"))
        self.unit = 1 << self.shift
        self.size = reader.u64(base + reader.field(struct_name, "base.page_size"))
        payload = "page_object_payload_offset" if self.bitfit else "exclusive_payload_offset"
        self.payload = reader.u64(base + reader.field(struct_name, payload))


class HeapConfig:
    """One libpas heap config (bmalloc or tagged_bmalloc): its page configs and lookup tables."""

    def __init__(self, reader, name):
        self.name = name
        address = reader.symbol(f"{name}_heap_config")
        self.pages = {kind: PageConfig(reader, address, kind) for kind in PAGE_KINDS}
        self.megapage_table = reader.symbol(f"{name}_megapage_table")
        self.header_tables = [table for table in (reader.symbol(f"{name}_{kind}_page_header_table")
                                                  for kind in HEADER_TABLES) if table]


class Page:
    def __init__(self, config, kind, boundary, header):
        self.config = config
        self.kind = kind
        self.boundary = boundary
        self.header = header
        self.page_config = config.pages[kind]

    def __getattr__(self, name):
        return getattr(self.page_config, name)


class Libpas:
    """Read-only access to libpas's heap structures."""

    def __init__(self, reader):
        self.reader = reader
        self.configs = [HeapConfig(reader, name) for name in HEAP_CONFIGS
                        if reader.symbol(f"{name}_heap_config") and reader.symbol(f"{name}_megapage_table")]
        if not self.configs:
            raise LookupError("libpas's bmalloc heap isn't in this process")
        self.large = None
        self.logs = None
        self.logged_objects = None
        self.full_heaps = set()

    # Finding pages.

    def megapage_kinds(self, config):
        """Megapage index -> 1 (small segregated) or 2 (small segregated or bitfit, read the header)."""
        r = self.reader
        table = config.megapage_table
        instances = r.field("pas_fast_megapage_table", "instances")
        kinds = {}
        fast_bits = r.read(table, instances)
        for byte_index, byte in enumerate(fast_bits):
            for bit in range(8) if byte else ():
                if byte >> bit & 1:
                    kinds[byte_index * 8 + bit] = 1
        impl = r.u64(table + instances)
        begin = r.u64(impl + r.field("pas_fast_megapage_table_impl", "index_begin"))
        end = r.u64(impl + r.field("pas_fast_megapage_table_impl", "index_end"))
        bits = r.read(impl + r.field("pas_fast_megapage_table_impl", "bits"), ((end - begin) * 2 + 31) // 32 * 4)
        for index in range(end - begin):
            kind = bits[index // 4] >> (index % 4 * 2) & 3
            if kind:
                kinds.setdefault(begin + index, kind)
        return kinds

    def header_table(self, table):
        """(boundary, header) for every live page in a page header table."""
        r = self.reader
        hashtable = r.u64(table + r.field("pas_page_header_table", "hashtable"))
        if not hashtable:
            return []
        size = r.u32(hashtable + r.field("pas_lock_free_read_ptr_ptr_hashtable_table", "table_size"))
        entries = r.read(hashtable + r.field("pas_lock_free_read_ptr_ptr_hashtable_table", "array"), size * 16)
        # Removed pages keep their key with a NULL header, and empty slots have the key all ones.
        return [(key, value) for key, value in struct.iter_unpack("<QQ", entries) if value and key != (1 << 64) - 1]

    def page(self, config, kind, boundary, header):
        """A Page, or None if the header doesn't hold a page kind this heap config uses."""
        if kind not in PAGE_KINDS or not config.pages[kind].enabled:
            return None
        return Page(config, kind, boundary, header)

    def small_page(self, config, boundary, megapage_kind):
        kind = 1 if megapage_kind == 1 else self.reader.u8(boundary)
        return self.page(config, kind, boundary, boundary)

    def find_page(self, address):
        r = self.reader
        for config in self.configs:
            index = address >> MEGAPAGE_SHIFT
            kind = self.megapage_kind(config, index)
            if kind:
                return self.small_page(config, address & ~(config.pages[1].size - 1), kind)
            for table in config.header_tables:
                size = r.u64(table + r.field("pas_page_header_table", "page_size"))
                for boundary, header in self.header_table(table):
                    if boundary == address & ~(size - 1):
                        return self.page(config, r.u8(header), boundary, header)
        return None

    def megapage_kind(self, config, index):
        r = self.reader
        table = config.megapage_table
        instances = r.field("pas_fast_megapage_table", "instances")
        if index < instances * 8 and r.u32(table + (index >> 5) * 4) >> (index & 31) & 1:
            return 1
        impl = r.u64(table + instances)
        begin = r.u64(impl + r.field("pas_fast_megapage_table_impl", "index_begin"))
        end = r.u64(impl + r.field("pas_fast_megapage_table_impl", "index_end"))
        if not begin <= index < end:
            return 0
        index -= begin
        bits = impl + r.field("pas_fast_megapage_table_impl", "bits")
        return r.u32(bits + (index >> 4) * 4) >> ((index & 15) * 2) & 3

    def all_pages(self):
        """Every page libpas currently owns, in both heap configs."""
        r = self.reader
        for config in self.configs:
            small = config.pages[1].size
            for index, kind in sorted(self.megapage_kinds(config).items()):
                for boundary in range(index << MEGAPAGE_SHIFT, (index + 1) << MEGAPAGE_SHIFT, small):
                    page = self.small_page(config, boundary, kind)
                    if page and page.kind in (1, 3) and self.is_live(page):
                        yield page
            for table in config.header_tables:
                for boundary, header in self.header_table(table):
                    page = self.page(config, r.u8(header), boundary, header)
                    if page and self.is_live(page):
                        yield page

    # Owners and heaps.

    def directory(self, page):
        """The page's directory: a bitfit directory, or a segregated size directory."""
        r = self.reader
        if page.bitfit:
            view = r.compact(page.header + r.field("pas_bitfit_page", "owner"), 4)
            return r.compact(view + r.field("pas_bitfit_view", "directory"), 3) if view else 0
        owner = r.u64(page.header + r.field("pas_segregated_page", "owner"))
        if owner & 7 > 1:  # The page belongs to its size directory directly.
            return owner & ~7
        view = owner & ~7
        return r.compact(view + r.field("pas_segregated_exclusive_view", "directory"), 3) if view else 0

    def is_live(self, page):
        """Whether a page is in use, which means its view owns it. Pages whose memory libpas gave
        back can keep old headers."""
        r = self.reader
        if page.bitfit:
            view = r.compact(page.header + r.field("pas_bitfit_page", "owner"), 4)
            struct_name = "pas_bitfit_view"
        else:
            owner = r.u64(page.header + r.field("pas_segregated_page", "owner"))
            if owner & 7 > 1:
                return r.u32(page.header + r.field("pas_segregated_page", "object_size")) > 0
            view = owner & ~7
            struct_name = "pas_segregated_exclusive_view"
        try:
            return bool(view) and r.u64(view + r.field(struct_name, "page_boundary")) == page.boundary \
                and r.u8(view + r.field(struct_name, "is_owned"))
        except LookupError:
            return False

    def owner(self, page):
        """The heap a page belongs to: its pas_heap, or its segregated heap if that has no parent."""
        r = self.reader
        directory = self.directory(page)
        if not directory:
            return 0
        struct_name = "pas_bitfit_directory" if page.bitfit else "pas_segregated_size_directory"
        segregated_heap = r.u64(directory + r.field(struct_name, "heap"))
        heap = r.u64(segregated_heap + r.field("pas_segregated_heap", "parent_heap")) if segregated_heap else 0
        if heap:
            self.full_heaps.add(heap)
            return heap
        return segregated_heap

    def large_owner(self, large_heap):
        """The pas_heap of a large heap. Older libpas gives each heap a second, megapage large heap."""
        r = self.reader
        if not large_heap:
            return 0
        flag = r.field("pas_large_heap", "is_megapage_heap", optional=True)
        member = "megapage_large_heap" if flag is not None and r.u8(large_heap + flag) else "large_heap"
        heap = large_heap - r.field("pas_heap", member)
        self.full_heaps.add(heap)
        return heap

    def name(self, heap):
        """A heap's name: its type's name, or its symbol for a static heap without one.

        A TZone bucket (TZoneHeapManager::Bucket) keeps its heap ref right after its type. Release
        builds name each bucket with a running number, written 6 bits per character from "0", lowest
        first, so pas decodes it and adds the object size the bucket serves. Builds with
        TZONE_VERBOSE_DEBUG name buckets "TZ_...", and pas keeps those names."""
        r = self.reader
        if not heap:
            return "unknown heap"
        if heap in self.full_heaps:
            heap_type = r.u64(heap + r.field("pas_heap", "type"))
            name = r.string(r.u64(heap_type + r.field("bmalloc_type", "name"))) if heap_type else None
            if name and r.u64(heap + r.field("pas_heap", "heap_ref")) == heap_type + r.size("bmalloc_type"):
                if not name.startswith("TZ_"):
                    name = f"bucket {sum(ord(c) - ord('0') << 6 * i for i, c in enumerate(name))}"
                return f"TZone {name}, {r.u32(heap_type + r.field('bmalloc_type', 'size'))}-byte types"
            if name:
                return name
        return r.symbol_at(heap) or f"heap {heap:#x}"

    # Objects.

    def entries(self, page):
        """The page's objects and free runs as (begin, size, state), in address order."""
        r = self.reader
        units = page.size >> page.shift
        if page.bitfit:
            words = (units + 63) // 64 * 8
            bits = r.read(page.header + r.field("pas_bitfit_page", "bits"), 2 * words)

            def bit(offset, index):
                return bits[offset + index // 8] >> (index % 8) & 1
            index = page.payload >> page.shift
            while index < units:
                start = index
                if bit(0, index):
                    while index < units and bit(0, index):
                        index += 1
                    state = "free"
                else:
                    while index < units - 1 and not bit(words, index):
                        index += 1
                    index += 1
                    state = "allocated"
                yield page.boundary + (start << page.shift), (index - start) << page.shift, state
            return
        object_size = r.u32(page.header + r.field("pas_segregated_page", "object_size"))
        if not object_size:
            return
        bits = r.read(page.header + r.field("pas_segregated_page", "alloc_bits"), (units + 31) // 32 * 4)
        offset = first_segregated_object(page, object_size)
        while offset + object_size <= page.size:
            index = offset >> page.shift
            state = "allocated" if bits[index // 8] >> (index % 8) & 1 else "free"
            if state == "allocated" and page.boundary + offset in self.logged():
                state = "logged"
            yield page.boundary + offset, object_size, state
            offset += object_size

    def deallocation_logs(self):
        """(thread, object addresses newest first) for each thread cache's pending frees.

        Freeing an object on a segregated page appends it to the thread's deallocation log, and libpas
        updates the page in batches. Until then the page still marks the object allocated."""
        if self.logs is None:
            self.logs = list(self.read_deallocation_logs())
        return self.logs

    def read_deallocation_logs(self):
        r = self.reader
        first = r.symbol("pas_thread_local_cache_node_first")
        node = r.u64(first) if first else 0
        seen = set()
        while node and node not in seen:
            seen.add(node)
            cache = r.u64(node + r.field("pas_thread_local_cache_node", "cache"))
            if cache and r.u64(cache + r.field("pas_thread_local_cache", "node")) == node:
                count = r.u32(cache + r.field("pas_thread_local_cache", "deallocation_log_index"))
                if count <= LOG_LIMIT:
                    log = r.read(cache + r.field("pas_thread_local_cache", "deallocation_log"), count * 8)
                    entries = [word & LOG_ADDRESS_MASK for (word,) in struct.iter_unpack("<Q", log) if word]
                    yield self.thread_name(r.u64(cache + r.field("pas_thread_local_cache", "thread"))), entries[::-1]
            node = r.u64(node + r.field("pas_thread_local_cache_node", "next"))

    def thread_name(self, pthread):
        """LLDB's name for the thread behind a pthread_t. libpthread keeps the thread's ID in its
        pthread struct, so pas looks for each LLDB thread's ID there."""
        try:
            words = set(word for (word,) in struct.iter_unpack("<Q", self.reader.read(pthread, 512)))
        except LookupError:
            words = set()
        for thread in self.reader.process:
            if thread.GetThreadID() in words:
                return f"thread {thread.GetIndexID()}"
        return f"pthread {pthread:#x}"

    def logged(self):
        """Object address -> thread, for objects waiting in a deallocation log."""
        if self.logged_objects is None:
            self.logged_objects = {begin: thread for thread, entries in self.deallocation_logs() for begin in entries}
        return self.logged_objects

    def large_objects(self):
        """(begin, end, pas_large_heap*) for every large object in libpas's large maps."""
        if self.large is None:
            self.large = list(self.read_large_maps())
        return self.large

    def read_large_maps(self):
        r = self.reader
        maps = r.symbol("pas_large_maps")
        heap_table = r.symbol("pas_heap_table")
        heap_table = r.u64(heap_table) if heap_table else 0
        if not maps:
            return
        for variant in range(2):
            large_map = maps + variant * r.size("pas_large_map")
            table = large_map + r.field("pas_large_map", "large_map_hashtable")
            for begin, end, heap in self.hashtable(table, r.size("pas_large_map_entry"), "<QQQ"):
                if begin > 1:
                    yield begin, end, heap
            table = large_map + r.field("pas_large_map", "small_large_map_hashtable")
            for begin, size, heap in self.hashtable(table, r.size("pas_small_large_map_entry"), "<III"):
                if begin > 1:
                    yield begin << MIN_ALIGN_SHIFT, (begin + size) << MIN_ALIGN_SHIFT, heap * 8
            table = large_map + r.field("pas_large_map", "tiny_large_map_hashtable")
            for base, second in self.hashtable(table, r.size("pas_first_level_tiny_large_map_entry"), "<QQ"):
                if base <= 1 or not second:
                    continue
                for raw in self.hashtable(second, r.size("pas_tiny_large_map_entry"), None):
                    if not any(raw[1:]) and raw[0] <= 1:
                        continue
                    begin = base + ((raw[0] | (raw[1] & 0xf) << 8) << MIN_ALIGN_SHIFT)
                    size = (raw[1] >> 4 | raw[2] << 4) << MIN_ALIGN_SHIFT
                    yield begin, begin + size, r.u64(heap_table + (raw[3] | raw[4] << 8) * 8) if heap_table else 0

    def hashtable(self, address, entry_size, layout):
        r = self.reader
        table = r.u64(address + r.field("pas_large_map_hashtable", "table"))
        size = r.u32(address + r.field("pas_large_map_hashtable", "table_size"))
        if not table or not size:
            return
        data = r.read(table, size * entry_size)
        for index in range(size):
            raw = data[index * entry_size:(index + 1) * entry_size]
            yield struct.unpack_from(layout, raw) if layout else raw

    def locate(self, address):
        """Where an address is: (page, rows, row) for page objects, (None, None, row) for large objects."""
        page = self.find_page(address)
        if page:
            rows = list(self.entries(page))
            return page, rows, next((row for row in rows if row[0] <= address < row[0] + row[1]), None)
        for begin, end, heap in self.large_objects():
            if begin <= address < end:
                return None, None, (begin, end - begin, "allocated", heap)
        return None, None, None


def first_segregated_object(page, object_size):
    """Offset of a segregated page's first object: libpas packs objects against whichever end of
    the page leaves the most room (pas_segregated_page_best_hugging_mode)."""
    left_first = -(-page.payload // object_size) * object_size
    left_end = page.size // object_size * object_size
    right_first = page.size - (page.size - page.payload) // object_size * object_size
    return left_first if left_end - left_first >= page.size - right_first else right_first


def show_tags(tags):
    if tags is None:
        return "not tagged"
    if len(tags) > 8 and len(set(tags)) == 1:
        return f"{tags[0]:x} x{len(tags)}"
    text = " ".join(f"{tag:x}" for tag in tags[:8])
    return text + (f" ... ({len(tags)} granules)" if len(tags) > 8 else "")


def size_text(size):
    if size >= 1024 * 1024 and size % (1024 * 1024) == 0:
        return f"{size >> 20} MiB"
    return f"{size >> 10} KiB" if size >= 1024 and size % 1024 == 0 else f"{size} bytes"


def tag_of(pointer):
    return pointer >> 56 & 0xf


# Commands. Each takes a Libpas, its arguments and a list of output lines to append to.

def describe(heap, pointer, out):
    """The lines info and explain share. Returns (page, rows, row)."""
    address = pointer & ADDRESS_MASK
    out.append(f"pointer   {pointer:#018x}   tag {tag_of(pointer):x}")
    page, rows, row = heap.locate(address)
    if page:
        out.append(f"heap      {heap.name(heap.owner(page))} ({page.config.name})")
        out.append(f"page      {page.boundary:#x}   {page.name}, {size_text(page.size)}")
        if address < page.boundary + page.payload:
            out.append("object    none, the address is in the page header")
        elif not rows:
            out.append("object    unknown, the page doesn't record an object size")
        elif not row:
            out.append("object    none, the address is in padding between the page's objects")
    elif row:
        out.append(f"heap      {heap.name(heap.large_owner(row[3]))} (large object)")
    else:
        out.append("heap      not in libpas (system malloc, a stack, or other memory)")
    if row:
        begin, size, state = row[:3]
        if state == "logged":
            state = f"freed, waiting in {heap.logged()[begin]}'s deallocation log"
        out.append(f"object    {begin:#x} - {begin + size:#x}   {size} bytes, {state}")
        out.append(f"offset    +{address - begin:#x}")
        if page and not page.bitfit and state == "allocated" and \
                heap.reader.u8(page.header + heap.reader.field("pas_segregated_page", "is_in_use_for_allocation")):
            out.append("note      a thread is allocating from this page, so some allocated slots "
                       "may be free in its cache")
    return page, rows, row


def info(heap, arguments, out):
    pointer = arguments[0]
    address = pointer & ADDRESS_MASK
    page, rows, row = describe(heap, pointer, out)
    begin, end = (row[0], row[0] + row[1]) if row else (address, address + 1)
    begin &= ~(TAG_GRANULE - 1)
    tags = heap.reader.tags(begin, end)
    out.append(f"memory    {show_tags(tags)}")
    if tags is None:
        out.append("result    address not tagged")
        return
    memory_tag = tags[(address - begin) // TAG_GRANULE]
    out.append("result    tags match" if memory_tag == tag_of(pointer)
               else f"result    tags differ: pointer {tag_of(pointer):x}, memory {memory_tag:x}")


def page_listing(heap, arguments, out, around=8):
    pointer = arguments[0]
    address = pointer & ADDRESS_MASK
    page = heap.find_page(address)
    if not page:
        out.append(f"{address:#x} is not in a libpas page")
        return
    out.append(f"page {page.boundary:#x}   {heap.name(heap.owner(page))} ({page.config.name}), "
               f"{page.name}, {size_text(page.size)}")
    rows = list(heap.entries(page))
    if not rows:
        out.append("objects unknown, the page doesn't record an object size")
        return
    here = next((i for i, (begin, size, _) in enumerate(rows) if begin <= address < begin + size), 0)
    first, last = max(0, here - around), min(len(rows), here + around + 1)
    shown = rows[first:last]
    tags = heap.reader.tags(shown[0][0], shown[-1][0] + shown[-1][1])
    out.append("")
    out.append(f"{'address':<14}{'bytes':>8}  {'state':<10} tags")
    for begin, size, state in shown:
        own = None if tags is None else tags[(begin - shown[0][0]) // TAG_GRANULE:
                                              (begin + size - shown[0][0]) // TAG_GRANULE]
        marker = f"   <- {pointer:#018x}" if begin <= address < begin + size else ""
        out.append(f"{begin:<#14x}{size:>8}  {state:<10} {show_tags(own)}{marker}")
    out.append(f"({last - first} of {len(rows)} entries)")
    if any(state == "logged" for _, _, state in shown):
        out.append("(logged: freed, but waiting in a thread's deallocation log, see pas log)")


def heap_walk(heap, arguments, out):
    """Every libpas heap with its pages, objects and bytes in use. Large objects live outside pages,
    so they count toward their heap's objects and bytes, and the last column says how many there are."""
    totals = {}
    for page in heap.all_pages():
        row = totals.setdefault(heap.owner(page), [0, 0, 0, 0, 0])
        row[0] += 1
        row[1] += page.size
        for _, size, state in heap.entries(page):
            if state == "allocated":
                row[2] += 1
                row[3] += size
    for begin, end, large_heap in heap.large_objects():
        row = totals.setdefault(heap.large_owner(large_heap), [0, 0, 0, 0, 0])
        row[2] += 1
        row[3] += end - begin
        row[4] += 1
    names = {owner: heap.name(owner) for owner in totals}
    width = max([len(name) for name in names.values()] + [4])
    out.append(f"{'heap':<{width}}  {'pages':>6} {'page bytes':>11} {'objects':>8} {'in use':>11} {'large':>6}")
    for owner, (pages, page_bytes, objects, used, large) in sorted(totals.items(), key=lambda item: -item[1][3]):
        out.append(f"{names[owner]:<{width}}  {pages:>6} {page_bytes:>11} {objects:>8} {used:>11} {large:>6}")
    sums = [sum(row[i] for row in totals.values()) for i in range(5)]
    out.append(f"{'total':<{width}}  {sums[0]:>6} {sums[1]:>11} {sums[2]:>8} {sums[3]:>11} {sums[4]:>6}")
    out.append(f"({len(totals)} heap{'' if len(totals) == 1 else 's'}. Objects and bytes in use include large "
               "objects, which libpas keeps outside pages.)")


def deallocation_log(heap, arguments, out):
    """Each thread's freed objects that libpas hasn't returned to their pages yet."""
    logs = heap.deallocation_logs()
    for thread, entries in logs:
        out.append(f"{thread}: {len(entries)} pending free{'' if len(entries) == 1 else 's'}")
        for begin in entries:
            page, _, row = heap.locate(begin)
            detail = f"{row[1]} bytes   {heap.name(heap.owner(page))}, {page.name}" if page and row \
                else "not in a libpas page"
            out.append(f"  {begin:#x}   {detail}")
    if not logs:
        out.append("no libpas thread caches")
    out.append("(newest first, and libpas returns these objects to their pages in batches)")


def refs(heap, arguments, out, limit=100):
    """Allocated libpas objects holding a pointer into the object at the address."""
    pointer = arguments[0]
    address = pointer & ADDRESS_MASK
    _, _, row = heap.locate(address)
    begin, end = (row[0], row[0] + row[1]) if row else (address, address + 1)
    out.append(f"pointers to {begin:#x} - {end:#x}, in allocated libpas objects:")
    found = 0
    for name, objects in referencing_candidates(heap):
        for object_begin, data in objects:
            if object_begin <= address < object_begin + len(data):
                continue
            for offset in range(0, len(data) - 7, 8):
                value = int.from_bytes(data[offset:offset + 8], "little") & ADDRESS_MASK
                if begin <= value < end:
                    found += 1
                    if found <= limit:
                        out.append(f"  {object_begin + offset:#x}   object {object_begin:#x} +{offset:#x}  "
                                   f"({name}) -> +{value - begin:#x}")
    if found > limit:
        out.append(f"  ... {found - limit} more")
    out.append(f"({found} found)")


def referencing_candidates(heap):
    r = heap.reader
    for page in heap.all_pages():
        name = heap.name(heap.owner(page))
        memory = r.read(page.boundary, page.size)
        yield name, [(begin, memory[begin - page.boundary:begin - page.boundary + size])
                     for begin, size, state in heap.entries(page) if state == "allocated"]
    for begin, end, large_heap in heap.large_objects():
        try:
            yield heap.name(heap.large_owner(large_heap)), [(begin, r.read(begin, end - begin))]
        except LookupError:
            continue


def explain(heap, arguments, out):
    """Why a pointer's tag doesn't match its memory, and the likely bug."""
    pointer = arguments[0]
    if len(arguments) > 1:
        out.append(f"fault     {arguments[1].splitlines()[0]}")
    address = pointer & ADDRESS_MASK
    tag = tag_of(pointer)
    page, rows, row = describe(heap, pointer, out)
    tags = heap.reader.tags(address & ~(TAG_GRANULE - 1), address + 1)
    if tags is None:
        out.append("result    address not tagged, so MTE doesn't check accesses to it")
        return
    memory = tags[0]
    out.append(f"memory    {memory:x}")
    if memory == tag:
        out.append("result    tags match, so this access doesn't fault")
        return
    out.append(f"result    tags differ: pointer {tag:x}, memory {memory:x}")
    neighbours = []
    if rows:
        index = next((i for i, r in enumerate(rows) if r[0] > address), len(rows))
        if row:
            index = rows.index(row)
            neighbours = [(rows[index - 1], "after") if index else None,
                          (rows[index + 1], "before") if index + 1 < len(rows) else None]
        else:
            neighbours = [(rows[index - 1], "after") if index else None,
                          (rows[index], "before") if index < len(rows) else None]
    for neighbour, where in filter(None, neighbours):
        begin, size, state = neighbour
        neighbour_tags = heap.reader.tags(begin, begin + TAG_GRANULE)
        if neighbour_tags and neighbour_tags[0] == tag:
            distance = address - (begin + size) if where == "after" else begin - address
            side = "past the end of" if where == "after" else "before the start of"
            how_far = "just" if distance == 0 and where == "after" else f"{distance} bytes"
            out.append(f"cause     likely out of bounds: the {state} {size}-byte object at {begin:#x} has the "
                       f"pointer's tag, and the address is {how_far} {side} it")
            return
    if row and row[2] == "logged":
        out.append(f"cause     likely use after free: the object here was freed, and is waiting in "
                   f"{heap.logged()[row[0]]}'s deallocation log")
    elif row and row[2] == "free":
        out.append("cause     likely use after free: the object here is free, and libpas retagged its memory "
                   "when it was freed")
    elif row:
        out.append("cause     likely use after free: the memory here was freed and now holds another "
                   "allocation, with a new tag")
    else:
        out.append("cause     the address isn't inside a libpas object")


def fault_from_stop(target):
    """The faulting pointer and description, if the selected thread stopped at a tag-check fault."""
    thread = target.GetProcess().GetSelectedThread()
    if thread.GetStopReason() != lldb.eStopReasonException:
        return None
    data = [thread.GetStopReasonDataAtIndex(i) for i in range(thread.GetStopReasonDataCount())]
    description = thread.GetStopDescription(256)
    if len(data) >= 3 and data[1] == EXC_ARM_MTE_TAGCHECK_FAIL:
        return data[2], description
    match = re.search(r"code=262, address=(0x[0-9a-f]+)", description)
    return (int(match.group(1), 16), description) if match else None


COMMANDS = {"info": (info, 1), "page": (page_listing, 1), "refs": (refs, 1), "explain": (explain, 1),
            "heap": (heap_walk, 0), "log": (deallocation_log, 0)}
USAGE = "usage: pas info|page|refs|explain <address>, pas heap|log, or pas explain at a tag-check fault"


def check_build(reader, out):
    if reader.debug_info:
        return
    address = reader.symbol("bmalloc_heap_config")
    module = reader.target.ResolveLoadAddress(address).GetModule() if address else None
    uuid = module.GetUUIDString() if module else "unknown"
    if uuid not in CHECKED_BUILDS:
        out.append(f"note: no libpas debug info, and pas hasn't been checked against this "
                   f"JavaScriptCore ({uuid}), "
                   "so it assumes the layouts of the macOS 27.0.1 JavaScriptCore")


def run(target, process, command, arguments, out):
    try:
        reader = Reader(target, process)
        check_build(reader, out)
        COMMANDS[command][0](Libpas(reader), arguments, out)
    except (LookupError, LayoutError) as error:
        out.append(f"error: {error}")


def lldb_command(debugger, text, result, _):
    words = text.split(None, 1)
    target = debugger.GetSelectedTarget()
    if not words or words[0] not in COMMANDS:
        result.SetError(USAGE)
        return
    command, expression = words[0], words[1] if len(words) > 1 else None
    arguments = []
    if expression:
        frame = target.GetProcess().GetSelectedThread().GetSelectedFrame()
        value = frame.EvaluateExpression(expression) if frame.IsValid() else target.EvaluateExpression(expression)
        if not value.GetError().Success():
            result.SetError(f"cannot evaluate {expression}: {value.GetError().GetCString()}")
            return
        arguments = [value.GetValueAsUnsigned()]
    elif command == "explain":
        fault = fault_from_stop(target)
        if not fault:
            result.SetError("this thread didn't stop at a tag-check fault, so give pas explain an address")
            return
        arguments = list(fault)
    if len(arguments) < COMMANDS[command][1]:
        result.SetError(USAGE)
        return
    out = []
    run(target, target.GetProcess(), command, arguments, out)
    result.AppendMessage("\n".join(out))


def __lldb_init_module(debugger, _):
    debugger.HandleCommand(f"command script add -o -f {__name__}.lldb_command pas")


def main(arguments):
    if len(arguments) < 2 or arguments[1] not in COMMANDS or len(arguments) != 2 + COMMANDS[arguments[1]][1]:
        sys.exit("usage: pas.py <pid> info|page|refs|explain <address>, or pas.py <pid> heap|log")
    pid, command, values = int(arguments[0]), arguments[1], [int(value, 0) for value in arguments[2:]]
    debugger = lldb.SBDebugger.Create()
    debugger.SetAsync(False)
    target = debugger.CreateTarget("")
    error = lldb.SBError()
    process = target.AttachToProcessWithID(debugger.GetListener(), pid, error)
    if not error.Success():
        sys.exit(f"cannot attach to {pid}: {error.GetCString()}")
    out = []
    try:
        run(target, process, command, values, out)
    finally:
        process.Detach()
    print("\n".join(out))


if __name__ == "__main__":
    main(sys.argv[1:])
