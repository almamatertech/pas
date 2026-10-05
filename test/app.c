// Test target for pas: allocates with WebKit's fastMalloc (libpas) at a few sizes, prints the
// addresses, then waits. It frees one small object so its page also has a free slot, and stores one
// pointer in the medium object for pas refs to find.
//
// Given "use-after-free" or "out-of-bounds", it waits for a debugger to attach and then makes that
// bad access, so pas explain has a real tag-check fault to look at. Otherwise it never touches the
// freed object; it only prints the pointer value it had.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

// WTF::fastMalloc and WTF::fastFree, exported by JavaScriptCore.
void* fast_malloc(size_t) __asm__("__ZN3WTF10fastMallocEm");
void fast_free(void*) __asm__("__ZN3WTF8fastFreeEPv");

enum { COUNT = 64 };

static int debugger_attached(void)
{
    struct kinfo_proc info = { 0 };
    size_t size = sizeof(info);
    int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    sysctl(name, 4, &info, &size, NULL, 0);
    return (info.kp_proc.p_flag & P_TRACED) != 0;
}

int main(int argc, char** argv)
{
    const char* mode = argc > 1 ? argv[1] : "";
    void* small[COUNT];
    for (int i = 0; i < COUNT; i++)
        small[i] = fast_malloc(24);
    void** medium = fast_malloc(3000);
    void* larger = fast_malloc(20000);
    void* large = fast_malloc(100000);
    void* system = malloc(64);
    void* freed = small[COUNT / 2];
    fast_free(freed);
    memset(medium, 0, 3000);
    medium[1] = small[COUNT / 2 - 1];

    printf("small %p\n", small[COUNT / 2 - 1]);
    printf("freed %p\n", freed);
    printf("medium %p\n", (void*)medium);
    printf("larger %p\n", larger);
    printf("large %p\n", large);
    printf("malloc %p\n", system);
    fflush(stdout);

    if (!strcmp(mode, "use-after-free") || !strcmp(mode, "out-of-bounds")) {
        while (!debugger_attached())
            usleep(10000);
        // out-of-bounds reads the first byte past a 24-byte object's 32-byte slot.
        volatile char* bad = !strcmp(mode, "use-after-free") ? freed : (char*)small[COUNT / 2 - 2] + 32;
        return *bad;
    }
    for (;;)
        pause(); // Attaching a debugger can interrupt pause(), so keep waiting.
}
