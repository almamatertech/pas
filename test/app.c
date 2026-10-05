// Test target for pas: allocates with WebKit's fastMalloc (libpas) at a few sizes, prints the
// addresses, then waits. It frees one small object so its page also has a free slot, and never
// touches that object again; it only prints the pointer value it had.
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// WTF::fastMalloc and WTF::fastFree, exported by JavaScriptCore.
void* fast_malloc(size_t) __asm__("__ZN3WTF10fastMallocEm");
void fast_free(void*) __asm__("__ZN3WTF8fastFreeEPv");

enum { COUNT = 64 };

int main(void)
{
    void* small[COUNT];
    for (int i = 0; i < COUNT; i++)
        small[i] = fast_malloc(24);
    void* medium = fast_malloc(3000);
    void* larger = fast_malloc(20000);
    void* large = fast_malloc(100000);
    void* system = malloc(64);
    void* freed = small[COUNT / 2];
    fast_free(freed);

    printf("small %p\n", small[COUNT / 2 - 1]);
    printf("freed %p\n", freed);
    printf("medium %p\n", medium);
    printf("larger %p\n", larger);
    printf("large %p\n", large);
    printf("malloc %p\n", system);
    fflush(stdout);
    for (;;)
        pause(); // Attaching a debugger can interrupt pause(), so keep waiting.
}
