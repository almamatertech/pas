// Minimal version of libmalloc's private header, for building WebKit with MTE on with the public
// SDK. These declarations match libmalloc c49dafa25f1e (private/malloc_private.h). The option enum
// is in the public <malloc/malloc.h>, and libsystem_malloc exports the function.
#pragma once
#include <malloc/malloc.h>
typedef malloc_zone_malloc_options_t malloc_options_np_t;
#define MALLOC_NP_OPTION_CLEAR MALLOC_ZONE_MALLOC_OPTION_CLEAR
#define MALLOC_NP_OPTION_CANONICAL_TAG MALLOC_ZONE_MALLOC_OPTION_CANONICAL_TAG
#ifdef __cplusplus
extern "C"
#endif
void* malloc_zone_malloc_with_options_np(malloc_zone_t*, size_t align, size_t size, malloc_options_np_t);
