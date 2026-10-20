#pragma once

#include <stddef.h>
#include <stdint.h>

#include "module_map.h"
#include "pe_types.h"

typedef void* (*TlsAllocFn)(size_t size, size_t align, const char* name);

uint32_t init_image_tls(
    ModuleMap* module_map, uint8_t* base, size_t image_size, const ImageNtHeaders* nt,
    ImageTlsDirectory* tls_out
);
// Allocates the calling thread's TLS, returns NULL if there is no TLS
void* alloc_thread_tls(const ModuleMap* module_map, _Bool is_64bit, TlsAllocFn alloc);
