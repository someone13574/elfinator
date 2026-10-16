#pragma once

#include <stddef.h>

#include "image.h"

typedef struct {
    const char* name;
    const BuiltinExport* exports;
    size_t export_count;
} BuiltinDll;

extern const BuiltinDll builtin_dlls[];
extern const size_t builtin_dll_count;

#ifdef ELFINATOR_COMPAT
// Called by 32-bit thunks via call64
void builtins_dispatch(uint32_t idx, const uint64_t* args, uint64_t* result);
#endif
