#pragma once

#include <stddef.h>
#include <stdint.h>

#include "module_map.h"
#include "pe_types.h"

void resolve_imports(
    uint8_t* base, size_t image_size, const ImageNtHeaders* nt, ModuleMap* module_map
);
