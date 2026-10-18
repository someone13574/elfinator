#pragma once

#include <stddef.h>
#include <stdint.h>

#include "module_map.h"
#include "pe_types.h"

uint32_t
init_image_tls(ModuleMap* module_map, uint8_t* base, size_t image_size, const ImageNtHeaders* nt);
