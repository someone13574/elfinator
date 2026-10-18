#pragma once

#include <stddef.h>
#include <stdint.h>

#include "pe_types.h"

void apply_relocations(uint8_t* base, size_t image_size, const ImageNtHeaders* nt);
