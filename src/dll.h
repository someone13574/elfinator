#pragma once

#include <stddef.h>
#include <stdint.h>

#include "image.h"

uint8_t* get_dll_file(const char* name, size_t* file_size_out);
void* module_get_fn_by_name(Module* module, const char* fn_name, uint16_t hint);
void* module_get_fn_by_ordinal(Module* module, uint16_t ordinal);
