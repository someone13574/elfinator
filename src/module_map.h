#pragma once

#include <stddef.h>
#include <stdint.h>

#include "image.h"

typedef struct {
    char* data;
    size_t size;
    size_t capacity;
} StringBuffer;

typedef struct ModuleMap {
    size_t capacity;
    size_t capacity_mask;
    size_t count;
    Module** slots;
    uint32_t* slot_hashes;
    StringBuffer names;
    StringBuffer temp;
    uint32_t next_tls_idx;
} ModuleMap;

ModuleMap module_map_new(size_t capacity);
void module_map_free(ModuleMap* map);

/// Returned modules are invalidated by free
Module* module_map_get(ModuleMap* map, const char* name, _Bool is_dll);
/// Duplicate inserts is undefined, returned modules are invalidated by free
Module* module_map_insert(ModuleMap* map, Module module);
/// Get the next tls index and increment
uint32_t module_map_next_tls_idx(ModuleMap* map);
