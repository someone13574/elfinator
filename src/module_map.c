#include "module_map.h"

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

ModuleMap module_map_new(size_t capacity) {
    assert(is_pow2(capacity) && capacity != 0);

    Module** slots = calloc(capacity, sizeof(Module*));
    if (!slots) {
        perror_exit("calloc module map slots");
    }

    uint32_t* slot_hashes = calloc(capacity, sizeof(uint32_t));
    if (!slot_hashes) {
        perror_exit("calloc module map slot hashes");
    }

    return (ModuleMap){.capacity = capacity,
                       .capacity_mask = capacity - 1,
                       .count = 0,
                       .slots = slots,
                       .slot_hashes = slot_hashes,
                       .names = {0},
                       .temp = {0}};
}

void module_map_free(ModuleMap* map) {
    assert(map);

    for (size_t slot = 0; slot < map->capacity; slot++) {
        free(map->slots[slot]);
    }

    free(map->slots);
    free(map->slot_hashes);
    free(map->names.data);
    free(map->temp.data);
    map->capacity = 0;
    map->capacity_mask = 0;
    map->count = 0;
    map->slots = NULL;
    map->slot_hashes = NULL;
    map->names = (StringBuffer){0};
    map->temp = (StringBuffer){0};
}

// Returns the replaced data (to be freed by the caller) if the buffer was moved, otherwise NULL
static char* string_buffer_reserve(StringBuffer* buffer, size_t additional) {
    assert(buffer);

    size_t required = buffer->size + additional;
    if (required <= buffer->capacity) {
        return NULL;
    }

    size_t new_capacity = buffer->capacity ? buffer->capacity * 2 : 256;
    while (new_capacity < required) {
        new_capacity *= 2;
    }

    char* new_data = malloc(new_capacity);
    if (!new_data) {
        perror_exit("malloc string buffer");
    }
    if (buffer->data) {
        memcpy(new_data, buffer->data, buffer->size);
    }

    char* old_data = buffer->data;
    buffer->data = new_data;
    buffer->capacity = new_capacity;
    return old_data;
}

static void module_map_reserve_name_space(ModuleMap* map, size_t additional) {
    assert(map);

    char* old_names = string_buffer_reserve(&map->names, additional);
    if (!old_names) {
        return;
    }

    for (size_t slot = 0; slot < map->capacity; slot++) {
        if (map->slots[slot]) {
            map->slots[slot]->name = map->names.data + (map->slots[slot]->name - old_names);
        }
    }

    free(old_names);
}

static inline unsigned char ascii_lower(unsigned char c) {
    if (c >= 0x80) {
        fprintf(
            stderr,
            "warning: module name contains non-ascii byte 0x%x, unicode lowering unimplemented\n",
            (int)c
        );
    }
    return (c >= 'A' && c <= 'Z') ? (unsigned char)(c | 0x20) : c;
}

static char* module_map_write_name(ModuleMap* map, const char* name, bool is_dll) {
    assert(map && name);

    static const char dll_suffix[] = ".dll";
    size_t suffix_len = sizeof(dll_suffix) - 1;

    size_t len = strlen(name);
    map->temp.size = 0;
    free(string_buffer_reserve(&map->temp, len + suffix_len + 1));

    char* normalized = map->temp.data;
    for (size_t idx = 0; idx < len; idx++) {
        normalized[idx] = (char)ascii_lower((unsigned char)name[idx]);
    }

    // A trailing dot means no extension, otherwise .dll is only added if there is no extension
    if (len > 0 && normalized[len - 1] == '.') {
        len--;
    } else if (is_dll && !memchr(normalized, '.', len)) {
        memcpy(normalized + len, dll_suffix, suffix_len);
        len += suffix_len;
    }

    normalized[len] = '\0';
    map->temp.size = len + 1;
    return normalized;
}

static uint32_t fnv1a32_cstr(const char* str) {
    assert(str);

    uint32_t state = 0x811c9dc5;
    while (*str) {
        state ^= (uint32_t)(unsigned char)*str;
        state = state * UINT32_C(0x01000193);
        str++;
    }

    return state;
}

Module* module_map_get(ModuleMap* map, const char* name, bool is_dll) {
    assert(map && map->slots && name);

    name = module_map_write_name(map, name, is_dll);
    uint32_t hash = fnv1a32_cstr(name);

    Module* found = NULL;
    uint32_t initial_probe = hash & map->capacity_mask;
    uint32_t probe = initial_probe;
    do {
        if (!map->slots[probe]) {
            break;
        }

        if (map->slot_hashes[probe] == hash && strcmp(map->slots[probe]->name, name) == 0) {
            found = map->slots[probe];
            break;
        }

        probe = (probe + 1) & map->capacity_mask;
    } while (probe != initial_probe);

    return found;
}

static Module* module_map_insert_with_hash(ModuleMap* map, Module* module, uint32_t hash);

static void module_map_grow(ModuleMap* map, size_t new_capacity) {
    assert(map && map->capacity < new_capacity);

    ModuleMap new_map = module_map_new(new_capacity);
    new_map.names = map->names;
    new_map.temp = map->temp;

    for (size_t slot = 0; slot < map->capacity; slot++) {
        if (map->slots[slot]) {
            module_map_insert_with_hash(&new_map, map->slots[slot], map->slot_hashes[slot]);
        }
    }

    free(map->slots);
    free(map->slot_hashes);
    *map = new_map;
}

static Module* module_map_insert_with_hash(ModuleMap* map, Module* module, uint32_t hash) {
    assert(map && map->slots && module && module->name);

    if ((map->count + 1) * 2 > map->capacity) {
        module_map_grow(map, map->capacity * 2);
    }

    uint32_t probe = hash & map->capacity_mask;
    while (map->slots[probe]) {
        probe = (probe + 1) & map->capacity_mask;
    }

    map->slots[probe] = module;
    map->slot_hashes[probe] = hash;
    map->count++;
    return module;
}

Module* module_map_insert(ModuleMap* map, Module module) {
    assert(map && module.name);

    bool is_dll = module.is_builtin || module.image.is_dll;
    assert(!module_map_get(map, module.name, is_dll));

    Module* allocated = malloc(sizeof(Module));
    if (!allocated) {
        perror_exit("malloc module");
    }

    *allocated = module;
    module_map_write_name(map, module.name, is_dll);
    module_map_reserve_name_space(map, map->temp.size);
    allocated->name = memcpy(map->names.data + map->names.size, map->temp.data, map->temp.size);
    map->names.size += map->temp.size;
    uint32_t hash = fnv1a32_cstr(allocated->name);
    return module_map_insert_with_hash(map, allocated, hash);
}
