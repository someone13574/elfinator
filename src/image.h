#pragma once

#include <stddef.h>
#include <stdint.h>

#include "pe_types.h"

typedef enum { MODULE_MAPPED, MODULE_INITIALIZED } ModuleState;

typedef struct {
    const char* name;
    void* fn;
} BuiltinExport;

typedef struct Module {
    const char* name;
    _Bool is_builtin;
    ModuleState state;

    union {
        struct {
            _Bool is_dll;
            uint8_t* base;
            size_t size;
            ImageNtHeaders nt;
        } image;

        struct {
            const BuiltinExport* exports;
            size_t builtin_count;
        } builtin;
    };
} Module;

typedef struct ModuleMap ModuleMap;

typedef enum { IMAGE_ARCH_EITHER, IMAGE_ARCH_PE, IMAGE_ARCH_PE_PLUS } ImageArch;

typedef void (*LoadBuiltinsFn)(ModuleMap* module_map, _Bool is_64bit);

Module* map_image(
    ModuleMap* module_map, const char* name, const uint8_t* file, size_t file_size, _Bool is_dll,
    ImageArch arch, LoadBuiltinsFn load_builtins
);

int start_image(ModuleMap* module_map, Module* module);
void detach_image(ModuleMap* module_map, Module* module);
