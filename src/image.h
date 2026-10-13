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
            const ImageNtHeaders64* nt;
        } image;

        struct {
            const BuiltinExport* exports;
            size_t builtin_count;
        } builtin;
    };
} Module;

typedef struct ModuleMap ModuleMap;

Module* map_image(
    ModuleMap* module_map, const char* name, const uint8_t* file, size_t file_size, _Bool is_dll
);

int start_image(ModuleMap* module_map, Module* module);
