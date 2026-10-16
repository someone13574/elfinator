#include "dll.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "builtin_dlls.h"
#include "image.h"
#include "pe_types.h"
#include "util.h"

uint8_t* get_dll_file(const char* name, size_t* file_size_out) {
    assert(name && file_size_out);

#ifdef ELFINATOR_COMPAT
    for (size_t idx = 0; idx < builtin_dll_count; idx++) {
        if (strcmp(builtin_dlls[idx].name, name) == 0) {
            char path[512];
            int len = snprintf(path, sizeof(path), "build/dlls32/%s", name);
            if (len < 0 || (size_t)len >= sizeof(path)) {
                pmsg_exit("dll path too long");
            }

            return map_file(path, file_size_out);
        }
    }
#endif

    if (strcmp("with_dll_lib.dll", name) == 0) {
        return map_file("build/with_dll_lib.dll", file_size_out);
    } else if (strcmp("with_dll_lib32.dll", name) == 0) {
        return map_file("build/with_dll_lib32.dll", file_size_out);
    } else {
        fprintf(stderr, "unknown dll `%s`\n", name);
    }

    return NULL;
}

typedef const char* (*NameAtFn)(const void* ctx, size_t idx);

static bool find_name_idx(
    const char* fn_name, uint16_t hint, size_t count, NameAtFn name_at, const void* ctx,
    size_t* idx_out
) {
    size_t low = 0;
    size_t high = count;

    if (hint < count) {
        int cmp = strcmp(name_at(ctx, hint), fn_name);
        if (cmp == 0) {
            *idx_out = hint;
            return true;
        } else if (cmp < 0) {
            low = (size_t)hint + 1;
        } else {
            high = hint;
        }
    }

    while (low < high) {
        size_t mid = low + (high - low) / 2;
        int cmp = strcmp(name_at(ctx, mid), fn_name);
        if (cmp == 0) {
            *idx_out = mid;
            return true;
        } else if (cmp < 0) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }

    return false;
}

static const char* builtin_name_at(const void* ctx, size_t idx) {
    return ((const BuiltinExport*)ctx)[idx].name;
}

typedef struct {
    const uint8_t* base;
    const u32_align1* name_addresses;
    size_t image_size;
} ExportNames;

static const char* export_name_at(const void* ctx, size_t idx) {
    const ExportNames* names = ctx;
    return rva_cstring(names->base, names->name_addresses[idx], names->image_size);
}

static void* module_builtin_fn_by_name(Module* module, const char* fn_name, uint16_t hint) {
    assert(module && fn_name && module->is_builtin);

    size_t idx;
    if (!find_name_idx(
            fn_name, hint, module->builtin.builtin_count, builtin_name_at, module->builtin.exports,
            &idx
        )) {
        return NULL;
    }

    return module->builtin.exports[idx].fn;
}

static const ImageExportDirectory* module_get_exports(Module* module, ImageDataDirectory* dir_out) {
    assert(module && dir_out && !module->is_builtin);

    *dir_out = nt_get_data_directory(&module->image.nt, IMAGE_DIRECTORY_ENTRY_EXPORT);
    if (dir_out->virtual_address == 0) {
        return NULL;
    }

    return rva_offset_ranged(
        module->image.base, dir_out->virtual_address, sizeof(ImageExportDirectory),
        module->image.size
    );
}

static void* module_export_fn_at(
    Module* module, ImageDataDirectory dir, const ImageExportDirectory* exports, uint32_t fn_idx
) {
    assert(module && exports && fn_idx < exports->number_of_functions);

    const u32_align1* function_addresses = rva_offset_ranged(
        module->image.base, exports->address_of_functions,
        sizeof(u32_align1) * exports->number_of_functions, module->image.size
    );

    uint32_t function_rva = function_addresses[fn_idx];
    if (function_rva == 0) {
        return NULL;
    }

    if (function_rva >= dir.virtual_address && function_rva - dir.virtual_address < dir.size) {
        pmsg_exit("unimplemented: forwarders");
    }

    return rva_offset(module->image.base, function_rva, module->image.size, NULL);
}

void* module_get_fn_by_name(Module* module, const char* fn_name, uint16_t hint) {
    assert(module && fn_name);

    if (module->is_builtin) {
        return module_builtin_fn_by_name(module, fn_name, hint);
    }

    ImageDataDirectory dir;
    const ImageExportDirectory* exports = module_get_exports(module, &dir);
    if (!exports) {
        return NULL;
    }

    const u32_align1* name_addresses = rva_offset_ranged(
        module->image.base, exports->address_of_names,
        sizeof(u32_align1) * exports->number_of_names, module->image.size
    );
    const u16_align1* ordinal_table = rva_offset_ranged(
        module->image.base, exports->address_of_name_ordinals,
        sizeof(u16_align1) * exports->number_of_names, module->image.size
    );

    ExportNames names = {
        .base = module->image.base,
        .name_addresses = name_addresses,
        .image_size = module->image.size,
    };
    size_t name_idx;
    if (!find_name_idx(
            fn_name, hint, exports->number_of_names, export_name_at, &names, &name_idx
        )) {
        return NULL;
    }

    uint16_t fn_idx = ordinal_table[name_idx];
    if (fn_idx >= exports->number_of_functions) {
        pmsg_exit("ordinal out of range");
    }

    return module_export_fn_at(module, dir, exports, fn_idx);
}

void* module_get_fn_by_ordinal(Module* module, uint16_t ordinal) {
    assert(module);

    // Builtins only export by name
    if (module->is_builtin) {
        return NULL;
    }

    ImageDataDirectory dir;
    const ImageExportDirectory* exports = module_get_exports(module, &dir);
    if (!exports) {
        return NULL;
    }

    if (ordinal < exports->base || ordinal - exports->base >= exports->number_of_functions) {
        return NULL;
    }

    return module_export_fn_at(module, dir, exports, ordinal - exports->base);
}
