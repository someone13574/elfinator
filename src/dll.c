#include "dll.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "image.h"
#include "pe_types.h"
#include "util.h"

uint8_t* get_dll_file(const char* name, size_t* file_size_out) {
    assert(name && file_size_out);

    if (strcmp("with_dll_lib.dll", name) == 0) {
        return map_file("build/with_dll_lib.dll", file_size_out);
    } else {
        fprintf(stderr, "unknown dll `%s`\n", name);
    }

    return NULL;
}

static void* module_builtin_fn_by_name(Module* module, const char* fn_name, uint16_t hint) {
    assert(module && fn_name && module->is_builtin);

    (void)hint;

    for (size_t idx = 0; idx < module->builtin.builtin_count; idx++) {
        if (strcmp(module->builtin.exports[idx].name, fn_name) == 0) {
            return module->builtin.exports[idx].fn;
        }
    }

    return NULL;
}

void* module_get_fn_by_name(Module* module, const char* fn_name, uint16_t hint) {
    assert(module && fn_name);

    if (module->is_builtin) {
        return module_builtin_fn_by_name(module, fn_name, hint);
    }

    ImageDataDirectory dir = optional_header_get_data_directory(
        &module->image.nt->optional_header, IMAGE_DIRECTORY_ENTRY_EXPORT
    );
    if (dir.virtual_address == 0) {
        return NULL;
    }

    const ImageExportDirectory* exports = rva_offset_ranged(
        module->image.base, dir.virtual_address, sizeof(ImageExportDirectory), module->image.size
    );

    (void)hint;

    const u32_align1* name_addresses = rva_offset_ranged(
        module->image.base, exports->address_of_names,
        sizeof(u32_align1) * exports->number_of_names, module->image.size
    );
    const u16_align1* ordinal_table = rva_offset_ranged(
        module->image.base, exports->address_of_name_ordinals,
        sizeof(u16_align1) * exports->number_of_names, module->image.size
    );
    const u32_align1* function_addresses = rva_offset_ranged(
        module->image.base, exports->address_of_functions,
        sizeof(u32_align1) * exports->number_of_functions, module->image.size
    );

    for (uint32_t name_idx = 0; name_idx < exports->number_of_names; name_idx++) {
        uint16_t ordinal = ordinal_table[name_idx];
        if (ordinal >= exports->number_of_functions) {
            pmsg_exit("ordinal out of range");
        }

        uint32_t function_rva = function_addresses[ordinal];
        if (function_rva == 0) {
            continue;
        }

        const char* name =
            rva_cstring(module->image.base, name_addresses[name_idx], module->image.size);
        if (strcmp(name, fn_name) == 0) {
            if (function_rva >= dir.virtual_address &&
                function_rva - dir.virtual_address < dir.size) {
                pmsg_exit("unimplemented: forwarders");
            } else {
                return rva_offset(module->image.base, function_rva, module->image.size, NULL);
            }

            break;
        }
    }

    return NULL;
}
