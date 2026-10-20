#include "import.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "dll.h"
#include "image.h"
#include "module_map.h"
#include "pe_types.h"
#include "util.h"

void resolve_imports(
    uint8_t* base, size_t image_size, const ImageNtHeaders* nt, ModuleMap* module_map
) {
    assert(base && nt && module_map);

    ImageArch image_arch = nt->is_64bit ? IMAGE_ARCH_PE_PLUS : IMAGE_ARCH_PE;

    ImageDataDirectory dir = nt_get_data_directory(nt, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (dir.virtual_address == 0) {
        printf("[loader] no imports\n");
        return;
    }

    for (size_t desc_offset = 0;; desc_offset += sizeof(ImageImportDescriptor)) {
        const ImageImportDescriptor* desc = rva_offset_ranged(
            base, (size_t)dir.virtual_address + desc_offset, sizeof(ImageImportDescriptor),
            image_size
        );
        if (desc->name == 0) {
            break;
        }

        const char* dll_name = rva_cstring(base, desc->name, image_size);
        printf("[loader] DLL name: %s\n", dll_name);

        Module* module = module_map_get(module_map, dll_name, true);
        if (!module) {
            size_t dll_file_size;
            const uint8_t* dll_file = get_dll_file(dll_name, &dll_file_size);
            if (!dll_file) {
                pmsg_exit("unknown dll file");
            }

            module =
                map_image(module_map, dll_name, dll_file, dll_file_size, true, image_arch, NULL);
        }

        // Sometime the IAT doubles as the ILT
        uint32_t ilt_rva =
            desc->original_first_thunk ? desc->original_first_thunk : desc->first_thunk;

        size_t entry_size = nt->is_64bit ? sizeof(u64_align1) : sizeof(u32_align1);
        uint64_t ordinal_flag = nt->is_64bit ? 0x8000000000000000ull : 0x80000000ull;

        for (size_t entry_offset = 0;; entry_offset += entry_size) {
            void* ilt_ptr =
                rva_offset_ranged(base, (size_t)ilt_rva + entry_offset, entry_size, image_size);
            uint64_t ilt = nt->is_64bit ? *(u64_align1*)ilt_ptr : *(u32_align1*)ilt_ptr;
            if (ilt == 0) {
                break;
            }

            void* iat = rva_offset_ranged(
                base, (size_t)desc->first_thunk + entry_offset, entry_size, image_size
            );

            void* fn;
            if (ilt & ordinal_flag) {
                uint16_t ordinal = ilt & 0xFFFF;
                printf("[loader] ordinal: %hu\n", ordinal);

                fn = module_get_fn_by_ordinal(module, ordinal);
                if (!fn) {
                    pmsg_exit("function not resolved");
                }

                printf("[loader] resolved %s/#%hu to %p\n", dll_name, ordinal, fn);
            } else {
                size_t rva = ilt & 0x7FFFFFFF;
                if (rva % 2 != 0 || rva > image_size || 2 > image_size - rva) {
                    pmsg_exit("invalid ilt pointer");
                }

                ImageImportByName* image_import_by_name = rva_offset(base, rva, image_size, NULL);
                check_rva_cstring(base, rva + offsetof(ImageImportByName, name), image_size);
                printf(
                    "[loader] hint: %hu, name: %s\n", image_import_by_name->hint,
                    image_import_by_name->name
                );

                fn = module_get_fn_by_name(
                    module, image_import_by_name->name, image_import_by_name->hint
                );
                if (!fn) {
                    pmsg_exit("function not resolved");
                }

                printf("[loader] resolved %s/%s to %p\n", dll_name, image_import_by_name->name, fn);
            }

            if (nt->is_64bit) {
                *(u64_align1*)iat = (uint64_t)(uintptr_t)fn;
            } else {
                if ((uintptr_t)fn > UINT32_MAX) {
                    pmsg_exit("resolved function address does not fit in 32-bit IAT entry");
                }

                *(u32_align1*)iat = (uint32_t)(uintptr_t)fn;
            }
        }
    }
}
