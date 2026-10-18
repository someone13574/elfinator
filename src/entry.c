#include "entry.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "compat.h"
#include "image.h"
#include "module_map.h"
#include "pe_types.h"
#include "util.h"

#ifdef __i386__
#define WINAPI __attribute__((stdcall))
#else
#define WINAPI __attribute__((ms_abi))
#endif

int start_image(ModuleMap* module_map, Module* module) {
    assert(module_map && module);

    if (module->is_builtin) {
        return 0;
    }

    if (module->state == MODULE_INITIALIZED) {
        printf("[loader] module %s already initialized\n", module->name);
        return 0;
    }

    printf("[loader] starting module %s\n", module->name);
    module->state = MODULE_INITIALIZED;

    ImageDataDirectory dir = nt_get_data_directory(&module->image.nt, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (dir.virtual_address != 0) {
        for (size_t desc_offset = 0;; desc_offset += sizeof(ImageImportDescriptor)) {
            const ImageImportDescriptor* desc = rva_offset_ranged(
                module->image.base, (size_t)dir.virtual_address + desc_offset,
                sizeof(ImageImportDescriptor), module->image.size
            );
            if (desc->name == 0) {
                break;
            }

            const char* dependency_name =
                rva_cstring(module->image.base, desc->name, module->image.size);
            Module* dependency = module_map_get(module_map, dependency_name, true);
            start_image(module_map, dependency);
        }
    } else {
        printf("[loader] no imports\n");
    }

    uint32_t address_of_entry_point = module->image.nt.is_64bit
                                          ? module->image.nt.u64.address_of_entry_point
                                          : module->image.nt.u32.address_of_entry_point;
    if (address_of_entry_point != 0) {
        if (module->image.is_dll) {
            typedef int(WINAPI * DllEntry)(void* hinst, uint32_t reason, void* reserved);
            DllEntry entry = (DllEntry)rva_offset(
                module->image.base, address_of_entry_point, module->image.size, NULL
            );
            printf("[loader] calling %s:DllMain at %p\n\n", module->name, (void*)entry);

            // Guest code writes to the fd directly, so the log needs to be flushed to stay in order
            fflush(stdout);
#ifdef ELFINATOR_COMPAT
            int code;
            if (!module->image.nt.is_64bit) {
                uint32_t args[3] = {
                    (uint32_t)(uintptr_t)module->image.base, DLL_PROCESS_ATTACH,
                    (uint32_t)(uintptr_t)NULL
                };
                code = (int)compat_call32((uint32_t)(uintptr_t)entry, args, 3);
            } else {
                code = entry(module->image.base, DLL_PROCESS_ATTACH, NULL);
            }
#else
            int code = entry(module->image.base, DLL_PROCESS_ATTACH, NULL);
#endif
            if (code == 0) {
                pmsg_exit("DllMain failed (returned 0)");
            }

            printf("\n[loader] started dll %s\n", module->name);
            return code;
        } else {
            typedef int(__attribute__((ms_abi)) * EntryPoint)(void);
            EntryPoint entry = (EntryPoint)rva_offset(
                module->image.base, address_of_entry_point, module->image.size, NULL
            );
            printf("[loader] jumping to exe entry at %p\n\n", (void*)entry);
            fflush(stdout);
#ifdef ELFINATOR_COMPAT
            int code;
            if (!module->image.nt.is_64bit) {
                code = (int)compat_call32((uint32_t)(uintptr_t)entry, NULL, 0);
            } else {
                code = entry();
            }
#else
            int code = entry();
#endif
            printf("\n[loader] entry returned exit code %d\n", code);
            return code;
        }
    } else {
        printf("[loader] %s has no entry\n", module->name);
        return 0;
    }
}

void detach_image(ModuleMap* module_map, Module* module) {
    assert(module_map && module);

    if (module->is_builtin) {
        return;
    }

    if (module->state != MODULE_INITIALIZED) {
        return;
    }

    printf("[loader] detaching module %s\n", module->name);
    module->state = MODULE_MAPPED;

    uint32_t address_of_entry_point = module->image.nt.is_64bit
                                          ? module->image.nt.u64.address_of_entry_point
                                          : module->image.nt.u32.address_of_entry_point;
    if (module->image.is_dll && address_of_entry_point != 0) {
        typedef int(WINAPI * DllEntry)(void* hinst, uint32_t reason, void* reserved);
        DllEntry entry = (DllEntry)rva_offset(
            module->image.base, address_of_entry_point, module->image.size, NULL
        );
        printf("[loader] calling %s:DllMain (detach) at %p\n\n", module->name, (void*)entry);

        // Guest code writes to the fd directly, so the log needs to be flushed to stay in order
        fflush(stdout);
#ifdef ELFINATOR_COMPAT
        if (!module->image.nt.is_64bit) {
            uint32_t args[3] = {
                (uint32_t)(uintptr_t)module->image.base, DLL_PROCESS_DETACH,
                (uint32_t)(uintptr_t)NULL
            };
            compat_call32((uint32_t)(uintptr_t)entry, args, 3);
        } else {
            entry(module->image.base, DLL_PROCESS_DETACH, NULL);
        }
#else
        entry(module->image.base, DLL_PROCESS_DETACH, NULL);
#endif

        printf("\n[loader] detached dll %s\n", module->name);
    }

    ImageDataDirectory dir = nt_get_data_directory(&module->image.nt, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (dir.virtual_address != 0) {
        for (size_t desc_offset = 0;; desc_offset += sizeof(ImageImportDescriptor)) {
            const ImageImportDescriptor* desc = rva_offset_ranged(
                module->image.base, (size_t)dir.virtual_address + desc_offset,
                sizeof(ImageImportDescriptor), module->image.size
            );
            if (desc->name == 0) {
                break;
            }

            const char* dependency_name =
                rva_cstring(module->image.base, desc->name, module->image.size);
            Module* dependency = module_map_get(module_map, dependency_name, true);
            detach_image(module_map, dependency);
        }
    }
}
