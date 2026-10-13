#include "image.h"

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <unistd.h>

#include "dll.h"
#include "module_map.h"
#include "pe_print.h"
#include "pe_types.h"
#include "util.h"

#define LOADER_PAGE_SIZE 0x1000
#define LOADER_IMAGE_ALIGNMENT 0x10000

static void apply_relocations(uint8_t* base, size_t image_size, const ImageOptionalHeaders64* opt) {
    assert(base && opt);

    int64_t delta = (int64_t)((uintptr_t)base - opt->image_base);
    ImageDataDirectory dir =
        optional_header_get_data_directory(opt, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (delta == 0 || dir.virtual_address == 0) {
        printf("[loader] no relocations needed\n");
        return;
    }

    if (dir.virtual_address % 4 != 0) {
        pmsg_exit("relocation directory not 4-byte aligned\n");
    }

    uint8_t* ptr = rva_offset_ranged(base, dir.virtual_address, dir.size, image_size);
    uint8_t* end = ptr + dir.size;
    unsigned long int fixed_entries = 0;

    while (ptr < end) {
        if ((size_t)(end - ptr) < sizeof(ImageBaseRelocation)) {
            pmsg_exit("truncated image base relocation header");
        }

        ImageBaseRelocation* block = (ImageBaseRelocation*)ptr;
        if (block->size_of_block == 0) {
            break;
        }

        if (block->size_of_block < sizeof(ImageBaseRelocation) || block->size_of_block % 4 != 0 ||
            (size_t)(end - ptr) < block->size_of_block) {
            pmsg_exit("bad base relocation block size");
        }

        uint16_t* entries = (uint16_t*)(ptr + sizeof(ImageBaseRelocation));
        int count = (block->size_of_block - sizeof(ImageBaseRelocation)) / sizeof(uint16_t);
        for (int idx = 0; idx < count; idx++) {
            int type = entries[idx] >> 12;
            int offset = entries[idx] & 0xfff;
            switch (type) {
                case IMAGE_REL_BASED_ABSOLUTE: {
                    break;
                }
                case IMAGE_REL_BASED_DIR64: {
                    size_t target = (size_t)block->virtual_address + (size_t)offset;
                    u64_align1* slot =
                        rva_offset_ranged(base, target, sizeof(u64_align1), image_size);
                    *slot += (uint64_t)delta;
                    fixed_entries++;
                    break;
                }
                default: {
                    fprintf(stderr, "unimplemented base relocation entry type %d\n", type);
                    exit(1);
                }
            }
        }

        ptr += block->size_of_block;
    }

    printf("[loader] applied %lu relocations, delta=0x%016" PRIx64 "\n", fixed_entries, delta);
}

static void resolve_imports(
    uint8_t* base, size_t image_size, const ImageOptionalHeaders64* opt, ModuleMap* module_map
) {
    assert(base && opt && module_map);

    ImageDataDirectory dir = optional_header_get_data_directory(opt, IMAGE_DIRECTORY_ENTRY_IMPORT);
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

            module = map_image(module_map, dll_name, dll_file, dll_file_size, true);
        }

        // Sometime the IAT doubles as the ILT
        uint32_t ilt_rva =
            desc->original_first_thunk ? desc->original_first_thunk : desc->first_thunk;

        for (size_t entry_offset = 0;; entry_offset += sizeof(u64_align1)) {
            u64_align1* ilt = rva_offset_ranged(
                base, (size_t)ilt_rva + entry_offset, sizeof(u64_align1), image_size
            );
            if (*ilt == 0) {
                break;
            }

            u64_align1* iat = rva_offset_ranged(
                base, (size_t)desc->first_thunk + entry_offset, sizeof(u64_align1), image_size
            );

            if (*ilt & 0x8000000000000000ull) {
                pmsg_exit("unimplemented: import by ordinal\n");
            } else {
                size_t rva = *ilt & 0x7FFFFFFF;
                if (rva % 2 != 0 || rva > image_size || 2 > image_size - rva) {
                    pmsg_exit("invalid ilt pointer");
                }

                ImageImportByName* image_import_by_name = rva_offset(base, rva, image_size, NULL);
                check_rva_cstring(base, rva + offsetof(ImageImportByName, name), image_size);
                printf(
                    "[loader] hint: %hu, name: %s\n", image_import_by_name->hint,
                    image_import_by_name->name
                );

                void* fn = module_get_fn_by_name(
                    module, image_import_by_name->name, image_import_by_name->hint
                );
                if (!fn) {
                    pmsg_exit("function not resolved");
                }

                printf("[loader] resolved %s/%s to %p\n", dll_name, image_import_by_name->name, fn);
                *iat = (uint64_t)(uintptr_t)fn;
            }
        }
    }
}

static void set_protections(
    uint8_t* base, const ImageSectionHeader* sections, uint16_t num_sections, size_t headers_size,
    size_t image_size
) {
    assert(base && image_size % LOADER_PAGE_SIZE == 0 && headers_size <= image_size);

    size_t num_pages = image_size / LOADER_PAGE_SIZE;
    uint8_t* page_prots = calloc(num_pages, 1);
    if (!page_prots) {
        perror_exit("calloc page protections");
    }

    for (size_t page = 0; page * LOADER_PAGE_SIZE < headers_size; page++) {
        page_prots[page] |= PROT_READ;
    }

    for (uint16_t idx = 0; idx < num_sections; idx++) {
        int prot = 0;
        if (sections[idx].characteristics & 0x20000000u) {
            prot |= PROT_EXEC;
        }

        if (sections[idx].characteristics & 0x40000000u) {
            prot |= PROT_READ;
        }

        if (sections[idx].characteristics & 0x80000000u) {
            prot |= PROT_WRITE;
        }

        size_t virtual_size = sections[idx].virtual_size != 0 ? sections[idx].virtual_size
                                                              : sections[idx].size_of_raw_data;
        if (virtual_size == 0) {
            continue;
        }

        size_t start = sections[idx].virtual_address;
        rva_offset_ranged(base, start, virtual_size, image_size);
        size_t first_page = start / LOADER_PAGE_SIZE;
        size_t last_page = (start + virtual_size - 1) / LOADER_PAGE_SIZE;
        for (size_t page = first_page; page <= last_page; page++) {
            page_prots[page] |= prot;
        }

        char name[9] = {0};
        memcpy(name, sections[idx].name, 8);
        fprintf(
            stderr, "[loader] protect: %-8s %c%c%c\n", name, (prot & PROT_READ) ? 'r' : '-',
            (prot & PROT_WRITE) ? 'w' : '-', (prot & PROT_EXEC) ? 'x' : '-'
        );
    }

    size_t page = 0;
    while (page < num_pages) {
        size_t run_end = page + 1;
        while (run_end < num_pages && page_prots[run_end] == page_prots[page]) {
            run_end++;
        }

        uint8_t* addr = base + page * LOADER_PAGE_SIZE;
        assert((uintptr_t)addr % LOADER_PAGE_SIZE == 0);
        if (mprotect(addr, (run_end - page) * LOADER_PAGE_SIZE, page_prots[page]) != 0) {
            perror_exit("mprotect");
        }

        page = run_end;
    }

    free(page_prots);
}

Module* map_image(
    ModuleMap* module_map, const char* name, const uint8_t* file, size_t file_size, _Bool is_dll
) {
    assert(module_map && name && file);
    assert(sysconf(_SC_PAGESIZE) == LOADER_PAGE_SIZE);

    // Check headers and sections
    if (file_size < sizeof(ImageDosHeader)) {
        pmsg_exit("file too small for DOS header");
    }

    const ImageDosHeader* dos = (const ImageDosHeader*)file;
    check_dos_header(dos);
    pe_print_dos_header(dos);

    size_t nt_fixed_size = offsetof(ImageNtHeaders64, optional_header) +
                           offsetof(ImageOptionalHeaders64, data_directory);
    if (dos->lfanew < 0 || file_size < nt_fixed_size ||
        (size_t)dos->lfanew > file_size - nt_fixed_size) {
        pmsg_exit("file too small for NT headers (bad lfanew)");
    }

    const ImageNtHeaders64* nt = offset_ptr(file, dos->lfanew);
    check_nt_headers(nt, is_dll);
    const ImageSectionHeader* sections = nt_header_get_sections(file, file_size, nt);
    check_sections(nt, sections);
    pe_print_nt_headers_64(nt);

    printf("---------------\n");

    ImageDataDirectory tls_dir =
        optional_header_get_data_directory(&nt->optional_header, IMAGE_DIRECTORY_ENTRY_TLS);
    if (tls_dir.virtual_address != 0 || tls_dir.size != 0) {
        pmsg_exit("unimplemented: tls");
    }

    size_t image_size = round_up_pow2(nt->optional_header.size_of_image, LOADER_PAGE_SIZE);
    size_t headers_size = nt->optional_header.size_of_headers;
    if (headers_size > file_size || headers_size > image_size) {
        pmsg_exit("headers outside of file or image (bad size_of_headers)");
    }

    // Map memory for image
    void* preferred_base = (void*)(uintptr_t)nt->optional_header.image_base;
    size_t reserve_size = image_size + LOADER_IMAGE_ALIGNMENT - LOADER_PAGE_SIZE;
    uint8_t* reserve = mmap(
        preferred_base, reserve_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0
    );
    if (reserve == MAP_FAILED) {
        perror_exit("mmap image reserve");
    }

    uint8_t* base = (uint8_t*)round_up_pow2((uintptr_t)reserve, LOADER_IMAGE_ALIGNMENT);
    size_t reserve_head_size = (size_t)(base - reserve);
    size_t reserve_tail_size = reserve_size - reserve_head_size - image_size;
    if (reserve_head_size != 0 && munmap(reserve, reserve_head_size) != 0) {
        perror_exit("munmap image reserve head");
    }

    if (reserve_tail_size != 0 && munmap(base + image_size, reserve_tail_size) != 0) {
        perror_exit("munmap image reserve tail");
    }

    bool relocatable = !(nt->file_header.characteristics & IMAGE_FILE_RELOCS_STRIPPED);
    if (base != preferred_base && !relocatable) {
        pmsg_exit("image is not relocatable and count not be mapped at its preferred address");
    }

    printf("[loader] mapped image `%s` at %p (%zu bytes)\n", name, base, image_size);

    // Copy data to image
    memcpy(base, file, headers_size);
    for (int idx = 0; idx < nt->file_header.number_of_sections; idx++) {
        const ImageSectionHeader* section = &sections[idx];

        size_t copy_size = section->size_of_raw_data;
        if (section->virtual_size != 0 && section->virtual_size < copy_size) {
            copy_size = section->virtual_size;
        }

        if (section->virtual_address > image_size ||
            copy_size > image_size - section->virtual_address) {
            pmsg_exit("section outside of image (bad virtual_address or section size)");
        }

        if (section->pointer_to_raw_data > file_size ||
            copy_size > file_size - section->pointer_to_raw_data) {
            pmsg_exit("section outside of file (bad pointer_to_raw_data or section size)");
        }

        memcpy(
            offset_ptr(base, section->virtual_address),
            offset_ptr(file, section->pointer_to_raw_data), copy_size
        );
    }

    // Apply relocations
    apply_relocations(base, image_size, &nt->optional_header);

    module_map_insert(
        module_map, (Module){.name = name,
                             .is_builtin = false,
                             .state = MODULE_MAPPED,
                             .image.is_dll = is_dll,
                             .image.base = base,
                             .image.size = image_size,
                             .image.nt = nt}
    );

    resolve_imports(base, image_size, &nt->optional_header, module_map);
    set_protections(base, sections, nt->file_header.number_of_sections, headers_size, image_size);
    return module_map_get(module_map, name, is_dll);
}

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

    ImageDataDirectory dir = optional_header_get_data_directory(
        &module->image.nt->optional_header, IMAGE_DIRECTORY_ENTRY_IMPORT
    );
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

    uint32_t address_of_entry_point = module->image.nt->optional_header.address_of_entry_point;
    if (address_of_entry_point != 0) {
        if (module->image.is_dll) {
            typedef int(__attribute__((ms_abi)) * DllEntry)(
                void* hinst, uint32_t reason, void* reserved
            );
            DllEntry entry = (DllEntry)rva_offset(
                module->image.base, address_of_entry_point, module->image.size, NULL
            );
            printf("[loader] calling %s:DllMain at %p\n\n", module->name, (void*)entry);

            // Guest code writes to the fd directly, so the log needs to be flushed to stay in order
            fflush(stdout);
            int code = entry(module->image.base, DLL_PROCESS_ATTACH, NULL);
            if (code == 0) {
                pmsg_exit("DllMain failed (returned 0)");
            }

            printf("\n[loader] started dll %s\n", module->name);
            return code;
        } else {
            typedef int(__attribute__((ms_abi)) * EntryPoint)(void);
            EntryPoint entry = (EntryPoint)rva_offset(
                module->image.base, module->image.nt->optional_header.address_of_entry_point,
                module->image.size, NULL
            );
            printf("[loader] jumping to exe entry at %p\n\n", (void*)entry);
            fflush(stdout);
            int code = entry();
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

    uint32_t address_of_entry_point = module->image.nt->optional_header.address_of_entry_point;
    if (module->image.is_dll && address_of_entry_point != 0) {
        typedef int(__attribute__((ms_abi)) * DllEntry)(
            void* hinst, uint32_t reason, void* reserved
        );
        DllEntry entry = (DllEntry)rva_offset(
            module->image.base, address_of_entry_point, module->image.size, NULL
        );
        printf("[loader] calling %s:DllMain (detach) at %p\n\n", module->name, (void*)entry);

        // Guest code writes to the fd directly, so the log needs to be flushed to stay in order
        fflush(stdout);
        entry(module->image.base, DLL_PROCESS_DETACH, NULL);

        printf("\n[loader] detached dll %s\n", module->name);
    }

    ImageDataDirectory dir = optional_header_get_data_directory(
        &module->image.nt->optional_header, IMAGE_DIRECTORY_ENTRY_IMPORT
    );
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
