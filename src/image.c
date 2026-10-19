#include "image.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <unistd.h>

#include "compat.h"
#include "compat_arena.h"
#include "import.h"
#include "module_map.h"
#include "pe_print.h"
#include "pe_types.h"
#include "reloc.h"
#include "tls.h"
#include "util.h"

#define LOADER_PAGE_SIZE 0x1000

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
    ModuleMap* module_map, const char* name, const uint8_t* file, size_t file_size, _Bool is_dll,
    ImageArch image_arch, LoadBuiltinsFn load_builtins
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

    size_t magic_offset = offsetof(ImageNtHeaders, u64.magic);
    if (dos->lfanew < 0 || file_size < magic_offset + sizeof(u16_align1) ||
        (size_t)dos->lfanew > file_size - magic_offset - sizeof(u16_align1)) {
        pmsg_exit("file too small for NT magic (bad lfanew)");
    }

    const u16_align1* magic = offset_ptr(file, dos->lfanew + magic_offset);
    ImageNtHeaders nt = {.is_64bit = *magic == 0x20b};
    switch (image_arch) {
        case IMAGE_ARCH_EITHER: {
            break;
        }
        case IMAGE_ARCH_PE: {
            if (nt.is_64bit) {
                pmsg_exit("image is PE+ (expected 32-bit)");
            }
            break;
        }
        case IMAGE_ARCH_PE_PLUS: {
            if (!nt.is_64bit) {
                pmsg_exit("image is PE (expected 64-bit)");
            }
            break;
        }
    }

    size_t nt_fixed_size = nt_get_fixed_size(nt.is_64bit);
    if (dos->lfanew < 0 || file_size < nt_fixed_size ||
        (size_t)dos->lfanew > file_size - nt_fixed_size) {
        pmsg_exit("file too small for NT headers (bad lfanew)");
    }

    size_t max_optional_size =
        offsetof(ImageNtHeaders, u64) +
        (nt.is_64bit ? sizeof(ImageOptionalHeaders64) : sizeof(ImageOptionalHeaders32));
    size_t optional_copy_size =
        file_size - dos->lfanew < max_optional_size ? file_size - dos->lfanew : max_optional_size;
    memcpy(&nt, offset_ptr(file, dos->lfanew), optional_copy_size);

    check_nt_headers(&nt, is_dll);
    const ImageSectionHeader* sections = nt_header_get_sections(file, file_size, dos->lfanew, &nt);
    check_sections(&nt, sections);
    pe_print_nt_headers(&nt);

    printf("---------------\n");

#ifdef ELFINATOR_COMPAT
    if (!is_dll && !nt.is_64bit && !compat_arena_is_reserved()) {
        _Bool large_address_aware = (nt.file_header.characteristics & 0x20) == 0x20;
        uint64_t limit = large_address_aware ? (1ull << 32) : (1ull << 31);
        compat_arena_reserve(limit);
        compat_init(limit);
    }
#endif

    if (load_builtins) {
        load_builtins(module_map, nt.is_64bit);
    }

    size_t image_size =
        round_up_pow2(nt.is_64bit ? nt.u64.size_of_image : nt.u32.size_of_image, LOADER_PAGE_SIZE);
    size_t headers_size = nt.is_64bit ? nt.u64.size_of_headers : nt.u32.size_of_headers;
    if (headers_size > file_size || headers_size > image_size) {
        pmsg_exit("headers outside of file or image (bad size_of_headers)");
    }

    // Map memory for image
    void* preferred_base = (void*)(uintptr_t)(nt.is_64bit ? nt.u64.image_base : nt.u32.image_base);
    uint8_t* base = NULL;
#ifdef ELFINATOR_COMPAT
    if (!nt.is_64bit) {
        base = compat_arena_alloc(
            (uint64_t)(uintptr_t)preferred_base, image_size, ALLOCATION_GRANULARITY
        );
        if (!base) {
            pmsg_exit("no reserved low memory available for 32-bit image");
        }
    }
#endif

    if (!base) {
        size_t reserve_size = image_size + ALLOCATION_GRANULARITY - LOADER_PAGE_SIZE;
        uint8_t* reserve = mmap(
            preferred_base, reserve_size, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | (nt.is_64bit ? 0 : MAP_32BIT), -1, 0
        );
        if (reserve == MAP_FAILED) {
            perror_exit("mmap image reserve");
        }

        base = (uint8_t*)round_up_pow2((uintptr_t)reserve, ALLOCATION_GRANULARITY);
        size_t reserve_head_size = (size_t)(base - reserve);
        size_t reserve_tail_size = reserve_size - reserve_head_size - image_size;
        if (reserve_head_size != 0 && munmap(reserve, reserve_head_size) != 0) {
            perror_exit("munmap image reserve head");
        }

        if (reserve_tail_size != 0 && munmap(base + image_size, reserve_tail_size) != 0) {
            perror_exit("munmap image reserve tail");
        }
    }

    bool relocatable = !(nt.file_header.characteristics & IMAGE_FILE_RELOCS_STRIPPED);
    if (base != preferred_base && !relocatable) {
        pmsg_exit("image is not relocatable and count not be mapped at its preferred address");
    }

    printf("[loader] mapped image `%s` at %p (%zu bytes)\n", name, base, image_size);

    // Copy data to image
    memcpy(base, file, headers_size);
    for (int idx = 0; idx < nt.file_header.number_of_sections; idx++) {
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

    apply_relocations(base, image_size, &nt);

    uint32_t tls_index = init_image_tls(module_map, base, image_size, &nt);

    module_map_insert(
        module_map, (Module){.name = name,
                             .is_builtin = false,
                             .state = MODULE_MAPPED,
                             .image.is_dll = is_dll,
                             .image.base = base,
                             .image.size = image_size,
                             .image.nt = nt,
                             .image.tls_index = tls_index}
    );

    resolve_imports(base, image_size, &nt, module_map);
    set_protections(base, sections, nt.file_header.number_of_sections, headers_size, image_size);
    return module_map_get(module_map, name, is_dll);
}
