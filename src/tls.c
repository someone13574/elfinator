#include "tls.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "module_map.h"
#include "pe_types.h"
#include "util.h"

#define TLS_DEFAULT_ALIGNMENT 16

static ImageTlsDirectory read_tls_directory(
    const uint8_t* base, size_t image_size, const ImageDataDirectory* dir, _Bool is_64bit
) {
    assert(base && dir);

    size_t struct_size = is_64bit ? sizeof(ImageTlsDirectory) : sizeof(ImageTlsDirectory32);
    if (dir->size < struct_size) {
        pmsg_exit("tls directory size too small");
    }

    const void* ptr = rva_offset_ranged(base, dir->virtual_address, struct_size, image_size);
    if (is_64bit) {
        ImageTlsDirectory tls_dir;
        memcpy(&tls_dir, ptr, sizeof(tls_dir));
        return tls_dir;
    } else {
        ImageTlsDirectory32 tls_dir;
        memcpy(&tls_dir, ptr, sizeof(tls_dir));
        return (ImageTlsDirectory){.start_address_of_raw_data = tls_dir.start_address_of_raw_data,
                                   .end_address_of_raw_data = tls_dir.end_address_of_raw_data,
                                   .address_of_index = tls_dir.address_of_index,
                                   .address_of_callbacks = tls_dir.address_of_call_backs,
                                   .size_of_zero_fill = tls_dir.size_of_zero_fill,
                                   .characteristics = tls_dir.characteristics};
    }
}

static size_t va_to_rva(uintptr_t va, uintptr_t base) {
    if (va < base) {
        pmsg_exit("invalid virtual address (possibly not recorded in relocations)");
    }
    return va - base;
}

static void validate_and_relativize_tls_directory(
    ImageTlsDirectory* dir, uintptr_t base, size_t image_size, _Bool is_64bit
) {
    assert(dir && base);

    dir->start_address_of_raw_data = va_to_rva(dir->start_address_of_raw_data, base);
    dir->end_address_of_raw_data = va_to_rva(dir->end_address_of_raw_data, base);
    check_rva_range(image_size, dir->start_address_of_raw_data, dir->end_address_of_raw_data);
    if (dir->size_of_zero_fill >
        SIZE_MAX - (size_t)(dir->end_address_of_raw_data - dir->start_address_of_raw_data)) {
        pmsg_exit("tls zero fill too large");
    }

    dir->address_of_index = va_to_rva(dir->address_of_index, base);
    check_rva_range(image_size, dir->address_of_index, dir->address_of_index + 4);

    if (dir->address_of_callbacks) {
        dir->address_of_callbacks = va_to_rva(dir->address_of_callbacks, base);
        const size_t ptr_size = is_64bit ? 8 : 4;
        check_rva_range(
            image_size, dir->address_of_callbacks, dir->address_of_callbacks + ptr_size
        );
    }

    uint32_t alignment_idx = (dir->characteristics >> 20) & 0xf;
    if (alignment_idx > 14) {
        fprintf(stderr, "[loader] warning: undefined tls alignment\n");
    }
}

uint32_t init_image_tls(
    ModuleMap* module_map, uint8_t* base, size_t image_size, const ImageNtHeaders* nt,
    ImageTlsDirectory* tls_out
) {
    assert(module_map && base && nt && tls_out);

    *tls_out = (ImageTlsDirectory){0};
    ImageDataDirectory tls_dir = nt_get_data_directory(nt, IMAGE_DIRECTORY_ENTRY_TLS);
    if (tls_dir.virtual_address == 0) {
        return UINT32_MAX;
    }

    uint32_t tls_index = module_map_next_tls_idx(module_map);

    ImageTlsDirectory tls = read_tls_directory(base, image_size, &tls_dir, nt->is_64bit);
    validate_and_relativize_tls_directory(&tls, (uintptr_t)base, image_size, nt->is_64bit);

    u32_align1* index =
        rva_offset_ranged(base, tls.address_of_index, sizeof(u32_align1), image_size);
    *index = tls_index;
    *tls_out = tls;
    return tls_index;
}

static size_t tls_alignment(const ImageTlsDirectory* dir) {
    assert(dir);

    uint32_t alignment_idx = (dir->characteristics >> 20) & 0xf;
    if (alignment_idx == 0 || alignment_idx > 14) {
        return TLS_DEFAULT_ALIGNMENT;
    }

    return (size_t)1 << (alignment_idx - 1);
}

static size_t tls_block_size(const ImageTlsDirectory* dir) {
    assert(dir);

    return (size_t)(dir->end_address_of_raw_data - dir->start_address_of_raw_data) +
           dir->size_of_zero_fill;
}

static _Bool has_tls(const Module* module) {
    return module && !module->is_builtin && module->image.tls_index != UINT32_MAX;
}

void* alloc_thread_tls(const ModuleMap* module_map, _Bool is_64bit, TlsAllocFn alloc) {
    assert(module_map && alloc);

    if (module_map->next_tls_idx == 0) {
        return NULL;
    }

    size_t blocks_size = 0;
    size_t blocks_align = 1;
    for (size_t slot = 0; slot < module_map->capacity; slot++) {
        const Module* module = module_map->slots[slot];
        if (!has_tls(module)) {
            continue;
        }

        size_t align = tls_alignment(&module->image.tls);
        size_t size = tls_block_size(&module->image.tls);
        size_t offset = round_up_pow2(blocks_size, align);
        if (offset < blocks_size || size > SIZE_MAX - offset) {
            pmsg_exit("tls blocks too large");
        }

        blocks_size = offset + size;
        if (align > blocks_align) {
            blocks_align = align;
        }
    }

    size_t page_size = sysconf(_SC_PAGESIZE);
    size_t ptr_size = is_64bit ? sizeof(uint64_t) : sizeof(uint32_t);
    uint8_t* array = alloc(module_map->next_tls_idx * ptr_size, page_size, "tls array");
    uint8_t* blocks = alloc(
        blocks_size ? blocks_size : 1, blocks_align > page_size ? blocks_align : page_size,
        "tls blocks"
    );

    size_t offset = 0;
    for (size_t slot = 0; slot < module_map->capacity; slot++) {
        const Module* module = module_map->slots[slot];
        if (!has_tls(module)) {
            continue;
        }

        const ImageTlsDirectory* tls = &module->image.tls;
        size_t data_size = (size_t)(tls->end_address_of_raw_data - tls->start_address_of_raw_data);
        offset = round_up_pow2(offset, tls_alignment(tls));
        uint8_t* block = blocks + offset;
        memcpy(block, module->image.base + tls->start_address_of_raw_data, data_size);
        offset += tls_block_size(tls);

        uint32_t tls_index = module->image.tls_index;
        if (is_64bit) {
            ((uint64_t*)array)[tls_index] = (uint64_t)(uintptr_t)block;
        } else {
            ((uint32_t*)array)[tls_index] = (uint32_t)(uintptr_t)block;
        }
    }

    return array;
}
