#include "tls.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "module_map.h"
#include "pe_types.h"
#include "util.h"

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
                                   .address_of_call_backs = tls_dir.address_of_call_backs,
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

    dir->address_of_index = va_to_rva(dir->address_of_index, base);
    check_rva_range(image_size, dir->address_of_index, dir->address_of_index + 4);

    if (dir->address_of_call_backs) {
        dir->address_of_call_backs = va_to_rva(dir->address_of_call_backs, base);
        const size_t ptr_size = is_64bit ? 8 : 4;
        check_rva_range(
            image_size, dir->address_of_call_backs, dir->address_of_call_backs + ptr_size
        );
    }

    uint32_t alignment_idx = (dir->characteristics >> 20) & 0xf;
    if (alignment_idx > 14) {
        fprintf(stderr, "[loader] warning: undefined tls alignment\n");
    }
}

uint32_t
init_image_tls(ModuleMap* module_map, uint8_t* base, size_t image_size, const ImageNtHeaders* nt) {
    assert(module_map && base && nt);

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
    return tls_index;
}
