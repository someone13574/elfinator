#include "pe_types.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "util.h"

void check_dos_header(const ImageDosHeader* dos) {
    assert(dos);

    if (dos->magic != 0x5a4d) {
        pmsg_exit("bad dos header magic");
    }
}

void check_nt_headers(const ImageNtHeaders* nt, _Bool is_dll) {
    assert(nt);

    if (nt->signature != 0x00004550) {
        pmsg_exit("bad NT PE signature");
    }

    if (nt->is_64bit) {
        if (nt->u64.magic != 0x020b) {
            pmsg_exit("not PE32+ (expected 64-bit image)");
        }

        if (nt->file_header.machine != 0x8664) {
            pmsg_exit("not an x86-64 image");
        }
    } else {
        if (nt->u32.magic != 0x010b) {
            pmsg_exit("not PE32 (expected 32-bit image)");
        }

        if (nt->file_header.machine != 0x8664 && nt->file_header.machine != 0x014c) {
            pmsg_exit("not an x86-64 or i386 (or later) image");
        }
    }

    if (!(nt->file_header.characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
        pmsg_exit("not an executable image (IMAGE_FILE_EXECUTABLE_IMAGE not set)");
    }

    if ((_Bool)(nt->file_header.characteristics & IMAGE_FILE_DLL) != is_dll) {
        pmsg_exit("image is not the expected type");
    }

    uint32_t address_of_entry_point =
        nt->is_64bit ? nt->u64.address_of_entry_point : nt->u32.address_of_entry_point;
    if (address_of_entry_point == 0 && !is_dll) {
        pmsg_exit("image has no entry point");
    }

    uint64_t image_base = nt->is_64bit ? nt->u64.image_base : nt->u32.image_base;
    if (image_base % 0x10000 != 0) {
        pmsg_exit("image base not a multiple of 64K");
    }

    uint32_t file_alignment = nt->is_64bit ? nt->u64.file_alignment : nt->u32.file_alignment;
    if (file_alignment < 0x200 || file_alignment > 0x10000 ||
        (file_alignment & (file_alignment - 1)) != 0) {
        pmsg_exit("file alignment not a power of 2 between 512 and 64K");
    }

    uint32_t section_alignment =
        nt->is_64bit ? nt->u64.section_alignment : nt->u32.section_alignment;
    if (section_alignment < file_alignment) {
        pmsg_exit("section alignment less than file alignment");
    }

    if (section_alignment < 0x1000 && section_alignment != file_alignment) {
        pmsg_exit("section alignment below page size must equal file alignment");
    }

    uint32_t size_of_image = nt->is_64bit ? nt->u64.size_of_image : nt->u32.size_of_image;
    if (size_of_image % section_alignment != 0) {
        pmsg_exit("size of image not a multiple of section alignment");
    }

    uint32_t size_of_headers = nt->is_64bit ? nt->u64.size_of_headers : nt->u32.size_of_headers;
    if (size_of_headers % file_alignment != 0) {
        pmsg_exit("size of headers not a multiple of file alignment");
    }

    uint64_t number_of_rva_and_sizes =
        nt->is_64bit ? nt->u64.number_of_rva_and_sizes : nt->u32.number_of_rva_and_sizes;
    uint64_t min_optional_size = (nt->is_64bit ? offsetof(ImageOptionalHeaders64, data_directory)
                                               : offsetof(ImageOptionalHeaders32, data_directory)) +
                                 number_of_rva_and_sizes * sizeof(ImageDataDirectory);
    if (nt->file_header.size_of_optional_header < min_optional_size) {
        pmsg_exit("optional header too small for its data directories");
    }
}

size_t nt_get_fixed_size(_Bool is_64bit) {
    if (is_64bit) {
        return offsetof(ImageNtHeaders, u64) + offsetof(ImageOptionalHeaders64, data_directory);
    } else {
        return offsetof(ImageNtHeaders, u32) + offsetof(ImageOptionalHeaders32, data_directory);
    }
}

ImageDataDirectory nt_get_data_directory(const ImageNtHeaders* nt, uint32_t index) {
    assert(nt && index < 16);

    if (nt->is_64bit) {
        if (index >= nt->u64.number_of_rva_and_sizes) {
            return (ImageDataDirectory){0};
        }

        return nt->u64.data_directory[index];
    } else {
        if (index >= nt->u32.number_of_rva_and_sizes) {
            return (ImageDataDirectory){0};
        }

        return nt->u32.data_directory[index];
    }
}

const ImageSectionHeader* nt_header_get_sections(
    const uint8_t* file, size_t file_size, size_t nt_offset, const ImageNtHeaders* nt
) {
    assert(file && nt);

    size_t sections_offset =
        nt_offset + offsetof(ImageNtHeaders, u64) + nt->file_header.size_of_optional_header;
    size_t sections_size = nt->file_header.number_of_sections * sizeof(ImageSectionHeader);
    if (sections_offset > file_size || sections_size > file_size - sections_offset) {
        pmsg_exit("file too small for section table");
    }

    uint32_t size_of_headers = nt->is_64bit ? nt->u64.size_of_headers : nt->u32.size_of_headers;
    if (sections_offset + sections_size > size_of_headers) {
        pmsg_exit("section table extends past size of headers");
    }

    return offset_ptr(file, sections_offset);
}

void check_sections(const ImageNtHeaders* nt, const ImageSectionHeader* sections) {
    assert(nt && sections);

    uint64_t alignment = nt->is_64bit ? nt->u64.section_alignment : nt->u32.section_alignment;
    uint32_t file_alignment = nt->is_64bit ? nt->u64.file_alignment : nt->u32.file_alignment;
    uint32_t size_of_headers = nt->is_64bit ? nt->u64.size_of_headers : nt->u32.size_of_headers;
    uint32_t size_of_image = nt->is_64bit ? nt->u64.size_of_image : nt->u32.size_of_image;
    uint64_t next_address = (size_of_headers + alignment - 1) / alignment * alignment;

    for (uint16_t idx = 0; idx < nt->file_header.number_of_sections; idx++) {
        uint64_t address = sections[idx].virtual_address;
        if (address % alignment != 0) {
            pmsg_exit("section virtual address not a multiple of section alignment");
        }

        if (idx == 0 && address < next_address) {
            pmsg_exit("first section overlaps headers");
        }

        if (idx > 0 && address != next_address) {
            pmsg_exit("sections not in ascending order and adjacent");
        }

        if (sections[idx].pointer_to_raw_data % file_alignment != 0 ||
            sections[idx].size_of_raw_data % file_alignment != 0) {
            pmsg_exit("section raw data pointer or size not a multiple of file alignment");
        }

        uint64_t size = sections[idx].virtual_size != 0 ? sections[idx].virtual_size
                                                        : sections[idx].size_of_raw_data;
        next_address = address + (size + alignment - 1) / alignment * alignment;
    }

    if (next_address > size_of_image) {
        pmsg_exit("sections extend past size of image");
    }
}

ImageTlsDirectory read_tls_directory(
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

void validate_and_relativize_tls_directory(
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
