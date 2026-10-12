#include "pe_types.h"

#include <assert.h>

#include "util.h"

void check_dos_header(const ImageDosHeader* dos) {
    assert(dos);

    if (dos->magic != 0x5a4d) {
        pmsg_exit("bad dos header magic");
    }
}

void check_nt_headers(const ImageNtHeaders64* nt) {
    assert(nt);

    if (nt->signature != 0x00004550) {
        pmsg_exit("bad NT PE signature");
    }

    if (nt->optional_header.magic != 0x020b) {
        pmsg_exit("not PE32+ (need 64-bit exe)");
    }

    if (nt->file_header.machine != 0x8664) {
        pmsg_exit("not an x86-64 image");
    }

    if (!(nt->file_header.characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
        pmsg_exit("not an executable image (IMAGE_FILE_EXECUTABLE_IMAGE not set)");
    }

    if (nt->file_header.characteristics & IMAGE_FILE_DLL) {
        pmsg_exit("image is a DLL (need an exe)");
    }

    if (nt->optional_header.address_of_entry_point == 0) {
        pmsg_exit("image has no entry point");
    }

    const ImageOptionalHeaders64* opt = &nt->optional_header;
    if (opt->image_base % 0x10000 != 0) {
        pmsg_exit("image base not a multiple of 64K");
    }

    uint32_t file_alignment = opt->file_alignment;
    if (file_alignment < 0x200 || file_alignment > 0x10000 ||
        (file_alignment & (file_alignment - 1)) != 0) {
        pmsg_exit("file alignment not a power of 2 between 512 and 64K");
    }

    if (opt->section_alignment < file_alignment) {
        pmsg_exit("section alignment less than file alignment");
    }

    if (opt->section_alignment < 0x1000 && opt->section_alignment != file_alignment) {
        pmsg_exit("section alignment below page size must equal file alignment");
    }

    if (opt->size_of_image % opt->section_alignment != 0) {
        pmsg_exit("size of image not a multiple of section alignment");
    }

    if (opt->size_of_headers % file_alignment != 0) {
        pmsg_exit("size of headers not a multiple of file alignment");
    }

    uint64_t min_optional_size =
        offsetof(ImageOptionalHeaders64, data_directory) +
        (uint64_t)nt->optional_header.number_of_rva_and_sizes * sizeof(ImageDataDirectory);
    if (nt->file_header.size_of_optional_header < min_optional_size) {
        pmsg_exit("optional header too small for its data directories");
    }
}

ImageDataDirectory
optional_header_get_data_directory(const ImageOptionalHeaders64* opt, uint32_t index) {
    assert(opt && index < 16);

    if (index >= opt->number_of_rva_and_sizes) {
        return (ImageDataDirectory){0};
    }

    return opt->data_directory[index];
}

const ImageSectionHeader*
nt_header_get_sections(const uint8_t* file, size_t file_size, const ImageNtHeaders64* nt) {
    assert(nt);

    const uint8_t* opt = (const uint8_t*)&nt->optional_header;
    const ImageSectionHeader* sections = offset_ptr(opt, nt->file_header.size_of_optional_header);

    size_t sections_offset = (const uint8_t*)sections - file;
    size_t sections_size = nt->file_header.number_of_sections * sizeof(ImageSectionHeader);
    if (sections_offset > file_size || sections_size > file_size - sections_offset) {
        pmsg_exit("file too small for section table");
    }

    if (sections_offset + sections_size > nt->optional_header.size_of_headers) {
        pmsg_exit("section table extends past size of headers");
    }

    return sections;
}

void check_sections(const ImageNtHeaders64* nt, const ImageSectionHeader* sections) {
    assert(nt && sections);

    const ImageOptionalHeaders64* opt = &nt->optional_header;
    uint64_t alignment = opt->section_alignment;
    uint64_t next_address = (opt->size_of_headers + alignment - 1) / alignment * alignment;
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

        if (sections[idx].pointer_to_raw_data % opt->file_alignment != 0 ||
            sections[idx].size_of_raw_data % opt->file_alignment != 0) {
            pmsg_exit("section raw data pointer or size not a multiple of file alignment");
        }

        uint64_t size = sections[idx].virtual_size != 0 ? sections[idx].virtual_size
                                                        : sections[idx].size_of_raw_data;
        next_address = address + (size + alignment - 1) / alignment * alignment;
    }

    if (next_address > opt->size_of_image) {
        pmsg_exit("sections extend past size of image");
    }
}
