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

    return sections;
}
