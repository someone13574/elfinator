#include "loader.h"

#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "pe_print.h"
#include "pe_types.h"
#include "util.h"

static void apply_relocations(uint8_t* base, const ImageOptionalHeaders64* opt) {
    assert(base && opt);

    int64_t delta = (int64_t)((uintptr_t)base - opt->image_base);
    ImageDataDirectory dir = opt->data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (delta == 0 || dir.virtual_address == 0) {
        printf("[loader] no relocations needed\n");
        return;
    }

    uint8_t* ptr = rva_offset(base, dir.virtual_address);
    uint8_t* end = ptr + dir.size;
    unsigned long int fixed_entries = 0;

    while (ptr < end) {
        ImageBaseRelocation* block = (ImageBaseRelocation*)ptr;
        if (block->size_of_block == 0) {
            break;
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
                    uint64_t* slot = rva_offset(base, block->virtual_address + offset);
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

void map_image(const uint8_t* file, size_t file_size) {
    assert(file);

    if (file_size < sizeof(ImageDosHeader)) {
        pmsg_exit("file too small for DOS header");
    }

    const ImageDosHeader* dos = (const ImageDosHeader*)file;
    check_dos_header(dos);
    pe_print_dos_header(dos);

    if (dos->lfanew < 0 || file_size < sizeof(ImageNtHeaders64) ||
        (size_t)dos->lfanew > file_size - sizeof(ImageNtHeaders64)) {
        pmsg_exit("file too small for NT headers (bad lfanew)");
    }

    const ImageNtHeaders64* nt = rva_offset(file, dos->lfanew);
    check_nt_headers(nt);
    pe_print_nt_headers_64(nt);

    printf("---------------\n");

    size_t image_size = round_up_pow2(nt->optional_header.size_of_image, 0x1000);
    size_t headers_size = nt->optional_header.size_of_headers;
    if (headers_size > file_size || headers_size > image_size) {
        pmsg_exit("headers outside of file or image (bad size_of_headers)");
    }

    const ImageSectionHeader* sections = nt_header_get_sections(file, file_size, nt);

    uint8_t* base =
        mmap(NULL, image_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        perror_exit("mmap image");
    }

    printf("[loader] mapped image at %p (%zu bytes)\n", base, image_size);

    memcpy(base, file, headers_size);

    for (int idx = 0; idx < nt->file_header.number_of_sections; idx++) {
        const ImageSectionHeader* section = &sections[idx];

        if (section->virtual_address > image_size ||
            section->size_of_raw_data > image_size - section->virtual_address) {
            pmsg_exit("section outside of image (bad virtual_address or size_of_raw_data)");
        }

        if (section->pointer_to_raw_data > file_size ||
            section->size_of_raw_data > file_size - section->pointer_to_raw_data) {
            pmsg_exit("section outside of file (bad pointer_to_raw_data or size_of_raw_data)");
        }

        memcpy(
            rva_offset(base, section->virtual_address),
            rva_offset(file, section->pointer_to_raw_data), section->size_of_raw_data
        );
    }

    apply_relocations(base, &nt->optional_header);
}
