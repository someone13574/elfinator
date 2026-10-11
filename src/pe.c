#include "pe.h"

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static void perror_exit(const char* message) {
    perror(message);
    exit(1);
}

static void pmsg_exit(const char* message) {
    fprintf(stderr, "%s\n", message);
    exit(1);
}

void pe_print_dos_header(const ImageDosHeader* header) {
    assert(header);

    printf("DOS header:\n");
    printf("    magic:  0x%04" PRIx16 "\n", header->magic);
    printf("    lfanew: 0x%08" PRIx32 "\n", (uint32_t)header->lfanew);
}

void pe_print_file_header(const ImageFileHeader* header) {
    assert(header);

    printf("File header:\n");
    printf("    machine:                 0x%04" PRIx16 "\n", header->machine);
    printf("    number_of_sections:      %" PRIu16 "\n", header->number_of_sections);
    printf("    time_date_stamp:         0x%08" PRIx32 "\n", header->time_date_stamp);
    printf("    pointer_to_symbol_table: 0x%08" PRIx32 "\n", header->pointer_to_symbol_table);
    printf("    number_of_symbols:       %" PRIu32 "\n", header->number_of_symbols);
    printf("    size_of_optional_header: %" PRIu16 "\n", header->size_of_optional_header);
    printf("    characteristics:         0x%04" PRIx16 "\n", header->characteristics);
}

static const char* const data_directory_names[16] = {
    "export", "import",       "resource",       "exception", "security",    "basereloc",
    "debug",  "architecture", "globalptr",      "tls",       "load_config", "bound_import",
    "iat",    "delay_import", "com_descriptor", "reserved",
};

void pe_print_optional_headers_64(const ImageOptionalHeaders64* headers) {
    assert(headers);

    printf("Optional headers:\n");
    printf("    magic:                          0x%04" PRIx16 "\n", headers->magic);
    printf(
        "    linker_version:                 %" PRIu8 ".%" PRIu8 "\n",
        headers->major_linker_version, headers->minor_linker_version
    );
    printf("    size_of_code:                   0x%08" PRIx32 "\n", headers->size_of_code);
    printf(
        "    size_of_initialized_data:       0x%08" PRIx32 "\n", headers->size_of_initialized_data
    );
    printf(
        "    size_of_uninitialized_data:     0x%08" PRIx32 "\n", headers->size_of_uninitialized_data
    );
    printf(
        "    address_of_entry_point:         0x%08" PRIx32 "\n", headers->address_of_entry_point
    );
    printf("    base_of_code:                   0x%08" PRIx32 "\n", headers->base_of_code);
    printf("    image_base:                     0x%016" PRIx64 "\n", headers->image_base);
    printf("    section_alignment:              0x%08" PRIx32 "\n", headers->section_alignment);
    printf("    file_alignment:                 0x%08" PRIx32 "\n", headers->file_alignment);
    printf(
        "    operating_system_version:       %" PRIu16 ".%" PRIu16 "\n",
        headers->major_operating_system_version, headers->minor_operating_system_version
    );
    printf(
        "    image_version:                  %" PRIu16 ".%" PRIu16 "\n",
        headers->major_image_version, headers->minor_image_version
    );
    printf(
        "    subsystem_version:              %" PRIu16 ".%" PRIu16 "\n",
        headers->major_subsystem_version, headers->minor_subsystem_version
    );
    printf("    win32_version_value:            %" PRIu32 "\n", headers->win32_version_value);
    printf("    size_of_image:                  0x%08" PRIx32 "\n", headers->size_of_image);
    printf("    size_of_headers:                0x%08" PRIx32 "\n", headers->size_of_headers);
    printf("    check_sum:                      0x%08" PRIx32 "\n", headers->check_sum);
    printf("    subsystem:                      %" PRIu16 "\n", headers->subsystem);
    printf("    dll_characteristics:            0x%04" PRIx16 "\n", headers->dll_characteristics);
    printf(
        "    size_of_stack_reserve:          0x%016" PRIx64 "\n", headers->size_of_stack_reserve
    );
    printf("    size_of_stack_commit:           0x%016" PRIx64 "\n", headers->size_of_stack_commit);
    printf("    size_of_heap_reserve:           0x%016" PRIx64 "\n", headers->size_of_heap_reserve);
    printf("    size_of_heap_commit:            0x%016" PRIx64 "\n", headers->size_of_heap_commit);
    printf("    loader_flags:                   0x%08" PRIx32 "\n", headers->loader_flags);
    printf("    number_of_rva_and_sizes:        %" PRIu32 "\n", headers->number_of_rva_and_sizes);

    // number_of_rva_and_sizes comes from the file, so clamp it to the array size
    uint32_t count = headers->number_of_rva_and_sizes;
    if (count > 16) {
        count = 16;
    }

    printf("    data directories:\n");
    for (uint32_t i = 0; i < count; i++) {
        const ImageDataDirectory* dir = &headers->data_directory[i];
        printf(
            "        %-14s rva: 0x%08" PRIx32 ", size: 0x%08" PRIx32 "\n", data_directory_names[i],
            dir->virtual_address, dir->size
        );
    }
}

void check_nt_headers(const ImageNtHeaders64* headers) {
    assert(headers);

    if (headers->signature != nt_header_pe_signature) {
        pmsg_exit("bad NT PE signature");
    }

    if (headers->optional_header.magic != opt_header_magic) {
        pmsg_exit("not PE32+ (need 64-bit exe)");
    }

    if (headers->file_header.machine != nt_header_x8664_machine) {
        pmsg_exit("not an x86-64 image");
    }
}

void pe_print_nt_headers_64(const ImageNtHeaders64* headers) {
    assert(headers);

    printf("NT headers:\n");
    printf("    signature: 0x%08" PRIx32 "\n", headers->signature);
    pe_print_file_header(&headers->file_header);
    pe_print_optional_headers_64(&headers->optional_header);
}

void* rva_offset(uint8_t* base, size_t offset) {
    return (void*)(base + offset);
}

/// Round a value up to a power-of-two alignment
static size_t round_up(size_t value, size_t align) {
    return (value + align - 1) & ~(align - 1);
}

/// Fix absolute addresses to account for loading at `base` instead of `opt->image_base`
static void apply_relocations(uint8_t* base, const ImageOptionalHeaders64* opt) {
    assert(base && opt);

    int64_t delta = (int64_t)((uintptr_t)base - opt->image_base);
    ImageDataDirectory basereloc_dir = opt->data_directory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (delta == 0 || basereloc_dir.virtual_address == 0) {
        printf("[loader] no relocations needed\n");
        return;
    }

    uint8_t* ptr = rva_offset(base, basereloc_dir.virtual_address);
    uint8_t* end = ptr + basereloc_dir.size;
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
                    *slot = (uint64_t)delta;
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

void map_image(
    uint8_t* file, size_t file_size, const ImageDosHeader* dos_header,
    const ImageNtHeaders64* nt_header
) {
    assert(file && dos_header && nt_header);

    size_t image_size = round_up(nt_header->optional_header.size_of_image, 0x1000);
    size_t headers_size = nt_header->optional_header.size_of_headers;
    if (headers_size > file_size || headers_size > image_size) {
        pmsg_exit("headers outside file or image (bad size_of_headers)");
    }

    size_t sections_offset = (size_t)dos_header->lfanew +
                             offsetof(ImageNtHeaders64, optional_header) +
                             nt_header->file_header.size_of_optional_header;
    size_t sections_size = nt_header->file_header.number_of_sections * sizeof(ImageSectionHeader);
    if (sections_offset > file_size || sections_size > file_size - sections_offset) {
        pmsg_exit("file too small for section table");
    }

    uint8_t* base =
        mmap(NULL, image_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        perror_exit("mmap image");
    }

    printf("[loader] mapped image at %p (%zu bytes)\n", base, image_size);
    memcpy(base, file, headers_size);

    const ImageSectionHeader* sections = (ImageSectionHeader*)rva_offset(file, sections_offset);
    for (int idx = 0; idx < nt_header->file_header.number_of_sections; idx++) {
        const ImageSectionHeader* section = &sections[idx];

        if (section->virtual_address > image_size) {
            pmsg_exit("section outside image (bad virtual_address)");
        }

        size_t copy_len = section->size_of_raw_data;
        if (copy_len > image_size - section->virtual_address) {
            copy_len = image_size - section->virtual_address;
        }

        if (copy_len == 0) {
            continue;
        }

        if (section->pointer_to_raw_data > file_size ||
            copy_len > file_size - section->pointer_to_raw_data) {
            pmsg_exit("section data outside file (bad pointer_to_raw_data)");
        }

        memcpy(
            rva_offset(base, section->virtual_address),
            rva_offset(file, section->pointer_to_raw_data), copy_len
        );
    }

    apply_relocations(base, &nt_header->optional_header);
}
