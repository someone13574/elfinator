#include "pe_print.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>

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

const char* const image_data_directory_names[16] = {
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

    uint32_t count = headers->number_of_rva_and_sizes;
    if (count > 16) {
        count = 16;
    }

    printf("    data directories:\n");
    for (uint32_t idx = 0; idx < count; idx++) {
        const ImageDataDirectory* dir = &headers->data_directory[idx];
        printf(
            "        %-14s rva: 0x%08" PRIx32 ", size: 0x%08" PRIx32 "\n",
            image_data_directory_names[idx], dir->virtual_address, dir->size
        );
    }
}

void pe_print_nt_headers_64(const ImageNtHeaders64* headers) {
    assert(headers);

    printf("NT headers:\n");
    printf("    signature: 0x%08" PRIx32 "\n", headers->signature);
    pe_print_file_header(&headers->file_header);
    pe_print_optional_headers_64(&headers->optional_header);
}

void pe_print_export_directory(const ImageExportDirectory* directory) {
    assert(directory);

    printf("Export directory:\n");
    printf("    characteristics:          0x%08" PRIx32 "\n", directory->characteristics);
    printf("    time_date_stamp:          0x%08" PRIx32 "\n", directory->time_date_stamp);
    printf(
        "    version:                  %" PRIu16 ".%" PRIu16 "\n", directory->major_version,
        directory->minor_version
    );
    printf("    name:                     0x%08" PRIx32 "\n", directory->name);
    printf("    base:                     %" PRIu32 "\n", directory->base);
    printf("    number_of_functions:      %" PRIu32 "\n", directory->number_of_functions);
    printf("    number_of_names:          %" PRIu32 "\n", directory->number_of_names);
    printf("    address_of_functions:     0x%08" PRIx32 "\n", directory->address_of_functions);
    printf("    address_of_names:         0x%08" PRIx32 "\n", directory->address_of_names);
    printf("    address_of_name_ordinals: 0x%08" PRIx32 "\n", directory->address_of_name_ordinals);
}
