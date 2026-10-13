#pragma once

#include <stddef.h>
#include <stdint.h>

typedef struct __attribute__((packed)) {
    uint16_t magic;
    uint16_t padding[29];
    int32_t lfanew;
} ImageDosHeader;

typedef struct __attribute__((packed)) {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
} ImageFileHeader;

enum {
    IMAGE_FILE_RELOCS_STRIPPED = 0x0001,
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002,
    IMAGE_FILE_DLL = 0x2000
};

enum {
    IMAGE_DIRECTORY_ENTRY_EXPORT = 0,
    IMAGE_DIRECTORY_ENTRY_IMPORT = 1,
    IMAGE_DIRECTORY_ENTRY_RESOURCE = 2,
    IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3,
    IMAGE_DIRECTORY_ENTRY_SECURITY = 4,
    IMAGE_DIRECTORY_ENTRY_BASERELOC = 5,
    IMAGE_DIRECTORY_ENTRY_DEBUG = 6,
    IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7,
    IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8,
    IMAGE_DIRECTORY_ENTRY_TLS = 9,
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10,
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11,
    IMAGE_DIRECTORY_ENTRY_IAT = 12,
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13,
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14
};

typedef struct __attribute__((packed)) {
    uint32_t virtual_address;
    uint32_t size;
} ImageDataDirectory;

typedef struct __attribute__((packed)) {
    uint16_t magic;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint32_t base_of_data;
    uint32_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_operating_system_version;
    uint16_t minor_operating_system_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t check_sum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint32_t size_of_stack_reserve;
    uint32_t size_of_stack_commit;
    uint32_t size_of_heap_reserve;
    uint32_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    ImageDataDirectory data_directory[16];
} ImageOptionalHeaders32;

typedef struct __attribute__((packed)) {
    uint16_t magic;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_operating_system_version;
    uint16_t minor_operating_system_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t check_sum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t size_of_stack_reserve;
    uint64_t size_of_stack_commit;
    uint64_t size_of_heap_reserve;
    uint64_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    ImageDataDirectory data_directory[16];
} ImageOptionalHeaders64;

typedef struct __attribute__((packed)) {
    uint32_t signature;
    ImageFileHeader file_header;

    union {
        ImageOptionalHeaders32 u32;
        ImageOptionalHeaders64 u64;
    };

    _Bool is_64bit;
} ImageNtHeaders;

typedef struct __attribute__((packed)) {
    uint8_t name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_line_numbers;
    uint16_t number_of_relocations;
    uint16_t number_of_line_numbers;
    uint32_t characteristics;
} ImageSectionHeader;

enum {
    IMAGE_REL_BASED_ABSOLUTE = 0,
    IMAGE_REL_BASED_HIGH = 1,
    IMAGE_REL_BASED_LOW = 2,
    IMAGE_REL_BASED_HIGHLOW = 3,
    IMAGE_REL_BASED_HIGHADJ = 4,
    IMAGE_REL_BASED_DIR64 = 10
};

enum { DLL_PROCESS_DETACH = 0, DLL_PROCESS_ATTACH = 1 };

typedef struct __attribute__((packed)) {
    uint32_t virtual_address;
    uint32_t size_of_block;
} ImageBaseRelocation;

typedef struct __attribute__((packed)) {
    uint32_t original_first_thunk;
    uint32_t time_date_stamp;
    uint32_t forwarder_chain;
    uint32_t name;
    uint32_t first_thunk;
} ImageImportDescriptor;

typedef struct {
    uint16_t hint;
    char name[1];
} ImageImportByName;

typedef struct __attribute__((packed)) {
    uint32_t characteristics;
    uint32_t time_date_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t name;
    uint32_t base;
    uint32_t number_of_functions;
    uint32_t number_of_names;
    uint32_t address_of_functions;
    uint32_t address_of_names;
    uint32_t address_of_name_ordinals;
} ImageExportDirectory;

void check_dos_header(const ImageDosHeader* dos);
void check_nt_headers(const ImageNtHeaders* nt, _Bool is_dll);
size_t nt_get_fixed_size(_Bool is_64bit);

ImageDataDirectory nt_get_data_directory(const ImageNtHeaders* nt, uint32_t index);
const ImageSectionHeader* nt_header_get_sections(
    const uint8_t* file, size_t file_size, size_t nt_offset, const ImageNtHeaders* nt
);
void check_sections(const ImageNtHeaders* nt, const ImageSectionHeader* sections);
