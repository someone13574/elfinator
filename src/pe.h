#pragma once

#include <stddef.h>
#include <stdint.h>

static const uint16_t dos_header_magic = 0x5a4d;
static const uint32_t nt_header_pe_signature = 0x00004550;
static const uint16_t opt_header_magic = 0x020b;
static const uint32_t nt_header_x8664_machine = 0x8664;

// Packed attribute lowers alignment requirements when accessed through the structure
// (https://gcc.gnu.org/onlinedocs/gcc/Common-Attributes.html#index-packed)
typedef struct __attribute__((packed)) {
    uint16_t magic;       /// `MZ`
    uint16_t padding[29]; /// ignore
    int32_t lfanew;       /// Offset to NT headers
} ImageDosHeader;

void pe_print_dos_header(const ImageDosHeader* header);

typedef struct __attribute__((packed)) {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
} ImageFileHeader;

void pe_print_file_header(const ImageFileHeader* header);

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

void pe_print_optional_headers_64(const ImageOptionalHeaders64* headers);

typedef struct __attribute__((packed)) {
    uint32_t signature;
    ImageFileHeader file_header;
    ImageOptionalHeaders64 optional_header;
} ImageNtHeaders64;

void check_nt_headers(const ImageNtHeaders64* headers);
void pe_print_nt_headers_64(const ImageNtHeaders64* headers);

void* rva_offset(uint8_t* base, size_t offset);
