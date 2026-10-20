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
    IMAGE_FILE_DLL = 0x2000,
    IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000
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
    char name[];
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

typedef struct __attribute__((packed)) {
    uint32_t start_address_of_raw_data;
    uint32_t end_address_of_raw_data;
    uint32_t address_of_index;
    uint32_t address_of_call_backs;
    uint32_t size_of_zero_fill;
    uint32_t characteristics;
} ImageTlsDirectory32;

typedef struct __attribute__((packed)) {
    uint64_t start_address_of_raw_data;
    uint64_t end_address_of_raw_data;
    uint64_t address_of_index;
    uint64_t address_of_call_backs;
    uint32_t size_of_zero_fill;
    uint32_t characteristics;
} ImageTlsDirectory;

enum { PROCESS_PARAMETERS_NORMALIZED = 0x1 };

enum { PEB_IMAGE_DYNAMICALLY_RELOCATED = 0x4 };

#if defined(__i386__) || defined(ELFINATOR_COMPAT)

typedef struct {
    uint16_t length;
    uint16_t maximum_length;
    uint32_t buffer;
} UnicodeString32;

typedef struct {
    uint32_t maximum_length;
    uint32_t length;
    uint32_t flags;
    uint32_t debug_flags;
    uint8_t reserved1[0x14];
    UnicodeString32 current_directory;
    uint32_t current_directory_handle;
    UnicodeString32 dll_path;
    UnicodeString32 image_path_name;
    UnicodeString32 command_line;
    uint32_t environment;
    uint8_t reserved2[0x278];
} ProcessParameters32;

typedef struct {
    uint8_t reserved1[2];
    uint8_t being_debugged;
    uint8_t bit_field;
    uint8_t reserved2[0x4];
    uint32_t image_base_address;
    uint32_t ldr_data;
    uint32_t process_parameters;
    uint8_t reserved3[0x4];
    uint32_t process_heap;
    uint32_t fast_peb_lock;
    uint8_t reserved4[0x20];
    uint32_t tls_bitmap;
    uint32_t tls_bitmap_bits[2];
    uint8_t reserved5[0x18];
    uint32_t number_of_processors;
    uint32_t nt_global_flag;
    uint8_t reserved6[0x4];
    int64_t critical_section_timeout;
    uint8_t reserved7[0x28];
    uint32_t loader_lock;
    uint32_t os_major_version;
    uint32_t os_minor_version;
    uint16_t os_build_number;
    uint16_t os_csd_version;
    uint32_t os_platform_id;
    uint32_t image_subsystem;
    uint32_t image_subsystem_major_version;
    uint32_t image_subsystem_minor_version;
    uint32_t active_process_affinity_mask;
    uint8_t reserved8[0x8c];
    uint32_t tls_expansion_bitmap;
    uint32_t tls_expansion_bitmap_bits[32];
    uint32_t session_id;
    uint8_t reserved9[0x2b0];
} ProcessEnvironmentBlock32;

_Static_assert(sizeof(ProcessEnvironmentBlock32) == 0x488, "PEB32 size");
_Static_assert(offsetof(ProcessEnvironmentBlock32, image_base_address) == 0x8, "PEB32 offset");
_Static_assert(offsetof(ProcessEnvironmentBlock32, process_parameters) == 0x10, "PEB32 offset");
_Static_assert(offsetof(ProcessEnvironmentBlock32, number_of_processors) == 0x64, "PEB32 offset");
_Static_assert(offsetof(ProcessEnvironmentBlock32, os_build_number) == 0xac, "PEB32 offset");
_Static_assert(offsetof(ProcessEnvironmentBlock32, image_subsystem) == 0xb4, "PEB32 offset");
_Static_assert(offsetof(ProcessEnvironmentBlock32, session_id) == 0x1d4, "PEB32 offset");

typedef struct {
    uint32_t flink_ptr;
    uint32_t blink_ptr;
} ListEntry32;

typedef struct {
    uint32_t unique_process_ptr;
    uint32_t unique_thread_ptr;
} ClientId32;

typedef struct {
    uint32_t exception_list_ptr;
    uint32_t stack_base_ptr;
    uint32_t stack_limit_ptr;
    uint32_t sub_system_tib_ptr;

    union {
        uint32_t fiber_data_ptr;
        uint32_t version;
    };

    uint32_t arbitrary_user_pointer_ptr;
    uint32_t self_ptr;
} NtTib32;

typedef struct {
    uint32_t active_frame_ptr;
    ListEntry32 frame_list_cache;
    uint32_t flags;
    uint32_t next_cookie_sequence_number;
    uint32_t stack_id;
} ActivationContextStack32;

typedef struct {
    NtTib32 nt_tib;
    uint32_t environment_pointer_ptr;
    ClientId32 client_id;
    uint32_t active_rpc_handle_ptr;
    uint32_t thread_local_storage_pointer_ptr;
    uint32_t process_environment_block_ptr;
    uint32_t last_error_value;
    uint8_t reserved1[0x8c];
    uint32_t current_locale;
    uint8_t reserved2[0xbc];
    ActivationContextStack32 activation_stack;
    uint8_t reserved3[0xc];
    uint32_t activation_context_stack_pointer_ptr;
    uint8_t reserved4[0x508];
    ClientId32 real_client_id;
    uint8_t reserved5[0x53c];
    UnicodeString32 static_unicode_string;
    uint16_t static_unicode_buffer[261];
    uint8_t reserved6[0x2];
    uint32_t deallocation_stack_ptr;
    uint32_t tls_slots_ptr[64];
    ListEntry32 tls_links;
    uint8_t reserved7[0x58];
    uint32_t gdi_batch_count;
    uint8_t reserved8[0x68];
    int32_t wow_teb_offset;
    uint8_t reserved9[0x58];
} ThreadEnvironmentBlock32;

_Static_assert(sizeof(ThreadEnvironmentBlock32) == 0x1038, "TEB32 size");
_Static_assert(
    offsetof(ThreadEnvironmentBlock32, process_environment_block_ptr) == 0x30, "TEB32 offset"
);
_Static_assert(offsetof(ThreadEnvironmentBlock32, activation_stack) == 0x184, "TEB32 offset");
_Static_assert(offsetof(ThreadEnvironmentBlock32, static_unicode_string) == 0xbf8, "TEB32 offset");
_Static_assert(offsetof(ThreadEnvironmentBlock32, wow_teb_offset) == 0xfdc, "TEB32 offset");

#endif // __i386__ || ELFINATOR_COMPAT

#ifdef __x86_64__

typedef struct {
    uint16_t length;
    uint16_t maximum_length;
    uint64_t buffer;
} UnicodeString64;

typedef struct {
    uint32_t maximum_length;
    uint32_t length;
    uint32_t flags;
    uint32_t debug_flags;
    uint8_t reserved1[0x28];
    UnicodeString64 current_directory;
    uint64_t current_directory_handle;
    UnicodeString64 dll_path;
    UnicodeString64 image_path_name;
    UnicodeString64 command_line;
    uint64_t environment;
    uint8_t reserved2[0x3c0];
} ProcessParameters64;

typedef struct {
    uint8_t reserved1[2];
    uint8_t being_debugged;
    uint8_t bit_field;
    uint8_t reserved2[0xc];
    uint64_t image_base_address;
    uint64_t ldr_data;
    uint64_t process_parameters;
    uint8_t reserved3[0x8];
    uint64_t process_heap;
    uint64_t fast_peb_lock;
    uint8_t reserved4[0x38];
    uint64_t tls_bitmap;
    uint32_t tls_bitmap_bits[2];
    uint8_t reserved5[0x30];
    uint32_t number_of_processors;
    uint32_t nt_global_flag;
    int64_t critical_section_timeout;
    uint8_t reserved6[0x48];
    uint64_t loader_lock;
    uint32_t os_major_version;
    uint32_t os_minor_version;
    uint16_t os_build_number;
    uint16_t os_csd_version;
    uint32_t os_platform_id;
    uint32_t image_subsystem;
    uint32_t image_subsystem_major_version;
    uint32_t image_subsystem_minor_version;
    uint8_t reserved7[0x4];
    uint64_t active_process_affinity_mask;
    uint8_t reserved8[0xf8];
    uint64_t tls_expansion_bitmap;
    uint32_t tls_expansion_bitmap_bits[32];
    uint32_t session_id;
    uint8_t reserved9[0x50c];
} ProcessEnvironmentBlock64;

_Static_assert(sizeof(ProcessEnvironmentBlock64) == 0x7d0, "PEB64 size");
_Static_assert(offsetof(ProcessEnvironmentBlock64, image_base_address) == 0x10, "PEB64 offset");
_Static_assert(offsetof(ProcessEnvironmentBlock64, process_parameters) == 0x20, "PEB64 offset");
_Static_assert(offsetof(ProcessEnvironmentBlock64, number_of_processors) == 0xb8, "PEB64 offset");
_Static_assert(offsetof(ProcessEnvironmentBlock64, os_build_number) == 0x120, "PEB64 offset");
_Static_assert(offsetof(ProcessEnvironmentBlock64, image_subsystem) == 0x128, "PEB64 offset");
_Static_assert(offsetof(ProcessEnvironmentBlock64, session_id) == 0x2c0, "PEB64 offset");

typedef struct {
    uint64_t flink_ptr;
    uint64_t blink_ptr;
} ListEntry64;

typedef struct {
    uint64_t unique_process_ptr;
    uint64_t unique_thread_ptr;
} ClientId64;

typedef struct {
    uint64_t exception_list_ptr;
    uint64_t stack_base_ptr;
    uint64_t stack_limit_ptr;
    uint64_t sub_system_tib_ptr;

    union {
        uint64_t fiber_data_ptr;
        uint32_t version;
    };

    uint64_t arbitrary_user_pointer_ptr;
    uint64_t self_ptr;
} NtTib64;

typedef struct {
    uint64_t active_frame_ptr;
    ListEntry64 frame_list_cache;
    uint32_t flags;
    uint32_t next_cookie_sequence_number;
    uint32_t stack_id;
} ActivationContextStack64;

typedef struct {
    NtTib64 nt_tib;
    uint64_t environment_pointer_ptr;
    ClientId64 client_id;
    uint64_t active_rpc_handle_ptr;
    uint64_t thread_local_storage_pointer_ptr;
    uint64_t process_environment_block_ptr;
    uint32_t last_error_value;
    uint8_t reserved1[0x9c];
    uint32_t current_locale;
    uint8_t reserved2[0x184];
    ActivationContextStack64 activation_stack;
    uint8_t reserved3[0x10];
    uint64_t activation_context_stack_pointer_ptr;
    uint8_t reserved4[0x20];
    uint8_t gdi_teb_batch[0x4e8];
    ClientId64 real_client_id;
    uint8_t reserved5[0xa70];
    UnicodeString64 static_unicode_string;
    uint16_t static_unicode_buffer[261];
    uint8_t reserved6[0x6];
    uint64_t deallocation_stack_ptr;
    uint64_t tls_slots_ptr[64];
    ListEntry64 tls_links;
    uint8_t reserved7[0x17c];
    int32_t wow_teb_offset;
    uint8_t reserved8[0x68];
} ThreadEnvironmentBlock64;

_Static_assert(sizeof(ThreadEnvironmentBlock64) == 0x1878, "TEB64 size");
_Static_assert(
    offsetof(ThreadEnvironmentBlock64, process_environment_block_ptr) == 0x60, "TEB64 offset"
);
_Static_assert(offsetof(ThreadEnvironmentBlock64, activation_stack) == 0x290, "TEB64 offset");
_Static_assert(offsetof(ThreadEnvironmentBlock64, gdi_teb_batch) == 0x2f0, "TEB64 offset");
_Static_assert(offsetof(ThreadEnvironmentBlock64, static_unicode_string) == 0x1258, "TEB64 offset");
_Static_assert(offsetof(ThreadEnvironmentBlock64, wow_teb_offset) == 0x180c, "TEB64 offset");

#endif // __x86_64__

void check_dos_header(const ImageDosHeader* dos);
void check_nt_headers(const ImageNtHeaders* nt, _Bool is_dll);
size_t nt_get_fixed_size(_Bool is_64bit);

ImageDataDirectory nt_get_data_directory(const ImageNtHeaders* nt, uint32_t index);
const ImageSectionHeader* nt_header_get_sections(
    const uint8_t* file, size_t file_size, size_t nt_offset, const ImageNtHeaders* nt
);
void check_sections(const ImageNtHeaders* nt, const ImageSectionHeader* sections);
