#define _GNU_SOURCE
#include "init.h"

#include <assert.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "../common/unicode.h"
#include "compat.h"
#include "compat_arena.h"
#include "pe_types.h"
#include "util.h"

#define WIN_MAX_PATH 260
#define WIN_OS_MAJOR_VERSION 10
#define WIN_OS_MINOR_VERSION 0
#define WIN_OS_BUILD_NUMBER 26100
#define WIN_OS_PLATFORM_ID_NT 2
#define WIN_CRITICAL_SECTION_TIMEOUT (INT64_C(30 * 24 * 60 * 60) * -10000000)

typedef struct {
    uint16_t length;
    uint16_t maximum_length;
    size_t offset;
} StringLayout;

typedef struct {
    StringLayout current_directory;
    StringLayout image_path_name;
    StringLayout command_line;
    size_t size;
} ParameterLayout;

typedef struct {
    uint32_t major;
    uint32_t minor;
    uint16_t build_number;
    uint32_t platform_id;
} OsVersion;

static StringLayout
layout_string(size_t* size, size_t units, size_t min_maximum_length, const char* name) {
    size_t length = units * sizeof(uint16_t);
    size_t maximum_length = length + sizeof(uint16_t);
    if (maximum_length < min_maximum_length) {
        maximum_length = min_maximum_length;
    }

    if (maximum_length > UINT16_MAX) {
        pmsg_exit("%s too long", name);
    }

    StringLayout layout = {
        .length = (uint16_t)length, .maximum_length = (uint16_t)maximum_length, .offset = *size
    };
    *size += round_up_pow2(maximum_length, sizeof(uint32_t));
    return layout;
}

static uint32_t number_of_processors(void) {
    long int count = sysconf(_SC_NPROCESSORS_ONLN);
    return count < 1 ? 1 : (uint32_t)count;
}

// Uniprocessor images get a single rotating processor, which starts at processor 0
static uint64_t process_affinity_mask(const ImageNtHeaders* nt) {
    if (nt->file_header.characteristics & IMAGE_FILE_UP_SYSTEM_ONLY) {
        return 1;
    }

    uint32_t count = number_of_processors();
    return count >= 64 ? UINT64_MAX : (UINT64_C(1) << count) - 1;
}

static OsVersion os_version(const ImageNtHeaders* nt) {
    uint32_t value = nt->is_64bit ? nt->u64.win32_version_value : nt->u32.win32_version_value;
    if (value == 0) {
        return (OsVersion){.major = WIN_OS_MAJOR_VERSION,
                           .minor = WIN_OS_MINOR_VERSION,
                           .build_number = WIN_OS_BUILD_NUMBER,
                           .platform_id = WIN_OS_PLATFORM_ID_NT};
    }

    return (OsVersion){.major = value & 0xff,
                       .minor = (value >> 8) & 0xff,
                       .build_number = (value >> 16) & 0x3fff,
                       .platform_id = (value >> 30) ^ 2};
}

#if defined(__i386__) || defined(ELFINATOR_COMPAT)

static UnicodeString32 unicode_string32(uint32_t strings, StringLayout layout) {
    return (UnicodeString32){.length = layout.length,
                             .maximum_length = layout.maximum_length,
                             .buffer = strings + (uint32_t)layout.offset};
}

static void init_parameters32(ProcessParameters32* params, const ParameterLayout* layout) {
    uint32_t strings = (uint32_t)(uintptr_t)(params + 1);
    params->maximum_length = (uint32_t)(sizeof(*params) + layout->size);
    params->length = params->maximum_length;
    params->flags = PROCESS_PARAMETERS_NORMALIZED;
    params->current_directory = unicode_string32(strings, layout->current_directory);
    params->image_path_name = unicode_string32(strings, layout->image_path_name);
    params->command_line = unicode_string32(strings, layout->command_line);
}

static void init_peb32(
    ProcessEnvironmentBlock32* peb, const Module* module, const ProcessParameters32* params
) {
    const ImageOptionalHeaders32* optional = &module->image.nt.u32;
    if ((uintptr_t)module->image.base != optional->image_base) {
        peb->bit_field |= PEB_IMAGE_DYNAMICALLY_RELOCATED;
    }

    OsVersion version = os_version(&module->image.nt);
    peb->image_base_address = (uint32_t)(uintptr_t)module->image.base;
    peb->process_parameters = (uint32_t)(uintptr_t)params;
    peb->number_of_processors = number_of_processors();
    peb->critical_section_timeout = WIN_CRITICAL_SECTION_TIMEOUT;
    peb->os_major_version = version.major;
    peb->os_minor_version = version.minor;
    peb->os_build_number = version.build_number;
    peb->os_platform_id = version.platform_id;
    peb->image_subsystem = optional->subsystem;
    peb->image_subsystem_major_version = optional->major_subsystem_version;
    peb->image_subsystem_minor_version = optional->minor_subsystem_version;
    peb->active_process_affinity_mask = (uint32_t)process_affinity_mask(&module->image.nt);
    peb->session_id = 1;
}

#endif

#ifdef __x86_64__

static UnicodeString64 unicode_string64(uint64_t strings, StringLayout layout) {
    return (UnicodeString64){.length = layout.length,
                             .maximum_length = layout.maximum_length,
                             .buffer = strings + layout.offset};
}

static void init_parameters64(ProcessParameters64* params, const ParameterLayout* layout) {
    uint64_t strings = (uint64_t)(uintptr_t)(params + 1);
    params->maximum_length = (uint32_t)(sizeof(*params) + layout->size);
    params->length = params->maximum_length;
    params->flags = PROCESS_PARAMETERS_NORMALIZED;
    params->current_directory = unicode_string64(strings, layout->current_directory);
    params->image_path_name = unicode_string64(strings, layout->image_path_name);
    params->command_line = unicode_string64(strings, layout->command_line);
}

static void init_peb64(
    ProcessEnvironmentBlock64* peb, const Module* module, const ProcessParameters64* params
) {
    const ImageNtHeaders* nt = &module->image.nt;
    uint64_t preferred_base = nt->is_64bit ? nt->u64.image_base : nt->u32.image_base;
    if ((uintptr_t)module->image.base != preferred_base) {
        peb->bit_field |= PEB_IMAGE_DYNAMICALLY_RELOCATED;
    }

    OsVersion version = os_version(nt);
    peb->image_base_address = (uint64_t)(uintptr_t)module->image.base;
    peb->process_parameters = (uint64_t)(uintptr_t)params;
    peb->number_of_processors = number_of_processors();
    peb->critical_section_timeout = WIN_CRITICAL_SECTION_TIMEOUT;
    peb->os_major_version = version.major;
    peb->os_minor_version = version.minor;
    peb->os_build_number = version.build_number;
    peb->os_platform_id = version.platform_id;
    peb->image_subsystem = nt->is_64bit ? nt->u64.subsystem : nt->u32.subsystem;
    peb->image_subsystem_major_version =
        nt->is_64bit ? nt->u64.major_subsystem_version : nt->u32.major_subsystem_version;
    peb->image_subsystem_minor_version =
        nt->is_64bit ? nt->u64.minor_subsystem_version : nt->u32.minor_subsystem_version;
    peb->active_process_affinity_mask = process_affinity_mask(nt);
    peb->session_id = 1;
}

#endif

static void* map_or_exit(size_t size, size_t align, const char* name) {
    size_t page_size = sysconf(_SC_PAGESIZE);
    size = round_up_pow2(size, page_size);

    size_t reserve_size = size + align - page_size;
    uint8_t* reserve =
        mmap(NULL, reserve_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reserve == MAP_FAILED) {
        perror_exit(name);
    }

    uint8_t* ptr = (uint8_t*)round_up_pow2((uintptr_t)reserve, align);
    size_t head_size = (size_t)(ptr - reserve);
    size_t tail_size = reserve_size - head_size - size;
    if (head_size != 0 && munmap(reserve, head_size) != 0) {
        perror_exit("munmap reserve head");
    }

    if (tail_size != 0 && munmap(ptr + size, tail_size) != 0) {
        perror_exit("munmap reserve tail");
    }

    return ptr;
}

static uint8_t* init_native_process(Process* process, const ParameterLayout* layout) {
    size_t page_size = sysconf(_SC_PAGESIZE);
#ifdef __x86_64__
    process->peb64 = map_or_exit(sizeof(ProcessEnvironmentBlock64), page_size, "mmap peb");
    ProcessParameters64* params = map_or_exit(
        sizeof(ProcessParameters64) + layout->size, ALLOCATION_GRANULARITY,
        "mmap process parameters"
    );

    init_parameters64(params, layout);
    init_peb64(process->peb64, process->image, params);
#else
    process->peb32 = map_or_exit(sizeof(ProcessEnvironmentBlock32), page_size, "mmap peb");
    ProcessParameters32* params = map_or_exit(
        sizeof(ProcessParameters32) + layout->size, ALLOCATION_GRANULARITY,
        "mmap process parameters"
    );

    init_parameters32(params, layout);
    init_peb32(process->peb32, process->image, params);
#endif
    return (uint8_t*)(params + 1);
}

#ifdef ELFINATOR_COMPAT

static void* compat_alloc_or_exit(size_t size, size_t align, const char* name) {
    size_t page_size = sysconf(_SC_PAGESIZE);
    void* ptr = compat_arena_alloc(0, round_up_pow2(size, page_size), align);
    if (!ptr) {
        pmsg_exit("no reserved low memory available for %s", name);
    }

    return ptr;
}

static uint8_t*
init_compat_process(Process* process, const ParameterLayout* layout, uint8_t** strings32_out) {
    size_t page_size = sysconf(_SC_PAGESIZE);
    size_t peb32_offset = round_up_pow2(sizeof(ProcessEnvironmentBlock64), page_size);
    uint8_t* pebs =
        compat_alloc_or_exit(peb32_offset + sizeof(ProcessEnvironmentBlock32), page_size, "PEBs");
    ProcessParameters64* params64 = compat_alloc_or_exit(
        sizeof(ProcessParameters64) + layout->size, ALLOCATION_GRANULARITY,
        "64-bit process parameters"
    );
    ProcessParameters32* params32 = compat_alloc_or_exit(
        sizeof(ProcessParameters32) + layout->size, ALLOCATION_GRANULARITY,
        "32-bit process parameters"
    );

    init_parameters64(params64, layout);
    init_parameters32(params32, layout);
    process->peb64 = (ProcessEnvironmentBlock64*)pebs;
    process->peb32 = (ProcessEnvironmentBlock32*)(pebs + peb32_offset);
    init_peb64(process->peb64, process->image, params64);
    init_peb32(process->peb32, process->image, params32);

    *strings32_out = (uint8_t*)(params32 + 1);
    return (uint8_t*)(params64 + 1);
}

#endif

Process process_init(Module* root_module, int argc, char** argv) {
    assert(root_module && argv && argc >= 2);

    char image_path[PATH_MAX + 2] = {'Z', ':'};
    if (!realpath(argv[1], image_path + 2)) {
        perror_exit("image realpath");
    }
    for (char* ch = image_path + 2; *ch; ch++) {
        if (*ch == '/') {
            *ch = '\\';
        }
    }

    char cwd[PATH_MAX + 3] = {'Z', ':'};
    if (!getcwd(cwd + 2, PATH_MAX)) {
        perror_exit("getcwd");
    }
    for (char* ch = cwd + 2; *ch; ch++) {
        if (*ch == '/') {
            *ch = '\\';
        }
    }

    size_t cwd_len = strlen(cwd);
    if (cwd[cwd_len - 1] != '\\') {
        cwd[cwd_len++] = '\\';
        cwd[cwd_len] = '\0';
    }
    size_t image_path_len = strlen(image_path);

    size_t cwd_units;
    if (!utf8_to_utf16((const uint8_t*)cwd, cwd_len, UTF16_MODE_PLAIN, NULL, NULL, &cwd_units)) {
        pmsg_exit("current directory is not valid utf8");
    }

    size_t image_path_units;
    if (!utf8_to_utf16(
            (const uint8_t*)image_path, image_path_len, UTF16_MODE_PLAIN, NULL, NULL,
            &image_path_units
        )) {
        pmsg_exit("image path is not valid utf8");
    }

    size_t command_line_units;
    if (!utf8_to_utf16(
            (const uint8_t*)image_path, image_path_len, UTF16_MODE_PROGRAM, NULL, NULL,
            &command_line_units
        )) {
        pmsg_exit("image path contains a quote");
    }

    for (int idx = 2; idx < argc; idx++) {
        bool quote;
        size_t arg_units;
        if (!utf8_to_utf16(
                (const uint8_t*)argv[idx], strlen(argv[idx]), UTF16_MODE_ARG, &quote, NULL,
                &arg_units
            )) {
            pmsg_exit("argument %d is not valid utf8", idx - 1);
        }
        command_line_units += 1 + arg_units;
    }

    ParameterLayout layout = {0};
    layout.current_directory = layout_string(
        &layout.size, cwd_units, WIN_MAX_PATH * sizeof(uint16_t), "current directory"
    );
    layout.image_path_name = layout_string(&layout.size, image_path_units, 0, "image path");
    layout.command_line = layout_string(&layout.size, command_line_units, 0, "command line");

    Process process = {.image = root_module};
    uint8_t* strings = NULL;
    uint8_t* strings32 = NULL;
#ifdef ELFINATOR_COMPAT
    if (!root_module->image.nt.is_64bit) {
        strings = init_compat_process(&process, &layout, &strings32);
    }
#endif
    if (!strings) {
        strings = init_native_process(&process, &layout);
    }

    uint16_t* cwd16 = (uint16_t*)(strings + layout.current_directory.offset);
    utf8_to_utf16((const uint8_t*)cwd, cwd_len, UTF16_MODE_PLAIN, NULL, cwd16, NULL);
    cwd16[cwd_units] = 0;

    uint16_t* image_path16 = (uint16_t*)(strings + layout.image_path_name.offset);
    utf8_to_utf16(
        (const uint8_t*)image_path, image_path_len, UTF16_MODE_PLAIN, NULL, image_path16, NULL
    );
    image_path16[image_path_units] = 0;

    uint16_t* command_line16 = (uint16_t*)(strings + layout.command_line.offset);
    size_t command_line_pos;
    utf8_to_utf16(
        (const uint8_t*)image_path, image_path_len, UTF16_MODE_PROGRAM, NULL, command_line16,
        &command_line_pos
    );
    for (int idx = 2; idx < argc; idx++) {
        command_line16[command_line_pos++] = ' ';

        bool quote;
        size_t arg_units;
        size_t arg_len = strlen(argv[idx]);
        utf8_to_utf16((const uint8_t*)argv[idx], arg_len, UTF16_MODE_ARG, &quote, NULL, NULL);
        utf8_to_utf16(
            (const uint8_t*)argv[idx], arg_len, UTF16_MODE_ARG, &quote,
            command_line16 + command_line_pos, &arg_units
        );
        command_line_pos += arg_units;
    }
    command_line16[command_line_pos] = 0;

    if (strings32) {
        memcpy(strings32, strings, layout.size);
    }

    return process;
}

void thread_init(const Process* process) {
    assert(process && process->image);

#ifdef ELFINATOR_COMPAT
    if (!process->image->image.nt.is_64bit) {
        compat_alloc_stack(process->image->image.nt.u32.size_of_stack_reserve);
    }
#endif
}
