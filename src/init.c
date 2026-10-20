#define _GNU_SOURCE
#include "init.h"

#include <asm/ldt.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
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
#include "module_map.h"
#include "pe_types.h"
#include "tls.h"
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
    assert(size && name);

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

static uint64_t process_affinity_mask(const ImageNtHeaders* nt) {
    assert(nt);

    if (nt->file_header.characteristics & IMAGE_FILE_UP_SYSTEM_ONLY) {
        return 1;
    }

    uint32_t count = number_of_processors();
    return count >= 64 ? UINT64_MAX : (UINT64_C(1) << count) - 1;
}

static OsVersion os_version(const ImageNtHeaders* nt) {
    assert(nt);

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
    assert(params && layout);

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
    assert(peb && module && params && !module->image.nt.is_64bit);

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

static void init_teb32(
    ThreadEnvironmentBlock32* teb, const ProcessEnvironmentBlock32* peb, uint32_t stack_base,
    uint32_t stack_limit, uint32_t deallocation_stack
) {
    assert(teb && peb);

    teb->nt_tib.exception_list_ptr = 0xffffffff;
    teb->nt_tib.stack_base_ptr = stack_base;
    teb->nt_tib.stack_limit_ptr = stack_limit;
    teb->nt_tib.version = 0x1e00; // OS/2 1.30 TIB
    teb->nt_tib.self_ptr = (uint32_t)(uintptr_t)teb;
    teb->client_id.unique_process_ptr = (uint32_t)getpid();
    teb->client_id.unique_thread_ptr = (uint32_t)gettid();
    teb->process_environment_block_ptr = (uint32_t)(uintptr_t)peb;
    teb->current_locale = 0x0409; // en-US
    teb->activation_context_stack_pointer_ptr = (uint32_t)(uintptr_t)&teb->activation_stack;

    uint32_t frame_list_cache = (uint32_t)(uintptr_t)&teb->activation_stack.frame_list_cache;
    teb->activation_stack.frame_list_cache.flink_ptr = frame_list_cache;
    teb->activation_stack.frame_list_cache.blink_ptr = frame_list_cache;
    teb->real_client_id = teb->client_id;
    teb->static_unicode_string.maximum_length = sizeof(teb->static_unicode_buffer);
    teb->static_unicode_string.buffer = (uint32_t)(uintptr_t)teb->static_unicode_buffer;
    teb->deallocation_stack_ptr = deallocation_stack;
}

#endif

#ifdef __x86_64__

static UnicodeString64 unicode_string64(uint64_t strings, StringLayout layout) {
    return (UnicodeString64){.length = layout.length,
                             .maximum_length = layout.maximum_length,
                             .buffer = strings + layout.offset};
}

static void init_parameters64(ProcessParameters64* params, const ParameterLayout* layout) {
    assert(params && layout);

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
    assert(peb && module && params);

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

static void init_teb64(
    ThreadEnvironmentBlock64* teb, const ProcessEnvironmentBlock64* peb, uint64_t stack_base,
    uint64_t stack_limit, uint64_t deallocation_stack
) {
    assert(teb && peb);

    teb->nt_tib.stack_base_ptr = stack_base;
    teb->nt_tib.stack_limit_ptr = stack_limit;
    teb->nt_tib.version = 0x1e00; // OS/2 1.30 TIB
    teb->nt_tib.self_ptr = (uint64_t)(uintptr_t)teb;
    teb->client_id.unique_process_ptr = (uint64_t)getpid();
    teb->client_id.unique_thread_ptr = (uint64_t)gettid();
    teb->process_environment_block_ptr = (uint64_t)(uintptr_t)peb;
    teb->current_locale = 0x0409; // en-US
    teb->activation_context_stack_pointer_ptr = (uint64_t)(uintptr_t)&teb->activation_stack;

    uint64_t frame_list_cache = (uint64_t)(uintptr_t)&teb->activation_stack.frame_list_cache;
    teb->activation_stack.frame_list_cache.flink_ptr = frame_list_cache;
    teb->activation_stack.frame_list_cache.blink_ptr = frame_list_cache;
    teb->real_client_id = teb->client_id;
    teb->static_unicode_string.maximum_length = sizeof(teb->static_unicode_buffer);
    teb->static_unicode_string.buffer = (uint64_t)(uintptr_t)teb->static_unicode_buffer;
    teb->deallocation_stack_ptr = deallocation_stack;
}

#endif

static void* map_or_exit(size_t size, size_t align, const char* name) {
    size_t page_size = sysconf(_SC_PAGESIZE);
    assert(size > 0 && name);
    assert(is_pow2(align) && align % page_size == 0);

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
    assert(process && process->image && layout);

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
    assert(size > 0 && name);

    size_t page_size = sysconf(_SC_PAGESIZE);
    void* ptr = compat_arena_alloc(0, round_up_pow2(size, page_size), align);
    if (!ptr) {
        pmsg_exit("no reserved low memory available for %s", name);
    }

    return ptr;
}

static uint8_t*
init_compat_process(Process* process, const ParameterLayout* layout, uint8_t** strings32_out) {
    assert(process && process->image && layout && strings32_out);

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

static void
host_stack_location(uintptr_t* base_out, uintptr_t* limit_out, uintptr_t* deallocation_out) {
    assert(base_out && limit_out && deallocation_out);

    pthread_attr_t attr;
    int err = pthread_getattr_np(pthread_self(), &attr);
    if (err != 0) {
        errno = err;
        perror_exit("pthread_getattr_np");
    }

    void* addr;
    size_t size;
    size_t guard_size;
    pthread_attr_getstack(&attr, &addr, &size);
    pthread_attr_getguardsize(&attr, &guard_size);
    pthread_attr_destroy(&attr);

    *base_out = (uintptr_t)addr + size;
    *limit_out = (uintptr_t)addr;
    *deallocation_out = (uintptr_t)addr - guard_size;
}

#if defined(__i386__) || defined(ELFINATOR_COMPAT)

// Returns the selector of a descriptor for the 32-bit TEB in the calling thread's GDT TLS entries.
// desc must be below 4GB
static uint16_t set_teb32_descriptor(ThreadEnvironmentBlock32* teb, struct user_desc* desc) {
    assert(teb && desc);
    assert((uint64_t)(uintptr_t)teb < (1ull << 32) && (uint64_t)(uintptr_t)desc < (1ull << 32));

    static int entry_number = -1;
    *desc = (struct user_desc){.entry_number = (unsigned int)entry_number,
                               .base_addr = (uint32_t)(uintptr_t)teb,
                               .limit = 0xfff,
                               .seg_32bit = 1,
                               .contents = MODIFY_LDT_CONTENTS_DATA,
                               .useable = 1};

    int ret;
#ifdef __x86_64__
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "0"(243), "b"(desc)
                     : "r8", "r9", "r10", "r11", "memory");
#else
    __asm__ volatile("int $0x80" : "=a"(ret) : "0"(243), "b"(desc) : "memory");
#endif
    if (ret < 0) {
        errno = -ret;
        perror_exit("set_thread_area");
    }

    entry_number = (int)desc->entry_number;
    return (uint16_t)(desc->entry_number << 3 | 3);
}

#endif

static void init_native_thread(const Process* process, const ModuleMap* module_map) {
    assert(process && module_map);

    uintptr_t stack_base;
    uintptr_t stack_limit;
    uintptr_t deallocation_stack;
    host_stack_location(&stack_base, &stack_limit, &deallocation_stack);

    size_t page_size = sysconf(_SC_PAGESIZE);
#ifdef __x86_64__
    ThreadEnvironmentBlock64* teb = map_or_exit(sizeof(*teb), page_size, "mmap teb");
    init_teb64(teb, process->peb64, stack_base, stack_limit, deallocation_stack);
    teb->thread_local_storage_pointer_ptr =
        (uint64_t)(uintptr_t)alloc_thread_tls(module_map, true, map_or_exit);
    __asm__ volatile("wrgsbase %0" ::"r"(teb));
#else
    ThreadEnvironmentBlock32* teb = map_or_exit(sizeof(*teb), page_size, "mmap teb");
    init_teb32(teb, process->peb32, stack_base, stack_limit, deallocation_stack);
    teb->thread_local_storage_pointer_ptr =
        (uint32_t)(uintptr_t)alloc_thread_tls(module_map, false, map_or_exit);
    struct user_desc desc;
    uint16_t selector = set_teb32_descriptor(teb, &desc);
    __asm__ volatile("mov %0, %%fs" ::"r"(selector));
#endif
}

#ifdef ELFINATOR_COMPAT

static void init_compat_thread(const Process* process, const ModuleMap* module_map) {
    assert(process && process->image && module_map);

    uintptr_t stack_base;
    uintptr_t stack_limit;
    uintptr_t deallocation_stack;
    host_stack_location(&stack_base, &stack_limit, &deallocation_stack);

    size_t page_size = sysconf(_SC_PAGESIZE);
    size_t stack32_size;
    uint8_t* stack32 =
        compat_alloc_stack(process->image->image.nt.u32.size_of_stack_reserve, &stack32_size);

    size_t teb32_offset = round_up_pow2(sizeof(ThreadEnvironmentBlock64), page_size);
    uint8_t* tebs =
        compat_alloc_or_exit(teb32_offset + sizeof(ThreadEnvironmentBlock32), page_size, "TEBs");
    ThreadEnvironmentBlock64* teb64 = (ThreadEnvironmentBlock64*)tebs;
    ThreadEnvironmentBlock32* teb32 = (ThreadEnvironmentBlock32*)(tebs + teb32_offset);

    init_teb64(teb64, process->peb64, stack_base, stack_limit, deallocation_stack);
    init_teb32(
        teb32, process->peb32, (uint32_t)(uintptr_t)(stack32 + stack32_size),
        (uint32_t)(uintptr_t)(stack32 + page_size), (uint32_t)(uintptr_t)stack32
    );
    teb64->nt_tib.exception_list_ptr = (uint64_t)(uintptr_t)teb32;
    teb64->wow_teb_offset = (int32_t)teb32_offset;
    teb32->gdi_batch_count = (uint32_t)(uintptr_t)teb64;
    teb32->wow_teb_offset = -(int32_t)teb32_offset;
    teb32->thread_local_storage_pointer_ptr =
        (uint32_t)(uintptr_t)alloc_thread_tls(module_map, false, compat_alloc_or_exit);

    __asm__ volatile("wrgsbase %0" ::"r"(teb64));

    // The 32-bit stack is unused at this point, and is below 4GB
    struct user_desc* desc = (struct user_desc*)(stack32 + stack32_size) - 1;
    compat_set_teb32_selector(set_teb32_descriptor(teb32, desc));
}

#endif

void thread_init(const Process* process, const ModuleMap* module_map) {
    assert(process && process->image && module_map);

#ifdef ELFINATOR_COMPAT
    if (!process->image->image.nt.is_64bit) {
        init_compat_thread(process, module_map);
        return;
    }
#endif
    init_native_thread(process, module_map);
}
