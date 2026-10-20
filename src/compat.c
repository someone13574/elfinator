#include "compat.h"

#ifdef ELFINATOR_COMPAT

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "builtin_dlls.h"
#include "low_mem.h"
#include "util.h"

extern const uint8_t compat_start[];
extern const uint8_t compat_end[];
extern const uint8_t call32_enter[];
extern const uint8_t call64_enter[];
extern const uint8_t call64_dispatch[];

// Windows linker default when the image doesn't specify one
#define COMPAT_DEFAULT_STACK_RESERVE 0x100000u

static uint32_t (*call32)(uint32_t fn, uint32_t stack_top, const uint32_t* args, uint32_t nargs);
static _Thread_local uint32_t stack_top;
static _Thread_local uint32_t call32_depth;
static uint8_t* compat_base;

void compat_init(uint64_t limit) {
    size_t page_size = sysconf(_SC_PAGESIZE);
    size_t code_size = (size_t)(compat_end - compat_start);
    assert(code_size <= page_size && page_size <= LOW_MEM_TOP_GAP);

    uint64_t addr = limit - LOW_MEM_TOP_GAP;
    void* ptr = mmap(
        (void*)(uintptr_t)addr, page_size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0
    );
    if (ptr == MAP_FAILED) {
        perror_exit("mmap call32");
    }

    if ((uint64_t)(uintptr_t)ptr != addr) {
        pmsg_exit("MAP_FIXED_NOREPLACE ignored (needs Linux 4.17)");
    }

    uint8_t* base = ptr;
    memcpy(base, compat_start, code_size);

    void (*dispatch)(uint32_t, const uint64_t*, uint64_t*) = builtins_dispatch;
    memcpy(base + (call64_dispatch - compat_start), &dispatch, sizeof(dispatch));

    if (mprotect(ptr, page_size, PROT_READ | PROT_EXEC) != 0) {
        perror_exit("mprotect call32");
    }

    compat_base = base;
    call32 = (void*)(base + (call32_enter - compat_start));
}

void* compat_call64_entry(void) {
    assert(compat_base);
    return compat_base + (call64_enter - compat_start);
}

void compat_alloc_stack(uint32_t stack_reserve) {
    assert(stack_top == 0);
    size_t page_size = sysconf(_SC_PAGESIZE);

    if (stack_reserve == 0) {
        stack_reserve = COMPAT_DEFAULT_STACK_RESERVE;
    }
    size_t stack_size = round_up_pow2(stack_reserve, page_size) + page_size;
    uint8_t* stack = low_mem_alloc(0, stack_size, page_size);
    if (!stack) {
        pmsg_exit("no reserved low memory available for 32-bit stack");
    }

    if (mprotect(stack, page_size, PROT_NONE) != 0) {
        perror_exit("mprotect 32-bit stack guard");
    }

    stack_top = (uint32_t)(uintptr_t)(stack + stack_size);
}

uint32_t compat_call32(uint32_t fn, const uint32_t* args, uint32_t nargs) {
    assert(call32 && stack_top != 0);

    uint32_t top = call32_depth == 0 ? stack_top : 0;
    call32_depth++;
    uint32_t ret = call32(fn, top, args, nargs);
    call32_depth--;
    return ret;
}

#endif
