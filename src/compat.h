#pragma once

#ifdef ELFINATOR_COMPAT

#include <stddef.h>
#include <stdint.h>

void compat_init(uint64_t limit);
// Allocates the calling thread's 32-bit stack, returning its base. The lowest page is a guard page
uint8_t* compat_alloc_stack(uint32_t stack_reserve, size_t* size_out);
// Records the FS selector of the calling thread's 32-bit TEB, loaded whenever 32-bit code runs
void compat_set_teb32_selector(uint16_t selector);
// Calls a 32-bit function on the calling thread's 32-bit stack
uint32_t compat_call32(uint32_t fn, const uint32_t* args, uint32_t nargs);
void* compat_call64_entry(void);

#endif
