#pragma once

#include "image.h"
#include "pe_types.h"

typedef struct {
    const Module* image;
#ifdef __x86_64__
    ProcessEnvironmentBlock64* peb64;
#endif
#if defined(__i386__) || defined(ELFINATOR_COMPAT)
    ProcessEnvironmentBlock32* peb32;
#endif
} Process;

Process process_init(Module* root_module, int argc, char** argv);
void thread_init(const Process* process, const ModuleMap* module_map);
