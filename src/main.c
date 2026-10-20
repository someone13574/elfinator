#include <asm/hwcap2.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

#include "builtin_dlls.h"
#include "compat.h"
#include "entry.h"
#include "image.h"
#include "init.h"
#include "module_map.h"
#include "util.h"

static void load_builtins(ModuleMap* module_map, _Bool is_64bit) {
    assert(module_map);

#ifdef ELFINATOR_COMPAT
    if (!is_64bit) {
        static BuiltinExport call64_export = {.name = "elfinator_call64"};
        call64_export.fn = compat_call64_entry();
        module_map_insert(
            module_map, (Module){.name = "elfinator32.dll",
                                 .is_builtin = true,
                                 .state = MODULE_INITIALIZED,
                                 .builtin.exports = &call64_export,
                                 .builtin.builtin_count = 1}
        );
        return;
    }
#else
    (void)is_64bit;
#endif

    // Compiled natively, so can be called directly
    for (size_t idx = 0; idx < builtin_dll_count; idx++) {
        module_map_insert(
            module_map, (Module){.name = builtin_dlls[idx].name,
                                 .is_builtin = true,
                                 .state = MODULE_INITIALIZED,
                                 .builtin.exports = builtin_dlls[idx].exports,
                                 .builtin.builtin_count = builtin_dlls[idx].export_count}
        );
    }
}

int main(int argc, char** argv) {
#ifdef __x86_64__
    // TEBs are set with wrgsbase, and 32-bit code swaps FS with rdfsbase/wrfsbase
    if (!(getauxval(AT_HWCAP2) & HWCAP2_FSGSBASE)) {
        pmsg_exit("FSGSBASE not supported by the CPU or enabled by the kernel (needs Linux 5.9)");
    }
#endif

    if (argc < 2) {
        fprintf(stderr, "usage: %s program.exe\n", argv[0]);
        return 1;
    }

    size_t file_size;
    uint8_t* file = map_file(argv[1], &file_size);

    const char* exe_name = strrchr(argv[1], '/');
    exe_name = exe_name ? exe_name + 1 : argv[1];

    ModuleMap module_map = module_map_new(8);
    Module* root_module =
        map_image(&module_map, exe_name, file, file_size, false, IMAGE_ARCH, load_builtins);
    Process process = process_init(root_module, argc, argv);
    thread_init(&process, &module_map);
    int code = start_image(&module_map, root_module);
    detach_image(&module_map, root_module);

    module_map_free(&module_map);
    return code;
}
