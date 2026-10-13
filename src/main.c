#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "image.h"
#include "module_map.h"
#include "util.h"

static void __attribute__((ms_abi)) write_message(const char* msg, uint64_t len) {
    ssize_t n = write(1, msg, (size_t)len);
    (void)n;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s program.exe\n", argv[0]);
        return 1;
    }

    size_t file_size;
    uint8_t* file = map_file(argv[1], &file_size);

    ModuleMap module_map = module_map_new(8);
    BuiltinExport builtin_write_message =
        (BuiltinExport){.name = "write_message", .fn = write_message};
    module_map_insert(
        &module_map, (Module){.name = "loader.dll",
                              .is_builtin = true,
                              .state = MODULE_INITIALIZED,
                              .builtin.exports = &builtin_write_message,
                              .builtin.builtin_count = 1}
    );

    const char* exe_name = strrchr(argv[1], '/');
    exe_name = exe_name ? exe_name + 1 : argv[1];
    Module* root_module = map_image(&module_map, exe_name, file, file_size, false);
    int code = start_image(&module_map, root_module);
    detach_image(&module_map, root_module);

    module_map_free(&module_map);
    return code;
}
