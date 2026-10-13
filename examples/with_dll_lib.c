__declspec(dllimport) void write_message(const char* msg, unsigned long long len);

static const char attach_msg[] = "with_dll_lib.dll: process attach\n";
static const char detach_msg[] = "with_dll_lib.dll: process detach\n";
static const char newline[] = "\n";

static unsigned long long strlen(const char* str) {
    const char* curr = str;
    while (*curr) {
        curr++;
    }
    return (unsigned long long)(curr - str);
}

__declspec(dllexport) void print_line(const char* msg) {
    write_message(msg, strlen(msg));
    write_message(newline, sizeof(newline) - 1);
}

int __stdcall DllMain(void* hinst, unsigned int reason, void* reserved) {
    (void)hinst;
    (void)reserved;

    if (reason == 1) {
        write_message(attach_msg, sizeof(attach_msg) - 1);
    } else if (reason == 0) {
        write_message(detach_msg, sizeof(detach_msg) - 1);
    }

    return 1;
}
