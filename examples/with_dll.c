__declspec(dllimport) void print_line(const char* msg);

static const char s0[] = "Hello from with_dll.exe!";
static const char s1[] = "Printed through with_dll_lib.dll";
static const char* const strings[2] = {s0, s1};

int pe_entry(void) {
    for (volatile int idx = 0; idx < 2; idx++) {
        print_line(strings[idx]);
    }

    return 0;
}
