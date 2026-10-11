__declspec(dllimport) void write_message(const char* msg, unsigned long long len);

static const char s0[] = "Hello World!\n";
static const char s1[] = "Another string!\n";
static const char* const strings[2] = {s0, s1};

static unsigned long long strlen(const char* str) {
    const char* curr = str;
    while (*curr) {
        curr++;
    }
    return (unsigned long long)(curr - str);
}

int pe_entry(void) {
    for (volatile int idx = 0; idx < 2; idx++) {
        const char* msg = strings[idx];
        write_message(msg, strlen(msg));
    }

    return 0;
}
