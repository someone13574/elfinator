#ifndef __i386__
#error "32-bit images only"
#endif

#define WINAPI __stdcall

#define SYS_WRITE 4
#define STDOUT_FILENO 1

__declspec(dllexport) void write_message(const char* msg, unsigned long long len) {
    int ret;
    __asm__ volatile("int $0x80"
                     : "=a"(ret)
                     : "a"(SYS_WRITE), "b"(STDOUT_FILENO), "c"(msg), "d"((unsigned int)len)
                     : "memory");
    (void)ret;
}

int WINAPI DllMain(void* hinst, unsigned int reason, void* reserved) {
    (void)hinst;
    (void)reason;
    (void)reserved;

    return 1;
}
