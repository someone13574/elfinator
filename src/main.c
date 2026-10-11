#define _GNU_SOURCE

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "pe.h"

static void perror_exit(const char* message) {
    perror(message);
    exit(1);
}

static void pmsg_exit(const char* message) {
    fprintf(stderr, "%s\n", message);
    exit(1);
}

static uint8_t* map_file(const char* path, size_t* size_out) {
    assert(size_out);

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror_exit("open");
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        perror_exit("fstat");
    }

    // mmap rejects zero-length mappings with a confusing EINVAL
    if (st.st_size == 0) {
        pmsg_exit("empty file");
    }

    uint8_t* file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file == MAP_FAILED) {
        perror_exit("mmap file");
    }

    *size_out = st.st_size;
    return file;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s program.exe\n", argv[0]);
        return 1;
    }

    size_t file_size;
    uint8_t* file = map_file(argv[1], &file_size);

    if (file_size < sizeof(ImageDosHeader)) {
        pmsg_exit("file too small for DOS header");
    }

    ImageDosHeader* dos_header = (ImageDosHeader*)file; // safe due to packed attribute
    if (dos_header->magic != dos_header_magic) {
        pmsg_exit("not a PE file (incorrect dos magic)");
    }

    if (dos_header->lfanew < 0 || file_size < sizeof(ImageNtHeaders64) ||
        (size_t)dos_header->lfanew > file_size - sizeof(ImageNtHeaders64)) {
        pmsg_exit("file too small for NT headers (bad lfanew)");
    }

    ImageNtHeaders64* nt_headers = (ImageNtHeaders64*)rva_offset(file, dos_header->lfanew);
    check_nt_headers(nt_headers);

    pe_print_dos_header(dos_header);
    pe_print_nt_headers_64(nt_headers);

    return 0;
}
