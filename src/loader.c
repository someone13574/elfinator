#include "loader.h"

#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <unistd.h>

#include "pe_print.h"
#include "pe_types.h"
#include "util.h"

#define LOADER_PAGE_SIZE 0x1000
#define LOADER_IMAGE_ALIGNMENT 0x10000

static void apply_relocations(uint8_t* base, size_t image_size, const ImageOptionalHeaders64* opt) {
    assert(base && opt);

    int64_t delta = (int64_t)((uintptr_t)base - opt->image_base);
    ImageDataDirectory dir =
        optional_header_get_data_directory(opt, IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (delta == 0 || dir.virtual_address == 0) {
        printf("[loader] no relocations needed\n");
        return;
    }

    if (dir.virtual_address % 4 != 0) {
        pmsg_exit("relocation directory not 4-byte aligned\n");
    }

    uint8_t* ptr = rva_offset_ranged(base, dir.virtual_address, dir.size, image_size);
    uint8_t* end = ptr + dir.size;
    unsigned long int fixed_entries = 0;

    while (ptr < end) {
        if ((size_t)(end - ptr) < sizeof(ImageBaseRelocation)) {
            pmsg_exit("truncated image base relocation header");
        }

        ImageBaseRelocation* block = (ImageBaseRelocation*)ptr;
        if (block->size_of_block == 0) {
            break;
        }

        if (block->size_of_block < sizeof(ImageBaseRelocation) || block->size_of_block % 4 != 0 ||
            (size_t)(end - ptr) < block->size_of_block) {
            pmsg_exit("bad base relocation block size");
        }

        uint16_t* entries = (uint16_t*)(ptr + sizeof(ImageBaseRelocation));
        int count = (block->size_of_block - sizeof(ImageBaseRelocation)) / sizeof(uint16_t);
        for (int idx = 0; idx < count; idx++) {
            int type = entries[idx] >> 12;
            int offset = entries[idx] & 0xfff;
            switch (type) {
                case IMAGE_REL_BASED_ABSOLUTE: {
                    break;
                }
                case IMAGE_REL_BASED_DIR64: {
                    size_t target = (size_t)block->virtual_address + (size_t)offset;
                    u64_align1* slot =
                        rva_offset_ranged(base, target, sizeof(u64_align1), image_size);
                    *slot += (uint64_t)delta;
                    fixed_entries++;
                    break;
                }
                default: {
                    fprintf(stderr, "unimplemented base relocation entry type %d\n", type);
                    exit(1);
                }
            }
        }

        ptr += block->size_of_block;
    }

    printf("[loader] applied %lu relocations, delta=0x%016" PRIx64 "\n", fixed_entries, delta);
}

static void __attribute__((ms_abi)) write_message(const char* msg, uint64_t len) {
    ssize_t n = write(1, msg, (size_t)len);
    (void)n;
}

static void resolve_imports(uint8_t* base, size_t image_size, const ImageOptionalHeaders64* opt) {
    assert(base && opt);

    ImageDataDirectory dir = optional_header_get_data_directory(opt, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (dir.virtual_address == 0) {
        printf("[loader] no imports\n");
        return;
    }

    const ImageImportDescriptor* desc =
        rva_offset_ranged(base, dir.virtual_address, dir.size, image_size);
    size_t max_count = dir.size / sizeof(ImageImportDescriptor);
    for (size_t idx = 0; idx < max_count && desc[idx].name != 0; idx++) {
        const char* dll_name = rva_cstring(base, desc[idx].name, image_size);
        printf("[loader] DLL name: %s\n", dll_name);

        // Sometime the IAT doubles as the ILT
        uint32_t ilt_rva =
            desc[idx].original_first_thunk ? desc[idx].original_first_thunk : desc[idx].first_thunk;

        const void* image_end;
        u64_align1* ilt = rva_offset(base, ilt_rva, image_size, &image_end);
        u64_align1* iat = rva_offset(base, desc[idx].first_thunk, image_size, NULL);

        for (; *ilt != 0; ilt++, iat++) {
            if ((void*)ilt >= image_end || (void*)iat >= image_end) {
                pmsg_exit("ilt or iat exceeded image size");
            }

            if (*ilt & 0x8000000000000000ull) {
                pmsg_exit("unimplemented: import by ordinal\n");
            } else {
                size_t rva = *ilt & 0x7FFFFFFF;
                if (rva % 2 != 0 || rva > image_size || 2 > image_size - rva) {
                    pmsg_exit("invalid ilt pointer");
                }

                ImageImportByName* image_import_by_name = rva_offset(base, rva, image_size, NULL);
                printf(
                    "[loader] hint: %hu, name: %s\n", image_import_by_name->hint,
                    image_import_by_name->name
                );

                if (strcasecmp(dll_name, "loader.dll") == 0 &&
                    strcmp(image_import_by_name->name, "write_message") == 0) {
                    void* fn = write_message;
                    printf(
                        "[loader] resolved %s/%s to %p\n", dll_name, image_import_by_name->name, fn
                    );
                    *iat = (uint64_t)(uintptr_t)fn;
                } else {
                    pmsg_exit("unknown fn");
                }
            }
        }
    }
}

static void set_protections(
    uint8_t* base, const ImageSectionHeader* sections, uint16_t num_sections, size_t image_size
) {
    assert(base && image_size % LOADER_PAGE_SIZE == 0);

    size_t num_pages = image_size / LOADER_PAGE_SIZE;
    uint8_t* page_prots = calloc(num_pages, 1);
    if (!page_prots) {
        perror_exit("calloc page protections");
    }

    for (uint16_t idx = 0; idx < num_sections; idx++) {
        int prot = 0;
        if (sections[idx].characteristics & 0x20000000u) {
            prot |= PROT_EXEC;
        }

        if (sections[idx].characteristics & 0x40000000u) {
            prot |= PROT_READ;
        }

        if (sections[idx].characteristics & 0x80000000u) {
            prot |= PROT_WRITE;
        }

        if (prot == 0) {
            prot = PROT_READ;
        }

        size_t virtual_size = sections[idx].virtual_size > sections[idx].size_of_raw_data
                                  ? sections[idx].virtual_size
                                  : sections[idx].size_of_raw_data;
        if (virtual_size == 0) {
            continue;
        }

        size_t start = sections[idx].virtual_address;
        rva_offset_ranged(base, start, virtual_size, image_size);
        size_t first_page = start / LOADER_PAGE_SIZE;
        size_t last_page = (start + virtual_size - 1) / LOADER_PAGE_SIZE;
        for (size_t page = first_page; page <= last_page; page++) {
            page_prots[page] |= prot;
        }

        char name[9] = {0};
        memcpy(name, sections[idx].name, 8);
        fprintf(
            stderr, "[loader] protect: %-8s %c%c%c\n", name, (prot & PROT_READ) ? 'r' : '-',
            (prot & PROT_WRITE) ? 'w' : '-', (prot & PROT_EXEC) ? 'x' : '-'
        );
    }

    size_t page = 0;
    while (page < num_pages) {
        size_t run_end = page + 1;
        while (run_end < num_pages && page_prots[run_end] == page_prots[page]) {
            run_end++;
        }

        if (page_prots[page] != 0) {
            uint8_t* addr = base + page * LOADER_PAGE_SIZE;
            assert((uintptr_t)addr % LOADER_PAGE_SIZE == 0);
            if (mprotect(addr, (run_end - page) * LOADER_PAGE_SIZE, page_prots[page]) != 0) {
                perror_exit("mprotect");
            }
        }

        page = run_end;
    }

    free(page_prots);
}

int load_and_run_image(const uint8_t* file, size_t file_size) {
    assert(file);
    assert(sysconf(_SC_PAGESIZE) == LOADER_PAGE_SIZE);

    if (file_size < sizeof(ImageDosHeader)) {
        pmsg_exit("file too small for DOS header");
    }

    const ImageDosHeader* dos = (const ImageDosHeader*)file;
    check_dos_header(dos);
    pe_print_dos_header(dos);

    size_t nt_fixed_size = offsetof(ImageNtHeaders64, optional_header) +
                           offsetof(ImageOptionalHeaders64, data_directory);
    if (dos->lfanew < 0 || file_size < nt_fixed_size ||
        (size_t)dos->lfanew > file_size - nt_fixed_size) {
        pmsg_exit("file too small for NT headers (bad lfanew)");
    }

    const ImageNtHeaders64* nt = offset_ptr(file, dos->lfanew);
    check_nt_headers(nt);
    const ImageSectionHeader* sections = nt_header_get_sections(file, file_size, nt);
    pe_print_nt_headers_64(nt);

    printf("---------------\n");

    size_t image_size = round_up_pow2(nt->optional_header.size_of_image, LOADER_PAGE_SIZE);
    size_t headers_size = nt->optional_header.size_of_headers;
    if (headers_size > file_size || headers_size > image_size) {
        pmsg_exit("headers outside of file or image (bad size_of_headers)");
    }

    size_t reserve_size = image_size + LOADER_IMAGE_ALIGNMENT - LOADER_PAGE_SIZE;
    uint8_t* reserve =
        mmap(NULL, reserve_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reserve == MAP_FAILED) {
        perror_exit("mmap image");
    }

    uint8_t* base = (uint8_t*)round_up_pow2((uintptr_t)reserve, LOADER_IMAGE_ALIGNMENT);
    size_t head_size = (size_t)(base - reserve);
    size_t tail_size = reserve_size - head_size - image_size;
    if (head_size != 0 && munmap(reserve, head_size) != 0) {
        perror_exit("munmap image head");
    }

    if (tail_size != 0 && munmap(base + image_size, tail_size) != 0) {
        perror_exit("munmap image tail");
    }

    printf("[loader] mapped image at %p (%zu bytes)\n", base, image_size);

    memcpy(base, file, headers_size);

    for (int idx = 0; idx < nt->file_header.number_of_sections; idx++) {
        const ImageSectionHeader* section = &sections[idx];

        if (section->virtual_address > image_size ||
            section->size_of_raw_data > image_size - section->virtual_address) {
            pmsg_exit("section outside of image (bad virtual_address or size_of_raw_data)");
        }

        if (section->pointer_to_raw_data > file_size ||
            section->size_of_raw_data > file_size - section->pointer_to_raw_data) {
            pmsg_exit("section outside of file (bad pointer_to_raw_data or size_of_raw_data)");
        }

        memcpy(
            offset_ptr(base, section->virtual_address),
            offset_ptr(file, section->pointer_to_raw_data), section->size_of_raw_data
        );
    }

    apply_relocations(base, image_size, &nt->optional_header);
    resolve_imports(base, image_size, &nt->optional_header);
    set_protections(base, sections, nt->file_header.number_of_sections, image_size);

    typedef int(__attribute__((ms_abi)) * EntryPoint)(void);
    EntryPoint entry =
        (EntryPoint)rva_offset(base, nt->optional_header.address_of_entry_point, image_size, NULL);
    printf("[loader] jumping to entry at %p\n\n", (void*)entry);
    int code = entry();
    printf("\n[loader] entry returned exit code %d\n", code);
    return code;
}
