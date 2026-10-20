#include "reloc.h"

#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "pe_types.h"
#include "util.h"

void apply_relocations(uint8_t* base, size_t image_size, const ImageNtHeaders* nt) {
    assert(base && nt);

    size_t image_base = nt->is_64bit ? nt->u64.image_base : nt->u32.image_base;
    int64_t delta = (int64_t)((uintptr_t)base - image_base);
    ImageDataDirectory dir = nt_get_data_directory(nt, IMAGE_DIRECTORY_ENTRY_BASERELOC);
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
                case IMAGE_REL_BASED_HIGHLOW: {
                    size_t target = (size_t)block->virtual_address + (size_t)offset;
                    u32_align1* slot =
                        rva_offset_ranged(base, target, sizeof(u32_align1), image_size);
                    *slot += (uint32_t)delta;
                    fixed_entries++;
                    break;
                }
                default: {
                    pmsg_exit("unimplemented base relocation entry type %d", type);
                }
            }
        }

        ptr += block->size_of_block;
    }

    printf("[loader] applied %lu relocations, delta=0x%016" PRIx64 "\n", fixed_entries, delta);
}
