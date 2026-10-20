#include "unicode.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static void put_unit(uint16_t* utf16, size_t* units, uint16_t unit) {
    if (utf16) {
        utf16[*units] = unit;
    }
    (*units)++;
}

// Based on
// https://unicode.org/mail-arch/unicode-ml/y2003-m02/att-0467/01-The_Algorithm_to_Valide_an_UTF-8_String
_Bool utf8_to_utf16(
    const uint8_t* utf8, size_t utf8_len, Utf16Mode mode, _Bool* quote, uint16_t* utf16,
    size_t* utf16_len
) {
    assert(utf8 || utf8_len == 0);
    assert(mode != UTF16_MODE_ARG || quote);

    static const uint8_t next_state[8] = {0, 0, 1, 1, 1, 2, 2, 2};
    static const uint8_t valid_range_start[8] = {0x00, 0x80, 0x80, 0xa0, 0x80, 0x80, 0x90, 0x80};
    static const uint8_t valid_range_end[8] = {0x00, 0xc0, 0xc0, 0xc0, 0xa0, 0xc0, 0xc0, 0x90};

    bool quoted = mode == UTF16_MODE_PROGRAM || (mode == UTF16_MODE_ARG && utf16 && *quote);
    bool needs_quote = utf8_len == 0;
    uint8_t state = 0;
    uint32_t codepoint = 0;
    size_t units = 0;
    size_t backslashes = 0;

    if (quoted) {
        put_unit(utf16, &units, '"');
    }

    for (size_t idx = 0; idx < utf8_len; idx++) {
        uint8_t octet = utf8[idx];

        if (state == 0) {
            if (octet <= 0x7f) {
                if (mode == UTF16_MODE_ARG) {
                    if (octet == ' ' || octet == '\t' || octet == '"') {
                        needs_quote = true;
                    }

                    if (octet == '\\') {
                        backslashes++;
                    } else if (octet == '"') {
                        for (size_t count = 0; count <= backslashes; count++) {
                            put_unit(utf16, &units, '\\');
                        }
                        backslashes = 0;
                    } else {
                        backslashes = 0;
                    }
                } else if (mode == UTF16_MODE_PROGRAM && octet == '"') {
                    return false;
                }

                put_unit(utf16, &units, octet);
                continue;
            } else if (octet >= 0xc2 && octet <= 0xdf) {
                state = 1;
            } else if (octet == 0xe0) {
                state = 3;
            } else if (octet == 0xed) {
                state = 4;
            } else if (octet >= 0xe1 && octet <= 0xef) {
                state = 2;
            } else if (octet == 0xf0) {
                state = 6;
            } else if (octet >= 0xf1 && octet <= 0xf3) {
                state = 5;
            } else if (octet == 0xf4) {
                state = 7;
            } else {
                return false;
            }

            backslashes = 0;
            codepoint = octet & (state == 1 ? 0x1f : state <= 4 ? 0x0f : 0x07);
            continue;
        }

        if (!(valid_range_start[state] <= octet && octet < valid_range_end[state])) {
            return false;
        }

        codepoint = (codepoint << 6) | (octet & 0x3f);
        state = next_state[state];

        if (state == 0) {
            if (codepoint >= 0x10000) {
                uint32_t offset = codepoint - 0x10000;
                put_unit(utf16, &units, (uint16_t)(0xd800 | (offset >> 10)));
                put_unit(utf16, &units, (uint16_t)(0xdc00 | (offset & 0x3ff)));
            } else {
                put_unit(utf16, &units, (uint16_t)codepoint);
            }
        }
    }

    if (state != 0) {
        return false;
    }

    if (mode == UTF16_MODE_ARG) {
        assert(!utf16 || needs_quote == *quote);
        if (!utf16 && needs_quote) {
            quoted = true;
            put_unit(utf16, &units, '"');
        }
    }

    if (quoted) {
        if (mode == UTF16_MODE_ARG) {
            for (size_t count = 0; count < backslashes; count++) {
                put_unit(utf16, &units, '\\');
            }
        }
        put_unit(utf16, &units, '"');
    }

    if (mode == UTF16_MODE_ARG && !utf16) {
        *quote = quoted;
    }

    if (utf16_len) {
        *utf16_len = units;
    }

    return true;
}
