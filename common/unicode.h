#pragma once

#include <stddef.h>
#include <stdint.h>

typedef enum {
    /// Converts the stream as is
    UTF16_MODE_PLAIN,
    /// Quotes and escapes the stream as a command line argument for CommandLineToArgvW
    UTF16_MODE_ARG,
    /// Always quotes the stream without escaping. Returns false if the path contains a quote
    UTF16_MODE_PROGRAM,
} Utf16Mode;

/// Returns true for valid utf8 streams. If `utf16_len` is not null, it returns the length of the
/// equivalent utf16 stream, and if `utf16` is not null, it writes the utf16 units (buffer *must* be
/// long enough). `utf16` may be partially written if validation fails, `utf16_len` will only be
/// written on success.
///
/// In `UTF16_MODE_ARG`, `quote` must not be null. When `utf16` is null (measure pass), it returns
/// whether the arg needs quotes (it is empty or contains a space, tab, or quote) on success. When
/// `utf16` is not null (write pass), it must hold the value returned by the measure pass. It is
/// ignored in other modes.
_Bool utf8_to_utf16(
    const uint8_t* utf8, size_t utf8_len, Utf16Mode mode, _Bool* quote, uint16_t* utf16,
    size_t* utf16_len
);
