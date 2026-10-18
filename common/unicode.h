#pragma once

#include <stddef.h>
#include <stdint.h>

/// Returns true for valid utf8 streams. If `utf16_len` is not null, it returns the length of the
/// equivalent utf16 stream, and if `utf16` is not null, it writes the utf16 units (buffer *must* be
/// long enough). `utf16` may be partially written if validation fails, `utf16_len` will only be
/// written on success.
_Bool utf8_to_utf16(const uint8_t* utf8, size_t utf8_len, uint16_t* utf16, size_t* utf16_len);
