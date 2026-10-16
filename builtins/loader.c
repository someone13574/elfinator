#include "loader.h"

#include <stdio.h>
#include <unistd.h>

#include "common/winapi.h"

void WINAPIV write_message(const char* msg, uint64_t len) {
    ssize_t n = write(1, msg, (size_t)len);
    (void)n;
}
