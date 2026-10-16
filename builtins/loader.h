#pragma once

#include <stdint.h>

#include "common/winapi.h"

void WINAPIV write_message(const char* msg, uint64_t len);
