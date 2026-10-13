#pragma once

#include "pe_types.h"

extern const char* const image_data_directory_names[16];

void pe_print_dos_header(const ImageDosHeader* header);
void pe_print_file_header(const ImageFileHeader* header);
void pe_print_optional_headers_32(const ImageOptionalHeaders32* headers);
void pe_print_optional_headers_64(const ImageOptionalHeaders64* headers);
void pe_print_nt_headers(const ImageNtHeaders* headers);
void pe_print_export_directory(const ImageExportDirectory* directory);
