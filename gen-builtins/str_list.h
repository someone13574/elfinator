#pragma once

#include <stddef.h>

typedef struct {
    char** strs;
    size_t len;
    size_t capacity;
} StrList;

StrList str_list_init(void);
void str_list_free(StrList* list);

void str_list_push(StrList* list, const char* str);
void str_list_sort(StrList* list);

typedef struct {
    StrList* list;
    size_t len;
    size_t capacity;
} StrListList;

StrListList str_list_list_init(void);
void str_list_list_free(StrListList* list);

void str_list_list_push(StrListList* list, StrList element);
