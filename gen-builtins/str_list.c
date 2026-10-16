#define _GNU_SOURCE

#include "str_list.h"

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "util.h"

StrList str_list_init(void) {
    const size_t initial_capacity = 8;

    char** strs = malloc(sizeof(char*) * initial_capacity);
    if (!strs) {
        perror_exit("str list malloc");
    }

    return (StrList){.strs = strs, .len = 0, .capacity = initial_capacity};
}

void str_list_free(StrList* list) {
    assert(list && list->strs);

    for (size_t idx = 0; idx < list->len; idx++) {
        assert(list->strs[idx]);
        free(list->strs[idx]);
        list->strs[idx] = NULL;
    }

    free(list->strs);
    list->strs = NULL;
    list->len = 0;
    list->capacity = 0;
}

void str_list_push(StrList* list, const char* str) {
    assert(list && list->strs && str);

    if (list->len == list->capacity) {
        list->capacity *= 2;
        char** tmp = realloc(list->strs, list->capacity * sizeof(char*));
        if (!tmp) {
            perror_exit("str list realloc");
        }

        list->strs = tmp;
    }

    char* dup = strdup(str);
    if (!dup) {
        perror_exit("str list strdup");
    }

    list->strs[list->len++] = dup;
}

static int str_compare(const void* a, const void* b) {
    return strcmp(*(const char**)a, *(const char**)b);
}

void str_list_sort(StrList* list) {
    assert(list && list->strs);

    qsort(list->strs, list->len, sizeof(char*), str_compare);
}

StrListList str_list_list_init(void) {
    const size_t initial_capacity = 4;

    StrList* list = malloc(sizeof(StrList) * initial_capacity);
    if (!list) {
        perror_exit("str list list malloc");
    }

    return (StrListList){.list = list, .len = 0, .capacity = initial_capacity};
}

void str_list_list_free(StrListList* list) {
    assert(list && list->list);

    for (size_t idx = 0; idx < list->len; idx++) {
        str_list_free(&list->list[idx]);
    }

    free(list->list);
    list->list = NULL;
    list->len = 0;
    list->capacity = 0;
}

void str_list_list_push(StrListList* list, StrList element) {
    assert(list && list->list && element.strs);

    if (list->len == list->capacity) {
        list->capacity *= 2;
        StrList* tmp = realloc(list->list, list->capacity * sizeof(StrList));
        if (!tmp) {
            perror_exit("str list list realloc");
        }

        list->list = tmp;
    }

    list->list[list->len++] = element;
}
