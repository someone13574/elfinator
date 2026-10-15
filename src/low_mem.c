#include "low_mem.h"

#ifdef ELFINATOR_COMPAT

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "util.h"

#define LOW_MEM_MIN 0x10000ull

typedef struct {
    uint64_t start;
    uint64_t end;
} U64Range;

typedef struct {
    U64Range* ranges;
    size_t len;
    size_t capacity;
} U64RangeList;

static pthread_mutex_t low_mem_lock = PTHREAD_MUTEX_INITIALIZER;
static U64RangeList available_ranges;

static U64RangeList range_list_init(size_t capacity) {
    assert(capacity > 0 && is_pow2(capacity));

    U64Range* ranges = malloc(capacity * sizeof(U64Range));
    if (!ranges) {
        perror_exit("range list malloc");
    }

    return (U64RangeList){.ranges = ranges, .len = 0, .capacity = capacity};
}

static void range_list_insert(U64RangeList* list, U64Range range) {
    assert(list && list->ranges && list->capacity);

    size_t low = 0;
    size_t high = list->len;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        if (list->ranges[mid].start < range.start) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }

    size_t idx = low;
    _Bool merge_prev = idx > 0 && list->ranges[idx - 1].end == range.start;
    _Bool merge_next = idx < list->len && list->ranges[idx].start == range.end;
    if (merge_prev && merge_next) {
        list->ranges[idx - 1].end = list->ranges[idx].end;
        memmove(
            &list->ranges[idx], &list->ranges[idx + 1], (list->len - idx - 1) * sizeof(U64Range)
        );
        list->len--;
        return;
    } else if (merge_prev) {
        list->ranges[idx - 1].end = range.end;
        return;
    } else if (merge_next) {
        list->ranges[idx].start = range.start;
        return;
    }

    if (list->len == list->capacity) {
        size_t new_capacity = list->capacity * 2;
        U64Range* ranges = realloc(list->ranges, new_capacity * sizeof(U64Range));
        if (!ranges) {
            perror_exit("range list realloc");
        }
        list->ranges = ranges;
        list->capacity = new_capacity;
    }

    memmove(&list->ranges[idx + 1], &list->ranges[idx], (list->len - idx) * sizeof(U64Range));
    list->ranges[idx] = range;
    list->len++;
}

static void range_list_remove(U64RangeList* list, uint64_t start, uint64_t end, size_t range_idx) {
    assert(list && list->ranges && range_idx < list->len);

    U64Range range = list->ranges[range_idx];
    assert(range.start <= start && start < end && end <= range.end);

    if (range.start == start && range.end == end) {
        memmove(
            &list->ranges[range_idx], &list->ranges[range_idx + 1],
            (list->len - range_idx - 1) * sizeof(U64Range)
        );
        list->len--;
    } else if (range.start == start) {
        list->ranges[range_idx].start = end;
    } else if (range.end == end) {
        list->ranges[range_idx].end = start;
    } else {
        // Ranges are never adjacent, so they can never merge
        list->ranges[range_idx].end = start;
        range_list_insert(list, (U64Range){.start = end, .end = range.end});
    }
}

static size_t range_list_sum(const U64RangeList* list) {
    assert(list && list->ranges && list->capacity);

    size_t sum = 0;
    for (size_t idx = 0; idx < list->len; idx++) {
        sum += list->ranges[idx].end - list->ranges[idx].start;
    }

    return sum;
}

static void reserve_range(uint64_t start, uint64_t end, uint64_t page_size) {
    void* ptr = mmap(
        (void*)start, end - start, PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0
    );

    if (ptr == MAP_FAILED) {
        if (errno != EEXIST) {
            perror_exit("reserve low memory");
        }

        if (end - start == page_size) {
            // Don't recurse below page size
            return;
        }

        uint64_t mid = start + (end - start) / 2 / page_size * page_size;
        reserve_range(start, mid, page_size);
        reserve_range(mid, end, page_size);
        return;
    }

    if ((uint64_t)(uintptr_t)ptr != start) {
        pmsg_exit("MAP_FIXED_NOREPLACE ignored (needs Linux 4.17)");
    }

    range_list_insert(&available_ranges, (U64Range){.start = start, .end = end});
}

_Bool low_mem_is_reserved() {
    return available_ranges.ranges && available_ranges.capacity != 0;
}

void low_mem_reserve(uint64_t limit) {
    size_t page_size = sysconf(_SC_PAGESIZE);
    assert(limit <= (1ull << 32) && (limit % page_size) == 0 && limit > LOW_MEM_MIN);
    assert(!low_mem_is_reserved());

    available_ranges = range_list_init(16);

    reserve_range(LOW_MEM_MIN, limit, page_size);

    size_t reserved = range_list_sum(&available_ranges);
    size_t requested = limit - LOW_MEM_MIN;
    printf(
        "[loader] reserved %zu of %zu low bytes (%zu bytes already in use)\n", reserved, requested,
        requested - reserved
    );
}

void* low_mem_alloc(uint64_t preferred, size_t size, size_t align) {
    size_t page_size = sysconf(_SC_PAGESIZE);
    assert(size > 0 && size % page_size == 0);
    assert(is_pow2(align) && align % page_size == 0);

    pthread_mutex_lock(&low_mem_lock);
    if (!low_mem_is_reserved()) {
        pthread_mutex_unlock(&low_mem_lock);
        return NULL;
    }

    size_t found_idx = available_ranges.len;
    uint64_t found_start = 0;
    if (preferred != 0 && preferred % align == 0) {
        for (size_t idx = 0; idx < available_ranges.len; idx++) {
            U64Range range = available_ranges.ranges[idx];
            if (range.start <= preferred && preferred < range.end &&
                size <= range.end - preferred) {
                found_idx = idx;
                found_start = preferred;
                break;
            }
        }
    }

    for (size_t idx = 0; found_idx == available_ranges.len && idx < available_ranges.len; idx++) {
        U64Range range = available_ranges.ranges[idx];
        uint64_t start = round_up_pow2(range.start, align);
        if (start >= range.start && start < range.end && size <= range.end - start) {
            found_idx = idx;
            found_start = start;
        }
    }

    if (found_idx == available_ranges.len) {
        pthread_mutex_unlock(&low_mem_lock);
        return NULL;
    }

    // Replace the reservation with a committed mapping
    void* ptr = mmap(
        (void*)(uintptr_t)found_start, size, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0
    );
    if (ptr == MAP_FAILED) {
        perror_exit("mmap low memory");
    }

    range_list_remove(&available_ranges, found_start, found_start + size, found_idx);
    pthread_mutex_unlock(&low_mem_lock);
    return ptr;
}

#endif
