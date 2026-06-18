#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

#define SMALL_BUFFER_SIZE   64
#define MEDIUM_BUFFER_SIZE  256
#define LARGE_BUFFER_SIZE   1024
#define MAX_PATH_LENGTH     4096

#define BOUNDS_CHECK(idx, max) ((idx) >= 0 && (idx) < (max))
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define ERR_SUCCESS         0
#define ERR_INVALID_PARAM  -1
#define ERR_OUT_OF_MEMORY  -2
#define ERR_BUFFER_OVERFLOW -3
#define ERR_INVALID_STATE  -4
#define ERR_NOT_FOUND      -5
#define ERR_IO_ERROR       -6

int str_copy(char *dest, size_t dest_size, const char *src);
int str_append(char *dest, size_t dest_size, const char *src);
char *xstrdup(const char *src);

int buffer_copy_checked(void *dest, size_t dest_size,
                        const void *src, size_t src_size);
int buffer_copy_raw(void *dest, const void *src, size_t size);
void buffer_zero(void *buf, size_t size);

bool validate_buffer_access(const void *buf, size_t buf_size,
                           size_t offset, size_t access_size);
int ring_write_byte_checked(char *buffer, size_t len, int index);
int ring_write_byte(char *buffer, size_t len, int index);

int descriptor_table_store(int *table, size_t count, int slot, int value);
int descriptor_table_store_checked(int *table, size_t count, int slot, int value);

uint32_t scale_unit_count(uint32_t units, uint32_t unit_size);
char *clone_token(const char *src, size_t len);

void log_debug(const char *format, ...);
void log_error(const char *format, ...);
void log_info(const char *format, ...);

#endif
