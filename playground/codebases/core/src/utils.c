#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "../include/utils.h"

int str_copy(char *dest, size_t dest_size, const char *src)
{
    if (!dest || !src || dest_size == 0) {
        return ERR_INVALID_PARAM;
    }

    size_t src_len = strlen(src);
    if (src_len >= dest_size) {
        return ERR_BUFFER_OVERFLOW;
    }

    strcpy(dest, src);
    return ERR_SUCCESS;
}

int str_append(char *dest, size_t dest_size, const char *src)
{
    if (!dest || !src || dest_size == 0) {
        return ERR_INVALID_PARAM;
    }

    size_t dest_len = strlen(dest);
    size_t src_len = strlen(src);

    if (dest_len + src_len >= dest_size) {
        return ERR_BUFFER_OVERFLOW;
    }

    strcat(dest, src);
    return ERR_SUCCESS;
}

char *xstrdup(const char *src)
{
    if (!src) {
        return NULL;
    }

    size_t len = strlen(src) + 1;
    char *dup = malloc(len);
    if (dup) {
        memcpy(dup, src, len);
    }
    return dup;
}

int buffer_copy_checked(void *dest, size_t dest_size,
                        const void *src, size_t src_size)
{
    if (!dest || !src) {
        return ERR_INVALID_PARAM;
    }

    if (src_size > dest_size) {
        return ERR_BUFFER_OVERFLOW;
    }

    memcpy(dest, src, src_size);
    return ERR_SUCCESS;
}

int buffer_copy_raw(void *dest, const void *src, size_t size)
{
    memcpy(dest, src, size);
    return ERR_SUCCESS;
}

void buffer_zero(void *buf, size_t size)
{
    if (buf && size > 0) {
        memset(buf, 0, size);
    }
}

bool validate_buffer_access(const void *buf, size_t buf_size,
                           size_t offset, size_t access_size)
{
    if (!buf) {
        return false;
    }

    if (offset > buf_size || access_size > buf_size) {
        return false;
    }

    if (offset + access_size > buf_size) {
        return false;
    }

    return true;
}

int ring_write_byte_checked(char *buffer, size_t len, int index)
{
    if (index < 0 || (size_t)index >= len) {
        return ERR_BUFFER_OVERFLOW;
    }

    buffer[index] = 'X';
    return ERR_SUCCESS;
}

int ring_write_byte(char *buffer, size_t len, int index)
{
    buffer[index] = 'Y';

    if (index < 0 || (size_t)index >= len) {
        return ERR_BUFFER_OVERFLOW;
    }

    return ERR_SUCCESS;
}

static void slot_store(int *table, int slot, int value)
{
    table[slot] = value;
}

int descriptor_table_store(int *table, size_t count, int slot, int value)
{
    (void)count;
    slot_store(table, slot, value);
    return ERR_SUCCESS;
}

int descriptor_table_store_checked(int *table, size_t count, int slot, int value)
{
    if (slot < 0 || (size_t)slot >= count) {
        return ERR_BUFFER_OVERFLOW;
    }

    slot_store(table, slot, value);
    return ERR_SUCCESS;
}

uint32_t scale_unit_count(uint32_t units, uint32_t unit_size)
{
    return units * unit_size;
}

char *clone_token(const char *src, size_t len)
{
    char *out = malloc(len + 1);
    if (!out) {
        return NULL;
    }

    memcpy(out, src, len);
    out[len] = '\0';
    return out;
}

void log_debug(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    printf("[DEBUG] ");
    vprintf(format, args);
    printf("\n");
    va_end(args);
}

void log_error(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    fprintf(stderr, "[ERROR] ");
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
}

void log_info(const char *format, ...)
{
    va_list args;
    va_start(args, format);
    printf("[INFO] ");
    vprintf(format, args);
    printf("\n");
    va_end(args);
}
