#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "../include/config.h"

ConfigContext *config_create(void)
{
    ConfigContext *ctx = malloc(sizeof(ConfigContext));
    if (!ctx) {
        return NULL;
    }

    ctx->entries = NULL;
    ctx->entry_count = 0;
    ctx->is_loaded = false;
    memset(ctx->config_file_path, 0, sizeof(ctx->config_file_path));

    return ctx;
}

void config_destroy(ConfigContext *ctx)
{
    if (!ctx) {
        return;
    }

    ConfigEntry *entry = ctx->entries;
    while (entry) {
        ConfigEntry *next = entry->next;
        free(entry);
        entry = next;
    }

    free(ctx);
}

int config_init(ConfigContext *ctx)
{
    if (!ctx) {
        return ERR_INVALID_PARAM;
    }

    ctx->is_loaded = false;
    return ERR_SUCCESS;
}

int config_parse_line(char *line, char *key, char *value)
{
    if (!line || !key || !value) {
        return ERR_INVALID_PARAM;
    }

    char *eq = strchr(line, '=');
    if (!eq) {
        return ERR_INVALID_PARAM;
    }

    size_t key_len = eq - line;
    if (key_len >= MAX_KEY_LENGTH) {
        key_len = MAX_KEY_LENGTH - 1;
    }
    strncpy(key, line, key_len);
    key[key_len] = '\0';

    while (key_len > 0 && key[key_len - 1] == ' ') {
        key[--key_len] = '\0';
    }

    char *val_start = eq + 1;
    while (*val_start == ' ') {
        val_start++;
    }

    str_copy(value, MAX_VALUE_LENGTH, val_start);

    size_t val_len = strlen(value);
    if (val_len > 0 && value[val_len - 1] == '\n') {
        value[val_len - 1] = '\0';
    }

    return ERR_SUCCESS;
}

int config_validate_entry(const char *key, const char *value)
{
    if (!key || !value) {
        return ERR_INVALID_PARAM;
    }

    if (strlen(key) == 0) {
        return ERR_INVALID_PARAM;
    }

    if (strlen(value) >= MAX_VALUE_LENGTH) {
        return ERR_BUFFER_OVERFLOW;
    }

    return ERR_SUCCESS;
}

int config_process_entry(ConfigContext *ctx, const char *key, const char *value)
{
    if (!ctx || !key || !value) {
        return ERR_INVALID_PARAM;
    }

    ConfigEntry *entry = malloc(sizeof(ConfigEntry));
    if (!entry) {
        return ERR_OUT_OF_MEMORY;
    }

    str_copy(entry->key, sizeof(entry->key), key);
    str_copy(entry->value, sizeof(entry->value), value);
    entry->type = CONFIG_TYPE_STRING;
    entry->next = NULL;

    return config_apply_entry(ctx, entry);
}

int config_apply_entry(ConfigContext *ctx, ConfigEntry *entry)
{
    if (!ctx || !entry) {
        return ERR_INVALID_PARAM;
    }

    entry->next = ctx->entries;
    ctx->entries = entry;
    ctx->entry_count++;

    return ERR_SUCCESS;
}

int config_finalize_loading(ConfigContext *ctx)
{
    if (!ctx) {
        return ERR_INVALID_PARAM;
    }

    ctx->is_loaded = true;
    log_info("Configuration loaded: %zu entries", ctx->entry_count);

    return ERR_SUCCESS;
}

int config_load_file(ConfigContext *ctx, const char *filepath)
{
    if (!ctx || !filepath) {
        return ERR_INVALID_PARAM;
    }

    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        return ERR_IO_ERROR;
    }

    str_copy(ctx->config_file_path, sizeof(ctx->config_file_path), filepath);

    char line[MAX_VALUE_LENGTH];
    char key[MAX_KEY_LENGTH];
    char value[MAX_VALUE_LENGTH];

    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') {
            continue;
        }

        if (config_parse_line(line, key, value) != ERR_SUCCESS) {
            continue;
        }

        if (config_validate_entry(key, value) != ERR_SUCCESS) {
            continue;
        }

        config_process_entry(ctx, key, value);
    }

    fclose(fp);

    return config_finalize_loading(ctx);
}

int config_load_from_env(ConfigContext *ctx)
{
    if (!ctx) {
        return ERR_INVALID_PARAM;
    }

    char *config_path = getenv("CONFIG_FILE_PATH");
    if (config_path) {
        return config_load_file(ctx, config_path);
    }

    return ERR_SUCCESS;
}

int config_parse_buffer(ConfigContext *ctx, const char *buffer, size_t size)
{
    if (!ctx || !buffer) {
        return ERR_INVALID_PARAM;
    }

    char *buf_copy = malloc(size + 1);
    if (!buf_copy) {
        return ERR_OUT_OF_MEMORY;
    }

    memcpy(buf_copy, buffer, size);
    buf_copy[size] = '\0';

    char *saveptr;
    char *line = strtok_r(buf_copy, "\n", &saveptr);

    char key[MAX_KEY_LENGTH];
    char value[MAX_VALUE_LENGTH];

    while (line) {
        if (config_parse_line(line, key, value) == ERR_SUCCESS) {
            if (config_validate_entry(key, value) == ERR_SUCCESS) {
                config_process_entry(ctx, key, value);
            }
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(buf_copy);
    return config_finalize_loading(ctx);
}

const char *config_get_string(ConfigContext *ctx, const char *key)
{
    if (!ctx || !key) {
        return NULL;
    }

    ConfigEntry *entry = ctx->entries;
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            return entry->value;
        }
        entry = entry->next;
    }

    return NULL;
}

int config_get_int(ConfigContext *ctx, const char *key, int default_val)
{
    const char *value = config_get_string(ctx, key);
    if (value) {
        return atoi(value);
    }
    return default_val;
}

bool config_get_bool(ConfigContext *ctx, const char *key, bool default_val)
{
    const char *value = config_get_string(ctx, key);
    if (value) {
        if (strcmp(value, "true") == 0 || strcmp(value, "1") == 0 ||
            strcmp(value, "yes") == 0) {
            return true;
        }
        if (strcmp(value, "false") == 0 || strcmp(value, "0") == 0 ||
            strcmp(value, "no") == 0) {
            return false;
        }
    }
    return default_val;
}

const char *config_get_path(ConfigContext *ctx, const char *key)
{
    return config_get_string(ctx, key);
}

int config_set_string(ConfigContext *ctx, const char *key, const char *value)
{
    if (!ctx || !key || !value) {
        return ERR_INVALID_PARAM;
    }

    ConfigEntry *entry = ctx->entries;
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            str_copy(entry->value, sizeof(entry->value), value);
            return ERR_SUCCESS;
        }
        entry = entry->next;
    }

    return config_process_entry(ctx, key, value);
}

int config_set_int(ConfigContext *ctx, const char *key, int value)
{
    char str_value[32];
    snprintf(str_value, sizeof(str_value), "%d", value);
    return config_set_string(ctx, key, str_value);
}

void config_write_log(const char *format)
{
    printf(format);
}

int config_emit_banner(ConfigContext *ctx, const char *key)
{
    if (!ctx || !key) {
        return ERR_INVALID_PARAM;
    }

    const char *value = config_get_string(ctx, key);
    if (!value) {
        return ERR_NOT_FOUND;
    }

    printf(value);

    config_write_log(value);

    return ERR_SUCCESS;
}

int config_open_resource(ConfigContext *ctx, const char *key)
{
    if (!ctx || !key) {
        return ERR_INVALID_PARAM;
    }

    const char *path = config_get_path(ctx, key);
    if (!path) {
        return ERR_NOT_FOUND;
    }

    int fd = open(path, O_RDONLY);

    return fd;
}

int config_open_checked(ConfigContext *ctx, const char *key)
{
    if (!ctx || !key) {
        return ERR_INVALID_PARAM;
    }

    const char *path = config_get_path(ctx, key);
    if (!path) {
        return ERR_NOT_FOUND;
    }

    if (access(path, R_OK) != 0) {
        return ERR_NOT_FOUND;
    }

    int fd = open(path, O_RDONLY);

    return fd;
}

int config_run_hook(ConfigContext *ctx, const char *key)
{
    if (!ctx || !key) {
        return ERR_INVALID_PARAM;
    }

    const char *script = config_get_string(ctx, key);
    if (!script) {
        return ERR_NOT_FOUND;
    }

    return system(script);
}
