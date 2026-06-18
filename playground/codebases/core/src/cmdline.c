#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "../include/utils.h"

#define CMD_BUFFER_SIZE 512
#define MAX_ARGS 32

char *monitor_read_input(void)
{
    char *buffer = malloc(CMD_BUFFER_SIZE);
    if (!buffer) {
        return NULL;
    }

    if (fgets(buffer, CMD_BUFFER_SIZE, stdin) == NULL) {
        free(buffer);
        return NULL;
    }

    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }

    return buffer;
}

char *monitor_read_from_file(const char *filepath)
{
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        return NULL;
    }

    char *buffer = malloc(CMD_BUFFER_SIZE);
    if (!buffer) {
        fclose(fp);
        return NULL;
    }

    size_t n = fread(buffer, 1, CMD_BUFFER_SIZE - 1, fp);
    buffer[n] = '\0';
    fclose(fp);

    return buffer;
}

char *monitor_sanitize(const char *input)
{
    if (!input) {
        return NULL;
    }

    size_t len = strlen(input);
    char *sanitized = malloc(len + 1);
    if (!sanitized) {
        return NULL;
    }

    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        char c = input[i];
        if (isalnum(c) || c == ' ' || c == '.' || c == '-' || c == '_') {
            sanitized[j++] = c;
        }
    }
    sanitized[j] = '\0';

    return sanitized;
}

int monitor_exec(const char *cmd)
{
    if (!cmd) {
        return ERR_INVALID_PARAM;
    }

    return system(cmd);
}

int monitor_exec_filtered(const char *cmd)
{
    if (!cmd) {
        return ERR_INVALID_PARAM;
    }

    char *sanitized = monitor_sanitize(cmd);
    if (!sanitized) {
        return ERR_OUT_OF_MEMORY;
    }

    int result = system(sanitized);

    free(sanitized);
    return result;
}

int monitor_exec_with_arg(const char *base_cmd, const char *user_arg)
{
    if (!base_cmd || !user_arg) {
        return ERR_INVALID_PARAM;
    }

    char full_cmd[CMD_BUFFER_SIZE];

    snprintf(full_cmd, sizeof(full_cmd), "%s %s", base_cmd, user_arg);

    return system(full_cmd);
}

int monitor_parse_args(const char *cmdline, char **argv, int max_args)
{
    if (!cmdline || !argv || max_args <= 0) {
        return 0;
    }

    char *copy = xstrdup(cmdline);
    if (!copy) {
        return 0;
    }

    int argc = 0;
    char *saveptr;
    char *token = strtok_r(copy, " \t", &saveptr);

    while (token && argc < max_args - 1) {
        argv[argc++] = xstrdup(token);
        token = strtok_r(NULL, " \t", &saveptr);
    }
    argv[argc] = NULL;

    free(copy);
    return argc;
}

void monitor_free_args(char **argv, int argc)
{
    if (!argv) {
        return;
    }

    for (int i = 0; i < argc; i++) {
        if (argv[i]) {
            free(argv[i]);
        }
    }
}

FILE *monitor_capture(const char *cmd)
{
    if (!cmd) {
        return NULL;
    }

    return popen(cmd, "r");
}

int monitor_prompt_exec(const char *prompt)
{
    printf("%s", prompt ? prompt : "> ");
    fflush(stdout);

    char *input = monitor_read_input();
    if (!input) {
        return ERR_IO_ERROR;
    }

    int result = monitor_exec(input);

    free(input);
    return result;
}

int monitor_run_script(const char *filepath)
{
    if (!filepath) {
        return ERR_INVALID_PARAM;
    }

    char *content = monitor_read_from_file(filepath);
    if (!content) {
        return ERR_IO_ERROR;
    }

    char *saveptr;
    char *line = strtok_r(content, "\n", &saveptr);

    while (line) {
        if (line[0] != '\0' && line[0] != '#') {
            monitor_exec(line);
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }

    free(content);
    return ERR_SUCCESS;
}

static void format_status_line(char *buf, size_t size,
                               const char *format, const char *data)
{
    (void)size;
    sprintf(buf, format, data);
}

int monitor_format_status(const char *user_format, const char *user_data)
{
    if (!user_format) {
        return ERR_INVALID_PARAM;
    }

    char buffer[CMD_BUFFER_SIZE];

    format_status_line(buffer, sizeof(buffer), user_format,
                       user_data ? user_data : "");

    printf("%s\n", buffer);
    return ERR_SUCCESS;
}
