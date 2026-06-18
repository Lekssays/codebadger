#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/device.h"

#define MAX_CALLBACKS 64

typedef struct CallbackEntry {
    char name[64];
    void (*callback)(void *data);
    void *user_data;
    bool is_active;
} CallbackEntry;

static CallbackEntry g_callbacks[MAX_CALLBACKS];
static size_t g_callback_count = 0;

int callbacks_init(void)
{
    memset(g_callbacks, 0, sizeof(g_callbacks));
    g_callback_count = 0;
    return ERR_SUCCESS;
}

int callback_register(const char *name, void (*callback)(void *), void *user_data)
{
    if (!name || !callback) {
        return ERR_INVALID_PARAM;
    }

    if (g_callback_count >= MAX_CALLBACKS) {
        return ERR_OUT_OF_MEMORY;
    }

    CallbackEntry *entry = &g_callbacks[g_callback_count++];
    str_copy(entry->name, sizeof(entry->name), name);
    entry->callback = callback;
    entry->user_data = user_data;
    entry->is_active = true;

    return ERR_SUCCESS;
}

int callback_unregister(const char *name)
{
    if (!name) {
        return ERR_INVALID_PARAM;
    }

    for (size_t i = 0; i < g_callback_count; i++) {
        if (strcmp(g_callbacks[i].name, name) == 0) {
            g_callbacks[i].is_active = false;
            return ERR_SUCCESS;
        }
    }

    return ERR_NOT_FOUND;
}

static CallbackEntry *callback_find(const char *name)
{
    for (size_t i = 0; i < g_callback_count; i++) {
        if (g_callbacks[i].is_active &&
            strcmp(g_callbacks[i].name, name) == 0) {
            return &g_callbacks[i];
        }
    }
    return NULL;
}

int callback_invoke(const char *name, void *data)
{
    if (!name) {
        return ERR_INVALID_PARAM;
    }

    CallbackEntry *entry = callback_find(name);
    if (!entry) {
        return ERR_NOT_FOUND;
    }

    entry->callback(data ? data : entry->user_data);

    return ERR_SUCCESS;
}

int callback_invoke_all(void *data)
{
    int count = 0;

    for (size_t i = 0; i < g_callback_count; i++) {
        if (g_callbacks[i].is_active && g_callbacks[i].callback) {
            g_callbacks[i].callback(data ? data : g_callbacks[i].user_data);
            count++;
        }
    }

    return count;
}

static void handler_level1(void *data)
{
    log_debug("Handler level 1: %p", data);
}

static void handler_level2(void *data)
{
    log_debug("Handler level 2: %p", data);
    handler_level1(data);
}

static void handler_level3(void *data)
{
    log_debug("Handler level 3: %p", data);
    handler_level2(data);
}

static void handler_with_network(void *data)
{
    NetworkContext *ctx = (NetworkContext *)data;
    if (ctx) {
        log_debug("Handler with network context");
    }
}

static void handler_with_memory(void *data)
{
    MemoryController *mc = (MemoryController *)data;
    if (mc) {
        log_debug("Handler with memory controller");
    }
}

int callbacks_register_defaults(void)
{
    callback_register("level1", handler_level1, NULL);
    callback_register("level2", handler_level2, NULL);
    callback_register("level3", handler_level3, NULL);
    callback_register("network", handler_with_network, NULL);
    callback_register("memory", handler_with_memory, NULL);

    return ERR_SUCCESS;
}

static void chain_step5(void *data)
{
    log_debug("Chain step 5 (final): %p", data);
}

static void chain_step4(void *data)
{
    log_debug("Chain step 4");
    chain_step5(data);
}

static void chain_step3(void *data)
{
    log_debug("Chain step 3");
    chain_step4(data);
}

static void chain_step2(void *data)
{
    log_debug("Chain step 2");
    chain_step3(data);
}

static void chain_step1(void *data)
{
    log_debug("Chain step 1");
    chain_step2(data);
}

int callback_dispatch_chain(void *data)
{
    log_debug("Starting callback chain");
    chain_step1(data);
    return ERR_SUCCESS;
}

int callback_device_read(Device *dev, uint64_t addr, void *data, size_t size)
{
    if (!dev || !dev->callbacks.read) {
        return ERR_INVALID_PARAM;
    }

    return dev->callbacks.read(dev->opaque_data, addr, data, size);
}

int callback_device_write(Device *dev, uint64_t addr, const void *data, size_t size)
{
    if (!dev || !dev->callbacks.write) {
        return ERR_INVALID_PARAM;
    }

    return dev->callbacks.write(dev->opaque_data, addr, data, size);
}

int callback_device_reset(Device *dev)
{
    if (!dev || !dev->callbacks.reset) {
        return ERR_INVALID_PARAM;
    }

    return dev->callbacks.reset(dev->opaque_data);
}

int callback_device_irq(Device *dev, int irq_num)
{
    if (!dev || !dev->callbacks.irq_handler) {
        return ERR_INVALID_PARAM;
    }

    return dev->callbacks.irq_handler(dev->opaque_data, irq_num);
}
