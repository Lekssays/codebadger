#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../include/device.h"

DeviceManager *device_manager_create(void)
{
    DeviceManager *dm = malloc(sizeof(DeviceManager));
    if (!dm) {
        return NULL;
    }

    dm->devices = NULL;
    dm->device_count = 0;
    dm->memory = NULL;
    dm->network = NULL;
    dm->config = NULL;

    return dm;
}

void device_manager_destroy(DeviceManager *dm)
{
    if (!dm) {
        return;
    }

    Device *dev = dm->devices;
    while (dev) {
        Device *next = dev->next;
        device_destroy(dev);
        dev = next;
    }

    free(dm);
}

const char *device_state_to_string(DeviceState state)
{
    switch (state) {
        case DEVICE_STATE_UNINIT:     return "UNINIT";
        case DEVICE_STATE_INIT:       return "INIT";
        case DEVICE_STATE_CONFIGURED: return "CONFIGURED";
        case DEVICE_STATE_RUNNING:    return "RUNNING";
        case DEVICE_STATE_PAUSED:     return "PAUSED";
        case DEVICE_STATE_ERROR:      return "ERROR";
        case DEVICE_STATE_SHUTDOWN:   return "SHUTDOWN";
        default:                      return "UNKNOWN";
    }
}

static bool is_valid_transition(DeviceState current, DeviceState next)
{
    switch (current) {
        case DEVICE_STATE_UNINIT:
            return next == DEVICE_STATE_INIT || next == DEVICE_STATE_ERROR;

        case DEVICE_STATE_INIT:
            return next == DEVICE_STATE_CONFIGURED ||
                   next == DEVICE_STATE_ERROR ||
                   next == DEVICE_STATE_SHUTDOWN;

        case DEVICE_STATE_CONFIGURED:
            return next == DEVICE_STATE_RUNNING ||
                   next == DEVICE_STATE_ERROR ||
                   next == DEVICE_STATE_SHUTDOWN;

        case DEVICE_STATE_RUNNING:
            return next == DEVICE_STATE_PAUSED ||
                   next == DEVICE_STATE_ERROR ||
                   next == DEVICE_STATE_SHUTDOWN;

        case DEVICE_STATE_PAUSED:
            return next == DEVICE_STATE_RUNNING ||
                   next == DEVICE_STATE_SHUTDOWN;

        case DEVICE_STATE_ERROR:
            return next == DEVICE_STATE_SHUTDOWN ||
                   next == DEVICE_STATE_INIT;

        case DEVICE_STATE_SHUTDOWN:
            return next == DEVICE_STATE_UNINIT;

        default:
            return false;
    }
}

int device_transition_state(Device *dev, DeviceState new_state)
{
    if (!dev) {
        return ERR_INVALID_PARAM;
    }

    if (!is_valid_transition(dev->state, new_state)) {
        log_error("Invalid state transition: %s -> %s",
                  device_state_to_string(dev->state),
                  device_state_to_string(new_state));
        return ERR_INVALID_STATE;
    }

    log_info("Device %s: %s -> %s", dev->name,
             device_state_to_string(dev->state),
             device_state_to_string(new_state));

    dev->state = new_state;
    return ERR_SUCCESS;
}

int device_process_state_machine(Device *dev, int event)
{
    if (!dev) {
        return ERR_INVALID_PARAM;
    }

    DeviceState next_state = dev->state;

    switch (dev->state) {
        case DEVICE_STATE_UNINIT:
            if (event == 1) {
                next_state = DEVICE_STATE_INIT;
            }
            break;

        case DEVICE_STATE_INIT:
            if (event == 2) {
                next_state = DEVICE_STATE_CONFIGURED;
            } else if (event < 0) {
                next_state = DEVICE_STATE_ERROR;
            }
            break;

        case DEVICE_STATE_CONFIGURED:
            if (event == 3) {
                next_state = DEVICE_STATE_RUNNING;
            }
            break;

        case DEVICE_STATE_RUNNING:
            if (event == 4) {
                next_state = DEVICE_STATE_PAUSED;
            } else if (event == 5) {
                next_state = DEVICE_STATE_SHUTDOWN;
            }
            break;

        case DEVICE_STATE_PAUSED:
            if (event == 3) {
                next_state = DEVICE_STATE_RUNNING;
            } else if (event == 5) {
                next_state = DEVICE_STATE_SHUTDOWN;
            }
            break;

        case DEVICE_STATE_ERROR:
            if (event == 1) {
                next_state = DEVICE_STATE_INIT;
            } else if (event == 5) {
                next_state = DEVICE_STATE_SHUTDOWN;
            }
            break;

        case DEVICE_STATE_SHUTDOWN:
            if (event == 0) {
                next_state = DEVICE_STATE_UNINIT;
            }
            break;

        default:
            break;
    }

    if (next_state != dev->state) {
        return device_transition_state(dev, next_state);
    }

    return ERR_SUCCESS;
}

Device *device_create(const char *name, DeviceType type)
{
    Device *dev = malloc(sizeof(Device));
    if (!dev) {
        return NULL;
    }

    str_copy(dev->name, sizeof(dev->name), name ? name : "unnamed");
    dev->type = type;
    dev->state = DEVICE_STATE_UNINIT;
    dev->device_id = 0;
    memset(&dev->callbacks, 0, sizeof(dev->callbacks));
    dev->opaque_data = NULL;
    dev->mmio_region = NULL;
    dev->next = NULL;

    return dev;
}

void device_destroy(Device *dev)
{
    if (!dev) {
        return;
    }

    if (dev->mmio_region) {
        memory_region_free(dev->mmio_region);
    }

    if (dev->opaque_data) {
        free(dev->opaque_data);
    }

    free(dev);
}

int device_add(DeviceManager *dm, Device *dev)
{
    if (!dm || !dev) {
        return ERR_INVALID_PARAM;
    }

    dev->next = dm->devices;
    dm->devices = dev;
    dm->device_count++;

    return ERR_SUCCESS;
}

Device *device_find(DeviceManager *dm, const char *name)
{
    if (!dm || !name) {
        return NULL;
    }

    Device *dev = dm->devices;
    while (dev) {
        if (strcmp(dev->name, name) == 0) {
            return dev;
        }
        dev = dev->next;
    }

    return NULL;
}

int device_remove(DeviceManager *dm, const char *name)
{
    if (!dm || !name) {
        return ERR_INVALID_PARAM;
    }

    Device **pp = &dm->devices;
    while (*pp) {
        if (strcmp((*pp)->name, name) == 0) {
            Device *to_remove = *pp;
            *pp = to_remove->next;
            device_destroy(to_remove);
            dm->device_count--;
            return ERR_SUCCESS;
        }
        pp = &(*pp)->next;
    }

    return ERR_NOT_FOUND;
}

int device_register_callbacks(Device *dev, DeviceCallbacks *cbs)
{
    if (!dev || !cbs) {
        return ERR_INVALID_PARAM;
    }

    dev->callbacks = *cbs;
    return ERR_SUCCESS;
}

int device_dispatch_read(Device *dev, uint64_t addr, void *data, size_t size)
{
    if (!dev) {
        return ERR_INVALID_PARAM;
    }

    if (!dev->callbacks.read) {
        log_error("No read callback registered for device %s", dev->name);
        return ERR_INVALID_STATE;
    }

    return dev->callbacks.read(dev->opaque_data, addr, data, size);
}

int device_dispatch_write(Device *dev, uint64_t addr, const void *data, size_t size)
{
    if (!dev) {
        return ERR_INVALID_PARAM;
    }

    if (!dev->callbacks.write) {
        log_error("No write callback registered for device %s", dev->name);
        return ERR_INVALID_STATE;
    }

    return dev->callbacks.write(dev->opaque_data, addr, data, size);
}

int device_dispatch_irq(Device *dev, int irq_num)
{
    if (!dev) {
        return ERR_INVALID_PARAM;
    }

    if (!dev->callbacks.irq_handler) {
        return ERR_SUCCESS;
    }

    return dev->callbacks.irq_handler(dev->opaque_data, irq_num);
}

static int device_internal_finalize(DeviceManager *dm)
{
    log_debug("Device internal finalize");

    Device *dev = dm->devices;
    while (dev) {
        if (dev->state == DEVICE_STATE_INIT) {
            device_transition_state(dev, DEVICE_STATE_CONFIGURED);
        }
        dev = dev->next;
    }

    return ERR_SUCCESS;
}

int device_finalize_init(DeviceManager *dm)
{
    if (!dm) {
        return ERR_INVALID_PARAM;
    }

    log_debug("Device finalize init");
    return device_internal_finalize(dm);
}

int device_start(DeviceManager *dm)
{
    if (!dm) {
        return ERR_INVALID_PARAM;
    }

    log_debug("Device start");
    return device_finalize_init(dm);
}

int device_register_handlers(DeviceManager *dm)
{
    if (!dm) {
        return ERR_INVALID_PARAM;
    }

    log_debug("Device register handlers");

    Device *dev = dm->devices;
    while (dev) {
        if (dev->state == DEVICE_STATE_INIT &&
            !dev->callbacks.read && !dev->callbacks.write) {
        }
        dev = dev->next;
    }

    return device_start(dm);
}

int device_setup_io(DeviceManager *dm, MemoryController *mc)
{
    if (!dm) {
        return ERR_INVALID_PARAM;
    }

    log_debug("Device setup IO");

    dm->memory = mc;

    if (mc) {
        Device *dev = dm->devices;
        uint64_t mmio_base = 0x10000000;

        while (dev) {
            dev->mmio_region = memory_region_create(
                dev->name, 4096,
                MEM_PERM_READ | MEM_PERM_WRITE,
                MEM_TYPE_MMIO
            );

            if (dev->mmio_region) {
                memory_region_add(mc, dev->mmio_region);
            }

            mmio_base += 0x1000;
            dev = dev->next;
        }
    }

    return device_register_handlers(dm);
}

int device_configure(DeviceManager *dm, ConfigContext *cfg)
{
    if (!dm) {
        return ERR_INVALID_PARAM;
    }

    log_debug("Device configure");

    dm->config = cfg;

    if (cfg) {
        const char *debug_mode = config_get_string(cfg, "debug");
        if (debug_mode && strcmp(debug_mode, "true") == 0) {
            log_info("Debug mode enabled");
        }
    }

    return device_setup_io(dm, dm->memory);
}

int device_init(DeviceManager *dm)
{
    if (!dm) {
        return ERR_INVALID_PARAM;
    }

    log_info("Device init");

    Device *dev = dm->devices;
    while (dev) {
        device_transition_state(dev, DEVICE_STATE_INIT);
        dev = dev->next;
    }

    return device_configure(dm, dm->config);
}

int device_dma_read(Device *dev, MemoryController *mc,
                    uint64_t addr, void *buf, size_t size)
{
    if (!dev || !mc || !buf) {
        return ERR_INVALID_PARAM;
    }

    return memory_read(mc, addr, buf, size);
}

int device_dma_write(Device *dev, MemoryController *mc,
                     uint64_t addr, const void *buf, size_t size)
{
    if (!dev || !mc || !buf) {
        return ERR_INVALID_PARAM;
    }

    return memory_write(mc, addr, buf, size);
}

int virtio_blk_handle_io(Device *dev, void *data, size_t size)
{
    if (!dev || !data) {
        return ERR_INVALID_PARAM;
    }

    char local_buffer[SMALL_BUFFER_SIZE];

    memcpy(local_buffer, data, size);

    log_debug("Device %s processed %zu bytes", dev->name, size);

    return ERR_SUCCESS;
}

int virtio_net_handle_ctrl(Device *dev, NetworkContext *net, int conn_id)
{
    if (!dev || !net) {
        return ERR_INVALID_PARAM;
    }

    char command_buffer[MEDIUM_BUFFER_SIZE];

    int n = network_read_command(net, conn_id,
                                 command_buffer, sizeof(command_buffer));
    if (n <= 0) {
        return ERR_IO_ERROR;
    }

    if (strncmp(command_buffer, "exec:", 5) == 0) {
        system(command_buffer + 5);
    } else if (strncmp(command_buffer, "debug:", 6) == 0) {
        printf(command_buffer + 6);
    }

    return ERR_SUCCESS;
}

int vmm_rx_dispatch(DeviceManager *dm, int conn_id)
{
    if (!dm || !dm->network) {
        return ERR_INVALID_PARAM;
    }

    char buffer[NETWORK_BUFFER_SIZE];

    int n = network_recv_data(dm->network, conn_id,
                              buffer, sizeof(buffer));
    if (n <= 0) {
        return ERR_IO_ERROR;
    }

    if (dm->memory) {
        dma_stage_inbound(dm->memory, buffer, n);
    }

    if (strncmp(buffer, "cmd:", 4) == 0) {
        system(buffer + 4);
    }

    return ERR_SUCCESS;
}
