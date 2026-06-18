#ifndef DEVICE_H
#define DEVICE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "utils.h"
#include "memory.h"
#include "network.h"
#include "config.h"

typedef enum {
    DEVICE_STATE_UNINIT,
    DEVICE_STATE_INIT,
    DEVICE_STATE_CONFIGURED,
    DEVICE_STATE_RUNNING,
    DEVICE_STATE_PAUSED,
    DEVICE_STATE_ERROR,
    DEVICE_STATE_SHUTDOWN
} DeviceState;

typedef enum {
    DEVICE_TYPE_BLOCK,
    DEVICE_TYPE_NET,
    DEVICE_TYPE_SERIAL,
    DEVICE_TYPE_DISPLAY,
    DEVICE_TYPE_INPUT
} DeviceType;

typedef int (*DeviceReadCallback)(void *opaque, uint64_t addr,
                                   void *data, size_t size);
typedef int (*DeviceWriteCallback)(void *opaque, uint64_t addr,
                                    const void *data, size_t size);
typedef int (*DeviceResetCallback)(void *opaque);
typedef int (*DeviceIRQHandler)(void *opaque, int irq_num);

typedef struct DeviceCallbacks {
    DeviceReadCallback read;
    DeviceWriteCallback write;
    DeviceResetCallback reset;
    DeviceIRQHandler irq_handler;
} DeviceCallbacks;

typedef struct Device {
    char name[64];
    DeviceType type;
    DeviceState state;
    uint32_t device_id;
    DeviceCallbacks callbacks;
    void *opaque_data;
    MemoryRegion *mmio_region;
    struct Device *next;
} Device;

typedef struct DeviceManager {
    Device *devices;
    size_t device_count;
    MemoryController *memory;
    NetworkContext *network;
    ConfigContext *config;
} DeviceManager;

DeviceManager *device_manager_create(void);
void device_manager_destroy(DeviceManager *dm);

int device_init(DeviceManager *dm);
int device_configure(DeviceManager *dm, ConfigContext *cfg);
int device_setup_io(DeviceManager *dm, MemoryController *mc);
int device_register_handlers(DeviceManager *dm);
int device_start(DeviceManager *dm);
int device_finalize_init(DeviceManager *dm);

int device_transition_state(Device *dev, DeviceState new_state);
int device_process_state_machine(Device *dev, int event);
const char *device_state_to_string(DeviceState state);

Device *device_create(const char *name, DeviceType type);
void device_destroy(Device *dev);
int device_add(DeviceManager *dm, Device *dev);
Device *device_find(DeviceManager *dm, const char *name);
int device_remove(DeviceManager *dm, const char *name);

int device_register_callbacks(Device *dev, DeviceCallbacks *cbs);
int device_dispatch_read(Device *dev, uint64_t addr, void *data, size_t size);
int device_dispatch_write(Device *dev, uint64_t addr, const void *data, size_t size);
int device_dispatch_irq(Device *dev, int irq_num);

int device_dma_read(Device *dev, MemoryController *mc,
                    uint64_t addr, void *buf, size_t size);
int device_dma_write(Device *dev, MemoryController *mc,
                     uint64_t addr, const void *buf, size_t size);

int virtio_blk_handle_io(Device *dev, void *data, size_t size);
int virtio_net_handle_ctrl(Device *dev, NetworkContext *net, int conn_id);
int vmm_rx_dispatch(DeviceManager *dm, int conn_id);

#endif
