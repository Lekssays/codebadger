#ifndef MEMORY_H
#define MEMORY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "utils.h"

#define MEM_PERM_READ   0x01
#define MEM_PERM_WRITE  0x02
#define MEM_PERM_EXEC   0x04

typedef enum {
    MEM_TYPE_RAM,
    MEM_TYPE_ROM,
    MEM_TYPE_MMIO,
    MEM_TYPE_DMA
} MemoryType;

typedef struct MemoryRegion {
    char *name;
    void *base;
    size_t size;
    uint8_t permissions;
    MemoryType type;
    struct MemoryRegion *next;
    bool is_allocated;
} MemoryRegion;

typedef struct DmaDescriptor {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} DmaDescriptor;

typedef struct MemoryController {
    MemoryRegion *regions;
    size_t region_count;
    size_t total_allocated;
    void *dma_buffer;
    void *dma_shadow;
    DmaDescriptor *ring;
    size_t ring_count;
} MemoryController;

typedef struct AllocationEntry {
    void *ptr;
    size_t size;
    const char *file;
    int line;
    bool freed;
    struct AllocationEntry *next;
} AllocationEntry;

MemoryController *memory_controller_create(void);
void memory_controller_destroy(MemoryController *mc);
int memory_controller_init(MemoryController *mc);

MemoryRegion *memory_region_create(const char *name, size_t size,
                                   uint8_t permissions, MemoryType type);
void memory_region_free(MemoryRegion *region);
int memory_region_add(MemoryController *mc, MemoryRegion *region);
MemoryRegion *memory_region_find(MemoryController *mc, const char *name);

int memory_read(MemoryController *mc, uint64_t addr, void *buf, size_t size);
int memory_write(MemoryController *mc, uint64_t addr, const void *buf, size_t size);
int memory_copy_region(MemoryController *mc, const char *src_name,
                       const char *dst_name, size_t size);

int dma_alloc_buffer(MemoryController *mc, size_t size);
int dma_free_buffer(MemoryController *mc);
int dma_transfer(MemoryController *mc, void *data, size_t size);
int dma_transfer_shadow(MemoryController *mc, void *data, size_t size);

int dma_ring_resize(MemoryController *mc, uint32_t count);
int dma_ring_resize_guarded(MemoryController *mc, uint32_t count);
int dma_remap_buffer(MemoryController *mc, size_t size, const void *seed);

int dma_stage_inbound(MemoryController *mc, void *data, size_t size);
int dma_controller_teardown(MemoryController *mc, int error_code);
void dma_shadow_refresh(MemoryController *mc);
int dma_release_either(MemoryController *mc, bool fast_path);

void *dma_detach_buffer(MemoryController *mc);
int scratch_pool_reclaim(MemoryController *mc);

#endif
