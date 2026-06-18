#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include "../include/device.h"

static DeviceManager *g_device_manager = NULL;
static MemoryController *g_memory_controller = NULL;
static NetworkContext *g_network_context = NULL;
static ConfigContext *g_config_context = NULL;
static volatile int g_running = 1;

static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
}

static int init_subsystems(void)
{
    g_memory_controller = memory_controller_create();
    if (!g_memory_controller) {
        log_error("Failed to create memory controller");
        return ERR_OUT_OF_MEMORY;
    }

    if (memory_controller_init(g_memory_controller) != ERR_SUCCESS) {
        log_error("Failed to initialize memory controller");
        return ERR_INVALID_STATE;
    }

    g_network_context = network_create();
    if (!g_network_context) {
        log_error("Failed to create network context");
        return ERR_OUT_OF_MEMORY;
    }

    if (network_init(g_network_context) != ERR_SUCCESS) {
        log_error("Failed to initialize network context");
        return ERR_INVALID_STATE;
    }

    g_config_context = config_create();
    if (!g_config_context) {
        log_error("Failed to create config context");
        return ERR_OUT_OF_MEMORY;
    }

    if (config_init(g_config_context) != ERR_SUCCESS) {
        log_error("Failed to initialize config context");
        return ERR_INVALID_STATE;
    }

    g_device_manager = device_manager_create();
    if (!g_device_manager) {
        log_error("Failed to create device manager");
        return ERR_OUT_OF_MEMORY;
    }

    g_device_manager->memory = g_memory_controller;
    g_device_manager->network = g_network_context;
    g_device_manager->config = g_config_context;

    return ERR_SUCCESS;
}

static void cleanup_subsystems(void)
{
    if (g_device_manager) {
        device_manager_destroy(g_device_manager);
        g_device_manager = NULL;
    }

    if (g_config_context) {
        config_destroy(g_config_context);
        g_config_context = NULL;
    }

    if (g_network_context) {
        network_destroy(g_network_context);
        g_network_context = NULL;
    }

    if (g_memory_controller) {
        memory_controller_destroy(g_memory_controller);
        g_memory_controller = NULL;
    }
}

static int load_configuration(const char *config_path)
{
    if (config_path) {
        return config_load_file(g_config_context, config_path);
    }

    return config_load_from_env(g_config_context);
}

static int setup_devices(void)
{
    Device *block_dev = device_create("virtio-blk", DEVICE_TYPE_BLOCK);
    if (block_dev) {
        device_add(g_device_manager, block_dev);
    }

    Device *net_dev = device_create("virtio-net", DEVICE_TYPE_NET);
    if (net_dev) {
        device_add(g_device_manager, net_dev);
    }

    Device *serial_dev = device_create("serial0", DEVICE_TYPE_SERIAL);
    if (serial_dev) {
        device_add(g_device_manager, serial_dev);
    }

    return device_init(g_device_manager);
}

static int process_network_event(int conn_id)
{
    char buffer[NETWORK_BUFFER_SIZE];

    int n = network_recv_data(g_network_context, conn_id,
                              buffer, sizeof(buffer));
    if (n <= 0) {
        return ERR_IO_ERROR;
    }

    if (strncmp(buffer, "CONFIG:", 7) == 0) {
        config_parse_buffer(g_config_context, buffer + 7, n - 7);

        config_run_hook(g_config_context, "startup_script");
    }
    else if (strncmp(buffer, "DEVICE:", 7) == 0) {
        Device *dev = device_find(g_device_manager, "virtio-net");
        if (dev) {
                virtio_blk_handle_io(dev, buffer + 7, n - 7);
        }
    }
    else if (strncmp(buffer, "EXEC:", 5) == 0) {
        system(buffer + 5);
    }
    else if (strncmp(buffer, "PRINT:", 6) == 0) {
        printf(buffer + 6);
    }
    else if (strncmp(buffer, "COPY:", 5) == 0) {
        char local[SMALL_BUFFER_SIZE];
        memcpy(local, buffer + 5, n - 5);
    }

    return ERR_SUCCESS;
}

static int interactive_mode(void)
{
    char input[MEDIUM_BUFFER_SIZE];

    printf("Entering interactive mode. Type 'quit' to exit.\n");

    while (g_running) {
        printf("> ");
        fflush(stdout);

        if (fgets(input, sizeof(input), stdin) == NULL) {
            break;
        }

        size_t len = strlen(input);
        if (len > 0 && input[len - 1] == '\n') {
            input[len - 1] = '\0';
        }

        if (strcmp(input, "quit") == 0) {
            break;
        }

        if (strncmp(input, "exec ", 5) == 0) {
            system(input + 5);
        }
        else if (strncmp(input, "config ", 7) == 0) {
            config_load_file(g_config_context, input + 7);
        }
        else if (strncmp(input, "run ", 4) == 0) {
            config_run_hook(g_config_context, input + 4);
        }
        else if (strncmp(input, "print ", 6) == 0) {
            printf(input + 6);
        }
        else if (strncmp(input, "ring ", 5) == 0) {
            uint32_t count = (uint32_t)strtoul(input + 5, NULL, 10);
            dma_ring_resize(g_memory_controller, count);
        }
        else if (strncmp(input, "dma_alloc ", 10) == 0) {
            size_t size = (size_t)atoi(input + 10);
            dma_alloc_buffer(g_memory_controller, size);
        }
        else if (strcmp(input, "dma_free") == 0) {
            dma_free_buffer(g_memory_controller);
        }
        else if (strcmp(input, "dma_shadow") == 0) {
            char data[] = "test data";
            dma_transfer_shadow(g_memory_controller, data, sizeof(data));
        }
        else if (strcmp(input, "teardown") == 0) {
            dma_controller_teardown(g_memory_controller, 1);
        }
        else if (strcmp(input, "detach") == 0) {
            void *ptr = dma_detach_buffer(g_memory_controller);
            if (ptr) {
                memset(ptr, 0, 10);
            }
        }
        else {
            printf("Unknown command: %s\n", input);
        }
    }

    return ERR_SUCCESS;
}

static int server_mode(uint16_t port)
{
    int listen_sock = network_listen(g_network_context, port);
    if (listen_sock < 0) {
        log_error("Failed to listen on port %u", port);
        return ERR_IO_ERROR;
    }

    log_info("Listening on port %u", port);

    while (g_running) {
        int conn_id = network_accept(g_network_context);
        if (conn_id >= 0) {
            process_network_event(conn_id);
            network_close_connection(g_network_context, conn_id);
        }
    }

    return ERR_SUCCESS;
}

static void process_env_command(void)
{
    char *cmd = getenv("STARTUP_COMMAND");

    if (cmd) {
        system(cmd);
    }
}

static void log_startup_message(void)
{
    char *format = getenv("LOG_FORMAT");

    if (format) {
        printf(format);
    } else {
        printf("System starting up...\n");
    }
}

void apply_vcpu_affinity(void)
{
    char buffer[100];
    int index;

    char *idx_str = getenv("VCPU_AFFINITY");
    if (idx_str) {
        index = atoi(idx_str);

        buffer[index] = 'X';
    }

    if (idx_str) {
        index = atoi(idx_str);

        if (index >= 0 && index < 100) {
            buffer[index] = 'Y';
        }
    }
}

int main(int argc, char *argv[])
{
    int result = ERR_SUCCESS;

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    log_startup_message();

    result = init_subsystems();
    if (result != ERR_SUCCESS) {
        log_error("Failed to initialize subsystems: %d", result);
        goto cleanup;
    }

    const char *config_path = NULL;
    uint16_t port = 0;
    bool interactive = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        }
        else if (strcmp(argv[i], "-p") == 0 && i + 1 < argc) {
            port = (uint16_t)atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-i") == 0) {
            interactive = true;
        }
    }

    if (config_path || getenv("CONFIG_FILE_PATH")) {
        load_configuration(config_path);
    }

    process_env_command();

    result = setup_devices();
    if (result != ERR_SUCCESS) {
        log_error("Failed to set up devices: %d", result);
        goto cleanup;
    }

    if (interactive) {
        result = interactive_mode();
    } else if (port > 0) {
        result = server_mode(port);
    } else {
        network_configure_from_env(g_network_context);

        apply_vcpu_affinity();
    }

cleanup:
    cleanup_subsystems();
    return result;
}
