# QEMU-like Security Test Codebase
# Makefile for building the multi-file test codebase

CC = gcc
CFLAGS = -Wall -Wextra -g -O0 -I./include
LDFLAGS = 

# Source files
SRCS = src/main.c \
       src/device.c \
       src/memory.c \
       src/network.c \
       src/config.c \
       src/utils.c \
       src/callbacks.c \
       src/cmdline.c \
       src/slice_scenarios.c

# C++ source files (compiled separately, not linked into the main binary)
CXX      = g++
CXXFLAGS = -Wall -Wextra -g -O0 -I./include -std=c++11
CXX_SRCS = src/slice_cpp.cpp

# Object files (in build directory)
BUILD_DIR = build
OBJS = $(SRCS:src/%.c=$(BUILD_DIR)/%.o)

# Output binary
TARGET = $(BUILD_DIR)/qemu_test

# Default target — builds C binary + standalone C++ object for CPG analysis
all: $(BUILD_DIR) $(TARGET) $(BUILD_DIR)/slice_cpp.o

# Create build directory
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Link object files
$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

# Compile C source files
$(BUILD_DIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Compile C++ source files
$(BUILD_DIR)/slice_cpp.o: src/slice_cpp.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)

# Rebuild
rebuild: clean all

# Run with Valgrind for memory checking
valgrind: $(TARGET)
	valgrind --leak-check=full --show-leak-kinds=all $(TARGET)

# Generate preprocessed output for analysis
preprocess:
	@mkdir -p $(BUILD_DIR)/pp
	@for src in $(SRCS); do \
		$(CC) $(CFLAGS) -E $$src -o $(BUILD_DIR)/pp/$$(basename $$src .c).i; \
	done

# Compile all sources into a single file for simpler CPG analysis
single:
	@echo "/* Combined source for CPG analysis */" > $(BUILD_DIR)/combined.c
	@for src in $(SRCS); do \
		echo "/* ===== $$src ===== */" >> $(BUILD_DIR)/combined.c; \
		cat $$src >> $(BUILD_DIR)/combined.c; \
		echo "" >> $(BUILD_DIR)/combined.c; \
	done

# Debug build with sanitizers
debug: CFLAGS += -fsanitize=address,undefined
debug: LDFLAGS += -fsanitize=address,undefined
debug: all

.PHONY: all clean rebuild valgrind preprocess single debug scenarios
