# Makefile for OpenSSH-TEST project (RISC-V Cross Compile)
CC = riscv64-linux-gnu-gcc
CFLAGS = -Iinclude -Wall -Wextra -Werror
# Add RISC-V specific optimizations and floating-point support
ARCH_FLAGS = -march=rv64gc -mabi=lp64d -mcmodel=medlow
LDFLAGS = -static  # Static linking to avoid dependency issues on the target environment

SOURCES = $(wildcard src/*.c)
OBJECTS = $(patsubst src/%.c, obj/%.o, $(SOURCES))
EXECUTABLE = openssh_auth_test

# Cross-compilation toolchain check
TOOLCHAIN_CHECK := $(shell command -v $(CC) 2> /dev/null)

all: build

build: $(OBJECTS)
ifndef TOOLCHAIN_CHECK
    $(error "RISC-V toolchain not found. Install with: sudo apt install gcc-riscv64-linux-gnu")
endif
	$(CC) $(ARCH_FLAGS) $(LDFLAGS) $^ -o $(EXECUTABLE)

obj/%.o: src/%.c
	mkdir -p obj
	$(CC) $(CFLAGS) $(ARCH_FLAGS) -c $< -o $@

# Add deployment rule for target environment (QEMU test)
deploy: build
	@echo "Deploying to RISC-V environment..."
	scp $(EXECUTABLE) user@riscv-target:/path/to/   # 替换为实际部署路径

# Add QEMU testing rule
test: build
	qemu-riscv64 -L /usr/riscv64-linux-gnu/ $(EXECUTABLE)

clean:
	rm -rf obj $(EXECUTABLE)

# Disassembly tool rule
disasm: build
	riscv64-linux-gnu-objdump -d -S $(EXECUTABLE) > $(EXECUTABLE).disasm

.PHONY: all clean deploy test disasm
