CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11
BUILD := build
UNAME_S := $(shell uname -s)
ARCH := $(shell uname -m)

.PHONY: all test clean

all: $(BUILD)/test-logic $(BUILD)/test-policy $(BUILD)/mad-elf-es
ifeq ($(UNAME_S),Linux)
ifeq ($(ARCH),x86_64)
all: $(BUILD)/mad-elf-shim
endif
endif

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/mad-elf-shim: src/shim.c src/entry_x86_64.S src/logic.c src/logic.h | $(BUILD)
	$(CC) -nostdlib -static-pie -ffreestanding -fno-builtin -fno-stack-protector \
	  -fno-asynchronous-unwind-tables -fno-jump-tables -Os -Wall -Wextra \
	  -Wl,-e,_start -o $@ src/entry_x86_64.S src/shim.c src/logic.c
	@if readelf -l $@ | grep -q 'Requesting program interpreter'; then \
	  echo "shim must not have its own PT_INTERP"; exit 1; fi
	@if readelf -r $@ | grep -E -q 'R_X86_64_'; then \
	  echo "shim has relocations and cannot relocate itself as PT_INTERP"; exit 1; fi

$(BUILD)/test-logic: tests/test_logic.c src/logic.c src/logic.h | $(BUILD)
	$(CC) $(CFLAGS) -Isrc -o $@ tests/test_logic.c src/logic.c

$(BUILD)/test-policy: es-demo/tests/test_policy.c es-demo/policy.c es-demo/policy.h | $(BUILD)
	$(CC) $(CFLAGS) -Ies-demo -o $@ es-demo/tests/test_policy.c es-demo/policy.c

$(BUILD)/mad-elf-es: es-demo/cli.c es-demo/policy.c es-demo/policy.h | $(BUILD)
	$(CC) $(CFLAGS) -Ies-demo -o $@ es-demo/cli.c es-demo/policy.c

test: all
	./$(BUILD)/test-logic
	./$(BUILD)/test-policy
	bash es-demo/tests/test_cli.sh
	bash es-demo/tests/test_integration.sh
	python3 tests/test_macho.py
	python3 tests/test_darwin.py
ifeq ($(UNAME_S),Linux)
ifeq ($(ARCH),x86_64)
	python3 tests/test_linux.py
endif
endif

clean:
	rm -rf $(BUILD)
