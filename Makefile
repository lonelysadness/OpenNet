# Compiler settings
CLANG ?= clang
CFLAGS := -O2 -g -Wall -Werror

# Go settings
GO ?= go
GOFLAGS := -v

# Output binary name
BINARY := OpenNet  # Changed from nettest

# Directories
BPFDIR := bpf
BPFOBJ := $(BPFDIR)/capture.o

.PHONY: all clean build generate

all: build

# Build the final binary
build: generate
	$(GO) build $(GOFLAGS) -o $(BINARY)

# Generate Go bindings for eBPF code
generate:
	$(GO) generate

# Clean build artifacts
clean:
	rm -f $(BINARY)
	rm -f $(BPFOBJ)
	rm -f capture_bpf*

# Build and run with sudo (helper target)
run: build
	sudo ./$(BINARY) $(IFACE)

# Help message when just running make
help:
	@echo "Available targets:"
	@echo "  build     - Build the program (default)"
	@echo "  generate  - Generate Go bindings for eBPF code"
	@echo "  clean     - Remove build artifacts"
	@echo "  run      - Build and run with sudo (specify IFACE=<interface>)"
	@echo ""
	@echo "Example usage:"
	@echo "  make run IFACE=eth0"

.DEFAULT_GOAL := help
