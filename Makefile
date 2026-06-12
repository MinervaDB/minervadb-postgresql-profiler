# MinervaDB PostgreSQL Profiler - Makefile
# Copyright (c) 2026 MinervaDB Inc.
# SPDX-License-Identifier: MIT
#
# Build system for MinervaDB PostgreSQL Profiler
# Compiles eBPF programs and installs Python userspace components.
#
# Usage:
#   make ebpf           - Compile all eBPF programs
#   make install        - Install profiler system-wide
#   make clean          - Remove build artifacts
#   make check-deps     - Verify all dependencies
#   make test           - Run test suite
#   make vmlinux        - Generate vmlinux.h for BTF CO-RE support

# ============================================================
# Variables
# ============================================================

# Version
VERSION := 1.0.0

# Directories
EBPF_DIR    := ebpf
COLLECTOR   := collector
TOOLS_DIR   := tools
BUILD_DIR   := build
INSTALL_DIR := /usr/local/bin
CONFIG_DIR  := /etc/minervadb
LOG_DIR     := /var/log/minervadb
DATA_DIR    := /var/lib/minervadb

# eBPF compilation
CC          := clang
LLC         := llc
BPFTOOL     := bpftool
ARCH        := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KERNEL_VER  := $(shell uname -r)
KERNEL_HDRS := /usr/src/linux-headers-$(KERNEL_VER)

# Compiler flags for eBPF programs
BPF_CFLAGS  := -g -O2 -target bpf \
               -D__TARGET_ARCH_$(ARCH) \
               -I$(EBPF_DIR) \
               -I/usr/include \
               -I/usr/include/$(shell uname -m)-linux-gnu

# Additional flags for BTF CO-RE
BTF_CFLAGS  := $(BPF_CFLAGS) -DBPF_CORE_READ

# vmlinux.h generation
VMLINUX_H   := $(EBPF_DIR)/vmlinux.h
BTF_PATH    := /sys/kernel/btf/vmlinux

# Python
PYTHON      := python3
PIP         := pip3
VENV_DIR    := .venv

# ============================================================
# eBPF Source Files
# ============================================================

EBPF_SRCS := \
    $(EBPF_DIR)/query_profiler.bpf.c \
    $(EBPF_DIR)/lock_profiler.bpf.c  \
    $(EBPF_DIR)/io_profiler.bpf.c    \
    $(EBPF_DIR)/memory_profiler.bpf.c \
    $(EBPF_DIR)/wal_profiler.bpf.c   \
    $(EBPF_DIR)/conn_profiler.bpf.c  \
    $(EBPF_DIR)/cpu_profiler.bpf.c   \
    $(EBPF_DIR)/wait_profiler.bpf.c  \
    $(EBPF_DIR)/vacuum_profiler.bpf.c \
    $(EBPF_DIR)/repl_profiler.bpf.c

EBPF_OBJS := $(patsubst $(EBPF_DIR)/%.bpf.c, $(BUILD_DIR)/%.bpf.o, $(EBPF_SRCS))
EBPF_SKELS := $(patsubst $(BUILD_DIR)/%.bpf.o, $(BUILD_DIR)/%.skel.h, $(EBPF_OBJS))

# ============================================================
# Default target
# ============================================================

.PHONY: all
all: check-deps vmlinux ebpf

# ============================================================
# Dependency checking
# ============================================================

.PHONY: check-deps
check-deps:
	@echo "Checking dependencies..."
	@which clang        > /dev/null 2>&1 || (echo "ERROR: clang not found. Install: apt-get install clang" && exit 1)
	@which llvm-strip   > /dev/null 2>&1 || echo "WARNING: llvm-strip not found"
	@which bpftool      > /dev/null 2>&1 || echo "WARNING: bpftool not found. Install: apt-get install linux-tools-$(KERNEL_VER)"
	@test -f /sys/kernel/btf/vmlinux || echo "WARNING: BTF not available at /sys/kernel/btf/vmlinux"
	@test -d $(KERNEL_HDRS) || echo "WARNING: Kernel headers not found at $(KERNEL_HDRS)"
	@$(PYTHON) -c "import bcc" 2>/dev/null && echo "OK: python3-bpfcc available" || echo "WARNING: python3-bpfcc not found"
	@$(PYTHON) -c "import psycopg2" 2>/dev/null && echo "OK: psycopg2 available" || echo "INFO: psycopg2 not found (optional)"
	@$(PYTHON) -c "import yaml" 2>/dev/null && echo "OK: PyYAML available" || echo "WARNING: PyYAML not found"
	@$(PYTHON) -c "import rich" 2>/dev/null && echo "OK: rich available" || echo "INFO: rich not found (optional, for pretty output)"
	@echo "Dependency check complete."

# ============================================================
# vmlinux.h - BTF type information for CO-RE
# ============================================================

.PHONY: vmlinux
vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	@echo "Generating vmlinux.h from BTF..."
	@if test -f $(BTF_PATH); then \
		$(BPFTOOL) btf dump file $(BTF_PATH) format c > $(VMLINUX_H); \
		echo "Generated $(VMLINUX_H) from $(BTF_PATH)"; \
	elif test -f /sys/kernel/btf/vmlinux.xz; then \
		xzcat /sys/kernel/btf/vmlinux.xz | $(BPFTOOL) btf dump format c - > $(VMLINUX_H); \
	else \
		echo "WARNING: BTF not found. eBPF programs may not compile on all kernels."; \
		echo "Install BTF-enabled kernel or provide vmlinux BTF file."; \
		touch $(VMLINUX_H); \
	fi

# ============================================================
# eBPF compilation
# ============================================================

.PHONY: ebpf
ebpf: $(BUILD_DIR) $(EBPF_OBJS)
	@echo "All eBPF programs compiled successfully"

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# Compile each eBPF .bpf.c file to .bpf.o
$(BUILD_DIR)/%.bpf.o: $(EBPF_DIR)/%.bpf.c $(VMLINUX_H) $(EBPF_DIR)/common.h
	@echo "Compiling eBPF: $< -> $@"
	$(CC) $(BTF_CFLAGS) -c $< -o $@
	@# Strip debug info to reduce size (keep BTF)
	@if which llvm-strip > /dev/null 2>&1; then \
		llvm-strip -g $@; \
	fi

# Generate skeleton headers (for libbpf-based userspace)
$(BUILD_DIR)/%.skel.h: $(BUILD_DIR)/%.bpf.o
	@echo "Generating skeleton: $@"
	$(BPFTOOL) gen skeleton $< > $@ 2>/dev/null || echo "NOTE: bpftool skeleton generation requires bpftool 5.13+"

# ============================================================
# Python userspace installation
# ============================================================

.PHONY: python-deps
python-deps:
	@echo "Installing Python dependencies..."
	$(PIP) install -r requirements.txt

.PHONY: venv
venv:
	@echo "Creating virtual environment..."
	$(PYTHON) -m venv $(VENV_DIR)
	$(VENV_DIR)/bin/pip install -r requirements.txt

# ============================================================
# System installation
# ============================================================

.PHONY: install
install: ebpf install-dirs install-ebpf install-python install-tools install-config
	@echo ""
	@echo "MinervaDB PostgreSQL Profiler v$(VERSION) installed successfully!"
	@echo ""
	@echo "  Tools installed to: $(INSTALL_DIR)"
	@echo "  Config template:    $(CONFIG_DIR)/profiler.yaml.example"
	@echo "  Log directory:      $(LOG_DIR)"
	@echo "  Data directory:     $(DATA_DIR)"
	@echo ""
	@echo "  Start profiling:    sudo minervadb-profiler --help"

.PHONY: install-dirs
install-dirs:
	@echo "Creating directories..."
	install -d $(CONFIG_DIR)
	install -d $(LOG_DIR)
	install -d $(DATA_DIR)
	install -d $(DATA_DIR)/flamegraphs
	install -d $(DATA_DIR)/ebpf
	install -d $(DATA_DIR)/reports

.PHONY: install-ebpf
install-ebpf: ebpf
	@echo "Installing eBPF objects..."
	@if ls $(BUILD_DIR)/*.bpf.o 2>/dev/null; then \
		install -m 644 $(BUILD_DIR)/*.bpf.o $(DATA_DIR)/ebpf/; \
	fi

.PHONY: install-python
install-python: python-deps
	@echo "Installing Python package..."
	$(PIP) install -e . 2>/dev/null || ($(PIP) install collector/ 2>/dev/null || true)

.PHONY: install-tools
install-tools:
	@echo "Installing CLI tools..."
	@for tool in $(TOOLS_DIR)/pg-*; do \
		if test -f "$$tool"; then \
			install -m 755 "$$tool" $(INSTALL_DIR)/; \
			echo "  Installed: $$(basename $$tool)"; \
		fi; \
	done
	@# Install main tool
	install -m 755 collector/profiler_main.py $(INSTALL_DIR)/minervadb-profiler

.PHONY: install-config
install-config:
	@echo "Installing configuration..."
	@if test -f config/profiler.yaml; then \
		install -m 644 config/profiler.yaml $(CONFIG_DIR)/profiler.yaml.example; \
		if ! test -f $(CONFIG_DIR)/profiler.yaml; then \
			install -m 644 config/profiler.yaml $(CONFIG_DIR)/profiler.yaml; \
		fi; \
	fi

# ============================================================
# Testing
# ============================================================

.PHONY: test
test:
	@echo "Running test suite..."
	$(PYTHON) -m pytest tests/ -v 2>/dev/null || \
		$(PYTHON) -m unittest discover -s tests/ -v

.PHONY: test-ebpf
test-ebpf:
	@echo "Running eBPF verifier tests..."
	@for obj in $(BUILD_DIR)/*.bpf.o; do \
		echo "Verifying: $$obj"; \
		$(BPFTOOL) prog load $$obj /sys/fs/bpf/test_$$( basename $$obj .o) 2>&1 | head -5; \
		rm -f /sys/fs/bpf/test_$$(basename $$obj .o); \
	done

.PHONY: test-usdt
test-usdt:
	@echo "Checking PostgreSQL USDT probes..."
	@PG_BINARY=$$(which postgres 2>/dev/null || echo /usr/lib/postgresql/16/bin/postgres); \
	if test -f "$$PG_BINARY"; then \
		readelf -n "$$PG_BINARY" 2>/dev/null | grep -c "stapsdt" || echo "0 USDT probes found"; \
	else \
		echo "PostgreSQL binary not found at $$PG_BINARY"; \
	fi

# ============================================================
# Flame graph generation
# ============================================================

.PHONY: flamegraph
flamegraph:
	@echo "Generating CPU flame graph (30s sample)..."
	sudo $(PYTHON) collector/profiler_main.py --flamegraph --duration 30 \
		--flamegraph-output /tmp/pg_cpu_flamegraph.svg
	@echo "Flame graph saved to: /tmp/pg_cpu_flamegraph.svg"

# ============================================================
# Package distribution
# ============================================================

.PHONY: package
package: clean all
	@echo "Creating distribution package..."
	tar czf minervadb-postgresql-profiler-$(VERSION).tar.gz \
		--exclude='.git' \
		--exclude='$(BUILD_DIR)' \
		--exclude='$(VENV_DIR)' \
		--exclude='*.pyc' \
		--exclude='__pycache__' \
		.
	@echo "Package: minervadb-postgresql-profiler-$(VERSION).tar.gz"

.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	docker build -t minervadb/postgresql-profiler:$(VERSION) .
	docker tag minervadb/postgresql-profiler:$(VERSION) \
		minervadb/postgresql-profiler:latest

# ============================================================
# Development helpers
# ============================================================

.PHONY: lint
lint:
	@echo "Running Python linters..."
	$(PYTHON) -m flake8 collector/ tools/ --max-line-length 100 2>/dev/null || true
	$(PYTHON) -m mypy collector/ 2>/dev/null || true

.PHONY: format
format:
	@echo "Formatting Python code..."
	$(PYTHON) -m black collector/ tools/ 2>/dev/null || true
	$(PYTHON) -m isort collector/ tools/ 2>/dev/null || true

.PHONY: debug-info
debug-info:
	@echo "=== MinervaDB PostgreSQL Profiler Debug Info ==="
	@echo "Version:     $(VERSION)"
	@echo "Kernel:      $(KERNEL_VER)"
	@echo "Arch:        $(ARCH)"
	@echo "CC:          $$($(CC) --version | head -1)"
	@echo "Python:      $$($(PYTHON) --version)"
	@echo "Build dir:   $(BUILD_DIR)"
	@echo "eBPF dir:    $(EBPF_DIR)"
	@echo "Compiled:    $$(ls $(BUILD_DIR)/*.bpf.o 2>/dev/null | wc -l) eBPF programs"
	@echo "BTF:         $$(test -f $(BTF_PATH) && echo 'available' || echo 'not available')"

# ============================================================
# Cleanup
# ============================================================

.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "Clean complete."

.PHONY: distclean
distclean: clean
	@echo "Removing generated files..."
	rm -f $(VMLINUX_H)
	rm -rf $(VENV_DIR)
	rm -f minervadb-postgresql-profiler-*.tar.gz

.PHONY: uninstall
uninstall:
	@echo "Uninstalling MinervaDB PostgreSQL Profiler..."
	rm -f $(INSTALL_DIR)/minervadb-profiler
	rm -f $(INSTALL_DIR)/pg-query-profiler
	rm -f $(INSTALL_DIR)/pg-lock-profiler
	rm -f $(INSTALL_DIR)/pg-io-profiler
	rm -f $(INSTALL_DIR)/pg-cpu-profiler
	rm -f $(INSTALL_DIR)/pg-wait-profiler
	rm -f $(INSTALL_DIR)/pg-memory-profiler
	rm -f $(INSTALL_DIR)/pg-vacuum-profiler
	rm -f $(INSTALL_DIR)/pg-repl-profiler
	@echo "Uninstall complete. Config and data directories preserved."
	@echo "Remove manually: $(CONFIG_DIR) $(LOG_DIR) $(DATA_DIR)"

# ============================================================
# Help
# ============================================================

.PHONY: help
help:
	@echo "MinervaDB PostgreSQL Profiler v$(VERSION) - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all           - Build everything (default)"
	@echo "  check-deps    - Verify all dependencies are installed"
	@echo "  vmlinux       - Generate vmlinux.h for BTF CO-RE support"
	@echo "  ebpf          - Compile all eBPF programs"
	@echo "  python-deps   - Install Python dependencies"
	@echo "  install       - Install system-wide"
	@echo "  uninstall     - Remove installed files"
	@echo "  test          - Run test suite"
	@echo "  test-ebpf     - Run eBPF verifier tests"
	@echo "  test-usdt     - Check PostgreSQL USDT probes"
	@echo "  flamegraph    - Generate a CPU flame graph"
	@echo "  package       - Create distribution tarball"
	@echo "  docker-build  - Build Docker image"
	@echo "  lint          - Run code linters"
	@echo "  format        - Format Python code"
	@echo "  debug-info    - Print debug information"
	@echo "  clean         - Remove build artifacts"
	@echo "  distclean     - Remove all generated files"
	@echo "  help          - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make check-deps ebpf   # Build eBPF programs"
	@echo "  sudo make install      # Full system installation"
	@echo "  make test              # Run tests"
