# Troubleshooting Guide

> MinervaDB PostgreSQL Profiler v1.0

This guide covers common issues encountered during installation, startup, and operation. Each section includes diagnostic commands, root causes, and step-by-step fixes.

## Table of Contents

- [Installation Issues](#installation-issues)
- [Startup and Load Failures](#startup-and-load-failures)
- [USDT Probe Issues](#usdt-probe-issues)
- [Permissions and Privilege Errors](#permissions-and-privilege-errors)
- [BTF and CO-RE Errors](#btf-and-co-re-errors)
- [Ring Buffer Drops](#ring-buffer-drops)
- [No Output or Empty Reports](#no-output-or-empty-reports)
- [Prometheus Exporter Issues](#prometheus-exporter-issues)
- [Flame Graph Issues](#flame-graph-issues)
- [High Overhead](#high-overhead)
- [PostgreSQL Version Compatibility](#postgresql-version-compatibility)
- [Kernel Version Issues](#kernel-version-issues)
- [Docker and Container Issues](#docker-and-container-issues)
- [Diagnostic Commands Reference](#diagnostic-commands-reference)

---

## Installation Issues

### Python dependency errors

**Symptom:**
```
ModuleNotFoundError: No module named 'bcc'
```

**Cause:** BCC Python bindings must be installed via the system package manager, not pip.

**Fix:**
```bash
# Ubuntu/Debian
sudo apt-get install -y python3-bpfcc bpfcc-tools linux-headers-$(uname -r)

# RHEL/Rocky/AlmaLinux 9
sudo dnf install -y bcc bcc-tools kernel-devel-$(uname -r)

# Amazon Linux 2023
sudo dnf install -y python3-bcc bcc-tools kernel-devel
```

After installing, verify:
```bash
python3 -c "import bcc; print(bcc.__version__)"
```

---

### clang/LLVM not found during make

**Symptom:**
```
make: clang: command not found
Makefile:12: *** eBPF compilation requires clang 10+.  Stop.
```

**Fix:**
```bash
# Ubuntu 22.04+
sudo apt-get install -y clang llvm

# RHEL 9
sudo dnf install -y clang llvm

# Verify version (must be >= 10)
clang --version
```

---

### libbpf headers missing

**Symptom:**
```
fatal error: bpf/libbpf.h: No such file or directory
```

**Fix:**
```bash
# Ubuntu 22.04+
sudo apt-get install -y libbpf-dev libelf-dev zlib1g-dev

# RHEL 9
sudo dnf install -y libbpf-devel elfutils-libelf-devel zlib-devel
```

---

## Startup and Load Failures

### eBPF program load failed: operation not permitted

**Symptom:**
```
ERROR: Failed to load eBPF program query_profiler: Operation not permitted (EPERM)
```

**Cause:** Missing kernel capabilities.

**Fix (option 1: run as root):**
```bash
sudo minervadb-profiler --duration 60
```

**Fix (option 2: file capabilities, Linux 5.8+):**
```bash
sudo setcap cap_bpf,cap_perfmon,cap_sys_ptrace+eip /usr/local/bin/minervadb-profiler
minervadb-profiler --duration 60
```

**Fix (option 3: check kernel version):**
```bash
uname -r  # must be >= 5.8 for CAP_BPF / CAP_PERFMON
# If < 5.8, root is required
```

---

### eBPF verifier rejected program

**Symptom:**
```
ERROR: eBPF verifier rejected program memory_profiler: 
  R1 unbounded memory access, use 'var &= const' pattern
```

**Cause:** The eBPF verifier is stricter on older kernels. The memory_profiler is particularly sensitive.

**Fix:**
- Upgrade to kernel 5.15+ for the best verifier support.
- On kernel 5.4-5.10, disable the memory profiler: set `memory_profiler: false` in `/etc/minervadb/profiler.yaml`.
- Check verifier log for details:
```bash
sudo minervadb-profiler --debug-verifier 2>&1 | head -100
```

---

### BPF JIT compilation failed

**Symptom:**
```
ERROR: BPF JIT compilation failed or JIT disabled
```

**Cause:** BPF JIT is disabled (affects performance severely) or JIT memory limit exceeded.

**Fix:**
```bash
# Enable JIT
echo 1 | sudo tee /proc/sys/net/core/bpf_jit_enable

# Increase JIT memory limit (if loading many modules fails)
echo 268435456 | sudo tee /proc/sys/net/core/bpf_jit_limit

# Verify
cat /proc/sys/net/core/bpf_jit_enable   # should be 1
```

---

## USDT Probe Issues

### No USDT probes found in postgres binary

**Symptom:**
```
WARNING: No USDT probes found in /usr/lib/postgresql/16/bin/postgres
         Falling back to uprobes (higher overhead, less precise)
```

**Cause:** PostgreSQL was compiled without `--enable-dtrace`.

**Diagnosis:**
```bash
readelf -n $(which postgres) | grep -c stapsdt
# Output: 0 means no USDT probes
```

**Fix (option 1: use distro USDT build):**

Ubuntu provides a USDT-enabled build:
```bash
sudo apt-get install -y postgresql-16
# Ubuntu PostgreSQL packages are compiled with --enable-dtrace
```

**Fix (option 2: compile PostgreSQL with USDT):**
```bash
./configure --enable-dtrace --prefix=/usr/local/pgsql
make -j$(nproc) && sudo make install
```

**Fix (option 3: continue without USDT):**

The profiler falls back to uprobe-based tracing automatically. Overhead increases slightly (~0.3-0.5% additional) and parse/plan/execute phase split is unavailable.

---

### USDT probe attach failed: no such process

**Symptom:**
```
ERROR: Failed to attach USDT probe postgresql:query__start: no such process (PID 12345)
```

**Cause:** PostgreSQL postmaster PID changed (restart occurred) or profiler started before PostgreSQL.

**Fix:**
```bash
# Verify PostgreSQL is running
pg_isready -h localhost -p 5432

# Restart the profiler (it auto-detects running postmaster)
sudo minervadb-profiler --duration 60
```

---

## Permissions and Privilege Errors

### Cannot open /sys/kernel/debug/tracing

**Symptom:**
```
ERROR: Cannot open /sys/kernel/debug/tracing: Permission denied
```

**Fix:**
```bash
# Mount debugfs if not mounted
sudo mount -t debugfs none /sys/kernel/debug

# Or add to /etc/fstab for persistence:
echo "debugfs /sys/kernel/debug debugfs defaults 0 0" | sudo tee -a /etc/fstab
```

---

### Cannot read /proc/<pid>/maps

**Symptom:**
```
WARNING: Cannot read /proc/12345/maps: Permission denied
         uprobe symbol resolution may be incomplete
```

**Cause:** Missing `CAP_SYS_PTRACE`.

**Fix:**
```bash
# Add CAP_SYS_PTRACE to file capabilities
sudo setcap cap_bpf,cap_perfmon,cap_sys_ptrace+eip /usr/local/bin/minervadb-profiler

# Or run with sudo
sudo minervadb-profiler
```

---

## BTF and CO-RE Errors

### BTF not available: /sys/kernel/btf/vmlinux not found

**Symptom:**
```
ERROR: BTF not available: /sys/kernel/btf/vmlinux: No such file or directory
       eBPF CO-RE requires CONFIG_DEBUG_INFO_BTF=y
```

**Cause:** Kernel compiled without `CONFIG_DEBUG_INFO_BTF=y`.

**Diagnosis:**
```bash
grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)
# Expected: CONFIG_DEBUG_INFO_BTF=y
```

**Fix (option 1: upgrade kernel):**

All Ubuntu 20.04+ HWE kernels and RHEL 9 kernels have BTF enabled. Upgrade:
```bash
# Ubuntu: upgrade to HWE kernel (5.15+)
sudo apt-get install -y linux-image-generic-hwe-20.04
sudo reboot
```

**Fix (option 2: generate vmlinux BTF manually):**

If you have a kernel with `CONFIG_DEBUG_INFO=y` but not BTF, generate the BTF file:
```bash
sudo apt-get install -y pahole
pahole --btf_encode_detached /sys/kernel/btf/vmlinux /usr/lib/debug/boot/vmlinux-$(uname -r)
```

---

### BTF type mismatch for struct

**Symptom:**
```
WARNING: CO-RE relocation failed for struct task_struct.pid
         Field offset patching failed, using fallback offset
```

**Cause:** Rare with standard kernels. Usually occurs with heavily patched enterprise kernels.

**Fix:** Report the kernel version and patch level via GitHub Issues. As a workaround, the profiler will use conservative fallback offsets which may reduce accuracy on affected fields.

---

## Ring Buffer Drops

### Events are being dropped

**Symptom (Prometheus metric):**
```bash
curl -s localhost:9187/metrics | grep profiler_ringbuf_drops
# pg_profiler_ringbuf_drops_total 15234
```

**Or in text output:**
```
[WARNING] Ring buffer dropped 15234 events in last 10s - consider increasing ring_buf_size_mb
```

**Root causes and fixes:**

1. **Ring buffer too small for event rate** — Increase `ebpf.ring_buf_size_mb`:
   ```yaml
   ebpf:
     ring_buf_size_mb: 128   # double from default 64
   ```

2. **Userspace collector CPU-starved** — Pin the profiler to a dedicated CPU:
   ```bash
   sudo taskset -c 31 minervadb-profiler
   ```

3. **Slow query threshold too low** — Raise to reduce event volume:
   ```yaml
   profiling:
     query_slow_threshold_ms: 200
   ```

4. **Memory profiler enabled at very high palloc rate** — Disable:
   ```yaml
   profiling:
     memory_profiler: false
   ```

---

## No Output or Empty Reports

### profiler shows 0 queries after running for 60 seconds

**Diagnosis steps:**

```bash
# 1. Verify PostgreSQL is running and accepting connections
pg_isready -h localhost -p 5432

# 2. Verify the profiler found the postmaster
sudo minervadb-profiler --list-targets
# Expected output: Found PostgreSQL postmaster PID: 12345, binary: /usr/lib/postgresql/16/bin/postgres

# 3. Generate test load
pgbench -h localhost -U postgres -c 5 -T 30 postgres &

# 4. Run profiler with verbose output
sudo minervadb-profiler --duration 30 --verbose --format text
```

**Common causes:**

- PostgreSQL is on a non-default port: use `--pg-port 5433`
- PostgreSQL binary path is non-standard: use `--pg-binary /path/to/postgres`
- USDT probes unavailable and uprobe fallback not working (see [USDT Probe Issues](#usdt-probe-issues))
- No actual queries executing during the profiling window

---

### JSON output file is empty or contains only headers

**Cause:** No queries exceeded the `query_slow_threshold_ms`.

**Fix:**
```bash
# Capture all queries (set threshold to 0)
sudo minervadb-profiler --slow-query-ms 0 --duration 30 --output /tmp/all_queries.json

# Or lower the threshold
sudo minervadb-profiler --slow-query-ms 10 --duration 30
```

---

## Prometheus Exporter Issues

### Port 9187 already in use

**Symptom:**
```
ERROR: Cannot bind Prometheus exporter to :9187 - Address already in use
```

**Fix:**
```bash
# Find what is using port 9187
sudo ss -tlnp | grep 9187

# Kill conflicting process or use alternate port
sudo minervadb-profiler --prometheus-port 9188
```

---

### Prometheus scrape returns 404

**Symptom:** Prometheus shows `UP` but all metrics are missing.

**Cause:** Scraping `/` instead of `/metrics`.

**Fix:** Ensure your prometheus.yml uses the correct path:
```yaml
scrape_configs:
  - job_name: 'minervadb-postgresql-profiler'
    metrics_path: /metrics      # <-- must be /metrics, not /
    static_configs:
      - targets: ['localhost:9187']
```

---

### pg_profiler_query_duration_seconds missing from metrics

**Cause:** No queries have been captured yet (profiler just started or threshold too high).

**Fix:** Generate some load and verify:
```bash
pgbench -h localhost -U postgres -c 10 -T 60 postgres
curl -s localhost:9187/metrics | grep pg_profiler_query
```

---

## Flame Graph Issues

### SVG file not generated

**Symptom:** Profiler exits successfully but no SVG file appears in `/var/lib/minervadb/flamegraphs/`.

**Diagnosis:**
```bash
# Check output directory exists and is writable
ls -la /var/lib/minervadb/flamegraphs/

# If missing, create it
sudo mkdir -p /var/lib/minervadb/flamegraphs
sudo chmod 755 /var/lib/minervadb/flamegraphs

# Check for errors
sudo minervadb-profiler --modules cpu --duration 30 --verbose 2>&1 | grep -i flame
```

---

### Flame graph shows only [unknown] frames

**Cause:** Missing debug symbols for the PostgreSQL binary.

**Fix:**
```bash
# Ubuntu: install debug symbols
sudo apt-get install -y postgresql-16-dbgsym

# Verify symbols are loaded
sudo minervadb-profiler --modules cpu --duration 15 --verbose 2>&1 | grep "symbol resolution"
```

---

### SVG is blank or too large to open

**Cause:** Excessively deep stacks or too many unique stacks (low-sample-rate issue).

**Fix:**
```bash
# Limit stack depth in SVG output
sudo minervadb-profiler --modules cpu --duration 30 --flame-max-depth 40

# Or increase sample rate for a shorter window
sudo minervadb-profiler --modules cpu --duration 15 --cpu-hz 199
```

---

## High Overhead

### TPS drop exceeds 2% with default configuration

**Steps to reduce overhead:**

1. **Check which modules are enabled:**
   ```bash
   sudo minervadb-profiler --show-config | grep -E "(profiler|enabled): (true|false)"
   ```

2. **Disable memory_profiler** (highest overhead module):
   ```yaml
   profiling:
     memory_profiler: false
   ```

3. **Raise slow query threshold** to reduce ring buffer pressure:
   ```yaml
   profiling:
     query_slow_threshold_ms: 200
   ```

4. **Reduce ring buffer size** (if drops are not occurring):
   ```yaml
   ebpf:
     ring_buf_size_mb: 16
   ```

5. **Pin profiler to isolated CPU** to avoid cache eviction:
   ```bash
   sudo taskset -c $(nproc --ignore 1) minervadb-profiler
   ```

See [Performance Tuning Guide](tuning-guide.md) for detailed overhead budgeting.

---

## PostgreSQL Version Compatibility

### Wait event USDT probes not found (PostgreSQL 12 or 13)

**Symptom:**
```
WARNING: Wait event USDT probes not available in this PostgreSQL build (requires 14+)
         wait_profiler will use polling fallback (1ms resolution)
```

**Cause:** Wait event USDT probes (`postgresql:wait__start`, `postgresql:wait__done`) were introduced in PostgreSQL 14.

**Fix:** Upgrade to PostgreSQL 14+ for full wait event instrumentation. On PostgreSQL 12-13, the wait profiler automatically falls back to a 1ms polling loop which increases CPU usage by ~0.5%.

---

### pg_stat_statements correlation not working

**Symptom:** Query IDs in profiler output do not match `pg_stat_statements.queryid`.

**Fix:**
```sql
-- Verify pg_stat_statements is loaded
SHOW shared_preload_libraries;
-- Must include 'pg_stat_statements'

-- If not loaded, add to postgresql.conf:
-- shared_preload_libraries = 'pg_stat_statements'
-- Then restart PostgreSQL

-- Verify compute_query_id is enabled (PostgreSQL 14+)
SHOW compute_query_id;
-- Should be 'auto' or 'on'
```

---

## Kernel Version Issues

### Running on kernel 5.4: ring buffer not available

**Symptom:**
```
INFO: BPF_MAP_TYPE_RINGBUF not available on kernel 5.4.x
      Falling back to BPF_MAP_TYPE_PERF_EVENT_ARRAY
```

This is an informational message, not an error. The profiler will function correctly but with per-CPU buffers instead of a shared ring buffer. Ordering of events across CPUs is not guaranteed.

**Recommended action:** Upgrade to kernel 5.10+ LTS for production deployments.

---

### Kernel 5.4: verifier rejects complex programs

**Fix:** Disable advanced modules that stress the 5.4 verifier:
```yaml
profiling:
  memory_profiler: false   # highest verifier complexity
  io_profiler: false       # moderate complexity
  # Keep: query_profiler, lock_profiler, wait_profiler
```

---

## Docker and Container Issues

### Container cannot load eBPF programs

**Symptom:**
```
ERROR: Failed to load eBPF program: Operation not permitted
       (running inside container without sufficient privileges)
```

**Fix:** Run with `--privileged` and host PID namespace:
```bash
docker run --privileged --pid=host --network=host \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /lib/modules:/lib/modules:ro \
  -v /usr/src:/usr/src:ro \
  -v /var/lib/minervadb:/var/lib/minervadb \
  minervadb/postgresql-profiler:1.0.0 \
  --duration 60
```

**Note:** `--pid=host` is required so the container can attach probes to the host PostgreSQL process.

---

### Docker: BTF not available inside container

**Symptom:**
```
ERROR: /sys/kernel/btf/vmlinux: No such file or directory
```

**Fix:** Mount the BTF file:
```bash
docker run --privileged --pid=host \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  -v /sys/fs/bpf:/sys/fs/bpf \
  -v /lib/modules:/lib/modules:ro \
  minervadb/postgresql-profiler:1.0.0
```

---

## Diagnostic Commands Reference

Run these commands to gather information before opening a GitHub issue:

```bash
# System information
uname -r                                    # kernel version
cat /etc/os-release                         # distribution
python3 --version                           # Python version

# eBPF environment
ls /sys/kernel/btf/vmlinux                  # BTF available
cat /proc/sys/net/core/bpf_jit_enable       # JIT enabled (should be 1)
bpftool version 2>/dev/null                 # bpftool version

# PostgreSQL
pg_isready -h localhost                     # PostgreSQL running
psql -U postgres -c "SELECT version();"    # PostgreSQL version
readelf -n $(which postgres) | grep -c stapsdt  # USDT probe count

# Kernel configuration
zcat /proc/config.gz 2>/dev/null | grep -E "CONFIG_BPF|CONFIG_DEBUG_INFO_BTF|CONFIG_KPROBES|CONFIG_UPROBES"

# Profiler startup diagnostics
sudo minervadb-profiler --check-requirements  # built-in requirements check
sudo minervadb-profiler --list-targets        # find PostgreSQL postmaster
sudo minervadb-profiler --version             # profiler version
```

---

If your issue is not covered here, please open a GitHub issue with the output of the diagnostic commands above:

**[Open an Issue](https://github.com/MinervaDB/MinervaDB-PostgreSQL-Profiler/issues/new)**

---

*See also: [Architecture](architecture.md) | [Tuning Guide](tuning-guide.md) | [Back to README](../README.md)*

*MinervaDB — Data Architecture, Engineering and Operations*
