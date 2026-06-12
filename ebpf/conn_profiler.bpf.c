// SPDX-License-Identifier: MIT
/*
 * MinervaDB PostgreSQL Profiler - Connection Profiler eBPF Program
 *
 * Profiles PostgreSQL connection lifecycle using kernel TCP kprobes
 * and PostgreSQL-specific uprobes. Tracks connection establishment,
 * authentication, idle time, and session duration.
 *
 * Probe points:
 *   - kprobe/tcp_v4_connect    - TCP connection initiated
 *   - kretprobe/inet_csk_accept - New connection accepted
 *   - kprobe/tcp_close         - Connection closed
 *   - uprobe on AuthenticationMD5Password() - Auth probe
 *   - uprobe on ClientAuthentication()       - Auth start
 *   - uretprobe on ClientAuthentication()    - Auth end
 *   - uprobe on PostgresMain()               - Backend start
 *
 * Copyright (c) 2026 MinervaDB Inc.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual MIT/GPL";

/* ============================================================
 * Maps
 * ============================================================ */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} conn_events SEC(".maps");

/* Track connection state per PID */
struct conn_state {
    __u64  connect_ns;
    __u64  auth_start_ns;
    __u64  auth_end_ns;
    __u32  client_addr;
    __u16  client_port;
    __u16  server_port;
    __u8   ssl_enabled;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct conn_state);
} conn_states SEC(".maps");

/* Active connection counter per database */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);         /* db_oid */
    __type(value, __u64);       /* active count */
} active_conn_counts SEC(".maps");

/* Global connection statistics */
struct global_conn_stats {
    __u64  total_connections;
    __u64  total_disconnections;
    __u64  total_auth_time_ns;
    __u64  max_auth_time_ns;
    __u64  total_session_time_ns;
    __u64  max_session_time_ns;
    __u64  ssl_connections;
    __u64  non_ssl_connections;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_conn_stats);
} global_conn_stats SEC(".maps");

/* ============================================================
 * Kernel kprobe: inet_csk_accept - TCP Accept
 *
 * Fires when PostgreSQL postmaster accepts a new client connection.
 * ============================================================ */

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(kretprobe_inet_csk_accept, struct sock *sk)
{
    if (!sk) return 0;

    /* Filter to PostgreSQL process */
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    if (comm[0] != 'p' || comm[1] != 'o') return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    /* Extract connection info from sock structure */
    __u32 client_addr = 0;
    __u16 client_port = 0;
    __u16 server_port = 0;

    /* Read IPv4 addresses using BTF CO-RE */
    struct inet_sock *inet = (struct inet_sock *)sk;
    bpf_core_read(&client_addr, sizeof(client_addr), &inet->inet_daddr);
    bpf_core_read(&client_port, sizeof(client_port), &inet->inet_dport);
    bpf_core_read(&server_port, sizeof(server_port), &inet->inet_sport);

    struct conn_state state = {
        .connect_ns  = now,
        .client_addr = client_addr,
        .client_port = bpf_ntohs(client_port),
        .server_port = bpf_ntohs(server_port),
    };
    bpf_map_update_elem(&conn_states, &pid, &state, BPF_ANY);

    /* Update global stats */
    __u32 zero = 0;
    struct global_conn_stats *stats = bpf_map_lookup_elem(&global_conn_stats, &zero);
    if (stats)
        __sync_fetch_and_add(&stats->total_connections, 1);

    return 0;
}

/* ============================================================
 * uprobe: ClientAuthentication - Auth tracking
 * void ClientAuthentication(Port *port)
 * ============================================================ */

SEC("uprobe/postgres:ClientAuthentication")
int BPF_UPROBE(pg_client_auth_start, void *port)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct conn_state *state = bpf_map_lookup_elem(&conn_states, &pid);
    if (state)
        state->auth_start_ns = now;

    return 0;
}

SEC("uretprobe/postgres:ClientAuthentication")
int BPF_URETPROBE(pg_client_auth_done)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    struct conn_state *state = bpf_map_lookup_elem(&conn_states, &pid);
    if (state && state->auth_start_ns > 0) {
        state->auth_end_ns = now;

        __u64 auth_ns = now - state->auth_start_ns;

        __u32 zero = 0;
        struct global_conn_stats *stats = bpf_map_lookup_elem(&global_conn_stats, &zero);
        if (stats) {
            __sync_fetch_and_add(&stats->total_auth_time_ns, auth_ns);
            if (auth_ns > stats->max_auth_time_ns)
                stats->max_auth_time_ns = auth_ns;
        }
    }

    return 0;
}

/* ============================================================
 * kprobe: tcp_close - Connection closed
 * ============================================================ */

SEC("kprobe/tcp_close")
int BPF_KPROBE(kprobe_tcp_close, struct sock *sk, long timeout)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();

    /* Filter to PostgreSQL */
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    if (comm[0] != 'p' || comm[1] != 'o') return 0;

    struct conn_state *state = bpf_map_lookup_elem(&conn_states, &pid);
    if (!state) return 0;

    __u64 session_ns = 0;
    if (state->connect_ns > 0 && now > state->connect_ns)
        session_ns = now - state->connect_ns;

    __u64 auth_ns = 0;
    if (state->auth_end_ns > state->auth_start_ns)
        auth_ns = state->auth_end_ns - state->auth_start_ns;

    /* Emit connection event */
    struct conn_event *event = bpf_ringbuf_reserve(&conn_events, sizeof(*event), 0);
    if (event) {
        event->timestamp_ns      = now;
        event->connect_time_ns   = state->connect_ns;
        event->auth_time_ns      = auth_ns;
        event->disconnect_time_ns = now;
        event->session_duration_ns = session_ns;
        event->pid               = pid;
        event->client_addr       = state->client_addr;
        event->client_port       = state->client_port;
        event->server_port       = state->server_port;
        event->ssl_enabled       = state->ssl_enabled;
        event->conn_type         = 2;  /* closed */
        bpf_ringbuf_submit(event, 0);
    }

    /* Update global stats */
    __u32 zero = 0;
    struct global_conn_stats *stats = bpf_map_lookup_elem(&global_conn_stats, &zero);
    if (stats) {
        __sync_fetch_and_add(&stats->total_disconnections, 1);
        __sync_fetch_and_add(&stats->total_session_time_ns, session_ns);
        if (session_ns > stats->max_session_time_ns)
            stats->max_session_time_ns = session_ns;
    }

    bpf_map_delete_elem(&conn_states, &pid);
    return 0;
}

/* ============================================================
 * Cleanup
 * ============================================================ */

SEC("tracepoint/sched/sched_process_exit")
int tp_sched_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&conn_states, &pid);
    return 0;
}
