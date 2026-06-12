/* SPDX-License-Identifier: MIT */
/*
 * MinervaDB PostgreSQL Profiler
 * Common data structures shared between eBPF kernel programs and userspace
 *
 * Copyright (c) 2026 MinervaDB Inc.
 * Author: MinervaDB Engineering Team <engineering@minervadb.com>
 */

#ifndef MINERVADB_PG_PROFILER_COMMON_H
#define MINERVADB_PG_PROFILER_COMMON_H

#include <linux/types.h>

/* Maximum sizes */
#define MAX_QUERY_LEN       4096
#define MAX_STACK_DEPTH     127
#define MAX_COMM_LEN        16
#define MAX_FILENAME_LEN    256
#define MAX_WAIT_EVENT_LEN  64
#define MAX_RELATION_LEN    128
#define MAX_DBNAME_LEN      64

/* ============================================================
 * Query Profiler Events
 * ============================================================ */

/* Query execution phases */
enum query_phase {
    QUERY_PHASE_PARSE    = 0,
    QUERY_PHASE_PLAN     = 1,
    QUERY_PHASE_EXECUTE  = 2,
    QUERY_PHASE_TOTAL    = 3,
};

/* Query event - emitted on query completion */
struct query_event {
    __u64  timestamp_ns;        /* Event timestamp (nanoseconds since boot) */
    __u64  start_ns;            /* Query start timestamp */
    __u64  end_ns;              /* Query end timestamp */
    __u64  parse_duration_ns;   /* Parse phase duration */
    __u64  plan_duration_ns;    /* Plan phase duration */
    __u64  exec_duration_ns;    /* Execute phase duration */
    __u64  total_duration_ns;   /* Total query duration */
    __u32  pid;                 /* Backend PID */
    __u32  tid;                 /* Thread ID */
    __u32  db_oid;              /* Database OID */
    __u32  user_oid;            /* User OID */
    __u64  query_id;            /* Query fingerprint hash */
    __u64  rows_returned;       /* Rows returned by query */
    __u64  rows_affected;       /* Rows affected (DML) */
    __u64  buffers_hit;         /* Buffer cache hits */
    __u64  buffers_read;        /* Buffer cache misses (disk reads) */
    __u64  buffers_dirtied;     /* Buffers dirtied */
    __u64  wal_bytes;           /* WAL bytes generated */
    char   dbname[MAX_DBNAME_LEN];      /* Database name */
    char   query[MAX_QUERY_LEN];        /* Query text (truncated) */
    char   application_name[64];        /* Application name */
    __u8   is_slow;             /* 1 if query exceeded slow threshold */
    __u8   had_error;           /* 1 if query ended with error */
    __u8   query_type;          /* 0=SELECT, 1=INSERT, 2=UPDATE, 3=DELETE, 4=OTHER */
    __u8   padding[5];
} __attribute__((packed));

/* ============================================================
 * Lock Profiler Events
 * ============================================================ */

/* Lock modes (mirrors PostgreSQL LOCKMODE) */
enum pg_lockmode {
    PG_LOCKMODE_NONE            = 0,
    PG_LOCKMODE_AccessShare     = 1,
    PG_LOCKMODE_RowShare        = 2,
    PG_LOCKMODE_RowExclusive    = 3,
    PG_LOCKMODE_ShareUpdateExcl = 4,
    PG_LOCKMODE_Share           = 5,
    PG_LOCKMODE_ShareRowExcl    = 6,
    PG_LOCKMODE_Exclusive       = 7,
    PG_LOCKMODE_AccessExclusive = 8,
};

/* Lock types */
enum pg_locktype {
    PG_LOCKTYPE_RELATION   = 0,
    PG_LOCKTYPE_PAGE       = 1,
    PG_LOCKTYPE_TUPLE      = 2,
    PG_LOCKTYPE_TRANSACTION = 3,
    PG_LOCKTYPE_OBJECT     = 4,
    PG_LOCKTYPE_ADVISORY   = 5,
    PG_LOCKTYPE_LWLOCK     = 6,
};

/* Lock acquisition event */
struct lock_event {
    __u64  timestamp_ns;        /* Event timestamp */
    __u64  wait_start_ns;       /* Lock wait start time */
    __u64  wait_end_ns;         /* Lock acquired time */
    __u64  hold_start_ns;       /* Lock hold start time */
    __u64  hold_end_ns;         /* Lock released time */
    __u64  wait_duration_ns;    /* Time spent waiting for lock */
    __u64  hold_duration_ns;    /* Time spent holding lock */
    __u32  pid;                 /* Backend PID */
    __u32  blocker_pid;         /* PID of lock holder (blocker) */
    __u32  db_oid;              /* Database OID */
    __u32  rel_oid;             /* Relation OID (for relation locks) */
    __u64  transaction_id;      /* Transaction ID */
    __u8   lockmode;            /* Lock mode (pg_lockmode enum) */
    __u8   locktype;            /* Lock type (pg_locktype enum) */
    __u8   granted;             /* 1 if lock was granted, 0 if timed out */
    __u8   is_deadlock;         /* 1 if this was part of deadlock */
    char   relation_name[MAX_RELATION_LEN];  /* Relation name */
    char   lockname[64];        /* Lock name (for LWLocks) */
} __attribute__((packed));

/* ============================================================
 * I/O Profiler Events
 * ============================================================ */

/* I/O operation types */
enum io_op_type {
    IO_OP_READ      = 0,
    IO_OP_WRITE     = 1,
    IO_OP_FSYNC     = 2,
    IO_OP_TRUNCATE  = 3,
};

/* Block I/O event */
struct io_event {
    __u64  timestamp_ns;        /* Event timestamp */
    __u64  issue_ns;            /* I/O issue timestamp */
    __u64  complete_ns;         /* I/O completion timestamp */
    __u64  latency_ns;          /* I/O latency */
    __u64  bytes;               /* Bytes transferred */
    __u64  offset;              /* File offset */
    __u32  pid;                 /* Backend PID */
    __u32  db_oid;              /* Database OID */
    __u32  rel_filenode;        /* Relation filenode */
    __u32  block_num;           /* Block number */
    __u32  fork_number;         /* Fork number (main/fsm/vm) */
    __u8   op_type;             /* io_op_type enum */
    __u8   is_sync;             /* 1 if synchronous I/O */
    __u8   from_cache;          /* 1 if served from OS page cache */
    __u8   padding;
    char   filename[MAX_FILENAME_LEN];  /* Relation file path */
    char   device[32];          /* Block device name */
} __attribute__((packed));

/* Buffer cache event */
struct buffer_event {
    __u64  timestamp_ns;
    __u32  pid;
    __u32  db_oid;
    __u32  rel_oid;
    __u32  block_num;
    __u8   is_hit;              /* 1 = cache hit, 0 = cache miss */
    __u8   is_dirty;            /* 1 = dirty buffer */
    __u8   fork_number;
    __u8   padding;
    char   relation_name[MAX_RELATION_LEN];
} __attribute__((packed));

/* ============================================================
 * Memory Profiler Events
 * ============================================================ */

/* Memory allocation event (palloc/pfree) */
struct mem_event {
    __u64  timestamp_ns;
    __u64  address;             /* Allocated/freed address */
    __u64  size;                /* Allocation size */
    __u32  pid;                 /* Backend PID */
    __u8   op_type;             /* 0=palloc, 1=pfree, 2=repalloc */
    __u8   padding[3];
    char   context_name[64];    /* Memory context name */
    __u64  stack_id;            /* Stack trace ID for attribution */
} __attribute__((packed));

/* Memory context stats */
struct mem_context_stats {
    __u64  total_space;         /* Total space in context */
    __u64  free_space;          /* Free space in context */
    __u64  used_space;          /* Used space */
    __u64  alloc_count;         /* Number of allocations */
    __u64  free_count;          /* Number of frees */
    char   context_name[64];
};

/* ============================================================
 * WAL Profiler Events
 * ============================================================ */

/* WAL record types */
enum wal_record_type {
    WAL_TYPE_HEAP      = 0,
    WAL_TYPE_BTREE     = 1,
    WAL_TYPE_SEQUENCE  = 2,
    WAL_TYPE_CHECKPOINT = 3,
    WAL_TYPE_OTHER     = 4,
};

/* WAL write event */
struct wal_event {
    __u64  timestamp_ns;
    __u64  write_start_ns;
    __u64  write_end_ns;
    __u64  flush_start_ns;
    __u64  flush_end_ns;
    __u64  lsn;                 /* Log Sequence Number */
    __u64  end_lsn;             /* End LSN */
    __u64  bytes_written;       /* Bytes written to WAL */
    __u64  flush_latency_ns;    /* fsync latency */
    __u32  pid;                 /* WAL writer PID */
    __u8   record_type;         /* wal_record_type enum */
    __u8   is_checkpoint;       /* 1 if checkpoint record */
    __u8   is_full_page;        /* 1 if full page write */
    __u8   padding;
} __attribute__((packed));

/* ============================================================
 * Connection Profiler Events
 * ============================================================ */

/* Connection lifecycle event */
struct conn_event {
    __u64  timestamp_ns;
    __u64  connect_time_ns;     /* Connection establishment time */
    __u64  auth_time_ns;        /* Authentication duration */
    __u64  disconnect_time_ns;  /* Disconnection timestamp */
    __u64  session_duration_ns; /* Total session duration */
    __u32  pid;                 /* Backend PID */
    __u32  client_addr;         /* Client IP (IPv4) */
    __u16  client_port;         /* Client port */
    __u16  server_port;         /* Server port */
    __u8   conn_type;           /* 0=new, 1=established, 2=closed */
    __u8   auth_method;         /* Authentication method */
    __u8   ssl_enabled;         /* 1 if SSL/TLS connection */
    __u8   padding;
    char   dbname[MAX_DBNAME_LEN];
    char   username[64];
    char   application_name[64];
} __attribute__((packed));

/* ============================================================
 * Wait Event Profiler Events
 * ============================================================ */

/* Wait event categories (matches PostgreSQL WaitEventType) */
enum wait_event_type {
    WAIT_EVENT_LOCK       = 0,
    WAIT_EVENT_LWLOCK     = 1,
    WAIT_EVENT_BUFFER_PIN = 2,
    WAIT_EVENT_IO         = 3,
    WAIT_EVENT_EXTENSION  = 4,
    WAIT_EVENT_CLIENT     = 5,
    WAIT_EVENT_IPC        = 6,
    WAIT_EVENT_TIMEOUT    = 7,
    WAIT_EVENT_CPU        = 8,  /* Not waiting (running) */
};

/* Wait event sample */
struct wait_event {
    __u64  timestamp_ns;
    __u64  wait_start_ns;
    __u64  wait_end_ns;
    __u64  wait_duration_ns;
    __u32  pid;
    __u32  db_oid;
    __u8   wait_type;           /* wait_event_type enum */
    __u8   padding[3];
    char   wait_event_name[MAX_WAIT_EVENT_LEN];
    char   query_id_hex[17];    /* Query ID as hex string */
} __attribute__((packed));

/* ============================================================
 * CPU Profiler Events (Stack Traces)
 * ============================================================ */

/* CPU sample with stack trace */
struct cpu_sample {
    __u64  timestamp_ns;
    __u32  pid;
    __u32  tid;
    __u64  kstack_id;           /* Kernel stack trace ID */
    __u64  ustack_id;           /* Userspace stack trace ID */
    __u64  cpu_ns;              /* CPU time accumulated */
    char   comm[MAX_COMM_LEN];  /* Process name */
} __attribute__((packed));

/* ============================================================
 * Vacuum Profiler Events
 * ============================================================ */

/* Vacuum/autovacuum event */
struct vacuum_event {
    __u64  timestamp_ns;
    __u64  start_ns;
    __u64  end_ns;
    __u64  duration_ns;
    __u64  heap_blks_scanned;
    __u64  heap_blks_vacuumed;
    __u64  index_scans;
    __u64  tuples_removed;
    __u64  dead_tuples;
    __u32  pid;
    __u32  db_oid;
    __u32  rel_oid;
    __u8   is_autovacuum;
    __u8   is_analyze;
    __u8   is_wraparound;
    __u8   padding;
    char   relation_name[MAX_RELATION_LEN];
} __attribute__((packed));

/* ============================================================
 * eBPF Map Key Types
 * ============================================================ */

/* Key for per-query statistics maps */
struct query_key {
    __u64  query_id;            /* Query fingerprint */
    __u32  db_oid;
    __u32  padding;
};

/* Key for per-relation I/O maps */
struct relation_key {
    __u32  db_oid;
    __u32  rel_filenode;
    __u32  fork_number;
    __u32  padding;
};

/* Key for per-PID tracking maps */
struct pid_key {
    __u32  pid;
    __u32  padding;
};

/* ============================================================
 * eBPF Ring Buffer Event Types
 * ============================================================ */

enum event_type {
    EVENT_TYPE_QUERY     = 1,
    EVENT_TYPE_LOCK      = 2,
    EVENT_TYPE_IO        = 3,
    EVENT_TYPE_BUFFER    = 4,
    EVENT_TYPE_MEMORY    = 5,
    EVENT_TYPE_WAL       = 6,
    EVENT_TYPE_CONN      = 7,
    EVENT_TYPE_WAIT      = 8,
    EVENT_TYPE_CPU       = 9,
    EVENT_TYPE_VACUUM    = 10,
};

/* Generic event header for ring buffer multiplexing */
struct event_header {
    __u32  type;                /* event_type enum */
    __u32  size;                /* Total event size including header */
    __u64  timestamp_ns;        /* Event timestamp */
};

/* ============================================================
 * Configuration (passed from userspace via eBPF maps)
 * ============================================================ */

struct profiler_config {
    __u64  query_min_duration_ns;   /* Minimum query duration to record */
    __u64  lock_min_wait_ns;        /* Minimum lock wait to record */
    __u64  io_min_latency_ns;       /* Minimum I/O latency to record */
    __u32  cpu_sample_period;       /* CPU sampling period (ns) */
    __u32  max_stack_depth;         /* Maximum stack depth to capture */
    __u8   enable_query;
    __u8   enable_lock;
    __u8   enable_io;
    __u8   enable_memory;
    __u8   enable_wal;
    __u8   enable_conn;
    __u8   enable_cpu;
    __u8   enable_wait;
    __u8   enable_vacuum;
    __u8   padding[7];
};

#endif /* MINERVADB_PG_PROFILER_COMMON_H */
