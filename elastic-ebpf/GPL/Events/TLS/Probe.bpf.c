// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2026 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "Helpers.h"
#include "State.h"
#include "Varlen.h"

// Allow-list of TGIDs to capture TLS from. Opposite of trusted_pids (a
// deny-list): a TGID must be present here for a connection to be minted.
// Populated by quark_queue_track_tgid()/untrack_tgid().
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u8));
    __uint(max_entries, 512);
} tracked_tgids SEC(".maps");

static bool ebpf_events_is_tracked_tgid()
{
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    return bpf_map_lookup_elem(&tracked_tgids, &tgid) != NULL;
}

// Global monotonic connection-id counter, bumped once per SSL_new. conn_id 0 is
// never issued, it is reserved as the "unset" sentinel.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 1);
} tls_conn_id_ctr SEC(".maps");

static u64 tls_mint_conn_id(void)
{
    u32 zero = 0;
    u64 *ctr = bpf_map_lookup_elem(&tls_conn_id_ctr, &zero);

    if (!ctr)
        return 0;

    return __sync_fetch_and_add(ctr, 1) + 1;
}

// (tgid, ssl_ptr) -> per-connection state, established at SSL_new's uretprobe
// and torn down at SSL_free.
//
// The key must include tgid: an SSL* is only unique within one address space,
// so two tracked processes can hold objects at the same virtual address --
// keying on the pointer alone would cross-attribute them.
struct tls_ssl_key {
    u32 tgid;
    u64 ssl;
} __attribute__((packed));

// call_seq is monotonic per (conn_id, direction), incremented once per
// SSL_read/SSL_write call regardless of how many chunks it is split into. flags
// carries EBPF_TLS_CONN_F_* (currently only PREFIX_UNKNOWN, set when the
// connection was adopted mid-stream rather than seen from SSL_new).
struct tls_conn {
    u64 conn_id;
    u64 read_seq;
    u64 write_seq;
    u32 flags;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct tls_ssl_key);
    __type(value, struct tls_conn);
    __uint(max_entries, 16384);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} tls_conns SEC(".maps");

// Max bytes captured per SSL_read/SSL_write call, set by quark_queue_open()
// before the object is loaded, same pattern as consumer_pid in Helpers.h.
const volatile u32 max_tls_call = 0;

// Per-chunk size. Kept well under half of event_buffer_map's 128 KiB ceiling,
// same headroom rule TTY_OUT_MAX follows in Process/Probe.bpf.c.
#define TLS_CHUNK_MAX 32768u

struct tls_chunk_ctx {
    const void *base;
    u64 conn_id;
    enum ebpf_tls_direction direction;
    u64 call_seq;
    u32 call_len;     // true call length, before max_tls_call capping
    u32 captured_len; // min(call_len, max_tls_call)
    u32 chunk_total;
};

static long tls_emit_chunk(u32 idx, void *ctx)
{
    struct tls_chunk_ctx *cctx = ctx;
    struct ebpf_tls_chunk_event *event;
    struct ebpf_varlen_field *field;
    struct task_struct *task;
    u32 off, len_cap;

    if (idx >= cctx->chunk_total)
        return 1;

    off = idx * TLS_CHUNK_MAX;

    event = get_event_buffer();
    if (!event)
        return 1;

    task               = (struct task_struct *)bpf_get_current_task();
    event->hdr.type    = EBPF_EVENT_TLS_CHUNK;
    event->hdr.ts      = bpf_ktime_get_ns();
    event->hdr.ts_boot = bpf_ktime_get_boot_ns_helper();
    ebpf_pid_info__fill(&event->pids, task);
    event->conn_id      = cctx->conn_id;
    event->direction    = (uint8_t)cctx->direction;
    event->call_seq     = cctx->call_seq;
    event->call_len     = cctx->call_len;
    event->chunk_idx    = idx;
    event->chunk_total  = cctx->chunk_total;
    event->dropped      = 0;

    ebpf_vl_fields__init(&event->vl_fields);
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_TLS_DATA);

    /*
     * DO NOT REMOVE THE CASTS, see the identical warning in
     * Process/Probe.bpf.c's output_tty_event(): narrowing 64->32bit loses
     * verifier bound tracking on older verifiers, keep this all 32bit.
     */
    len_cap = (u32)cctx->captured_len - off;
    len_cap = (u32)(len_cap > TLS_CHUNK_MAX ? TLS_CHUNK_MAX : len_cap);

    if (bpf_probe_read_user(field->data, len_cap, (const char *)cctx->base + off)) {
        /*
         * This chunk's bytes are unreadable, but later chunks in the same
         * call read from different offsets into the same buffer and may
         * still succeed - keep going rather than aborting the whole call.
         */
        event->dropped = 1;
        ebpf_vl_field__set_size(&event->vl_fields, field, 0);
        ebpf_ringbuf_write(&ringbuf, event, EVENT_SIZE(event), 0);
        return 0;
    }

    ebpf_vl_field__set_size(&event->vl_fields, field, len_cap);
    if (ebpf_ringbuf_write(&ringbuf, event, EVENT_SIZE(event), 0) < 0) {
        /*
         * The full chunk didn't fit - the ring buffer is under enough
         * pressure that quark's existing "lost" stat will already be
         * incremented for it. Retry with a minimal drop marker instead.
         */
        event->dropped = 1;
        ebpf_vl_fields__init(&event->vl_fields);
        field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_TLS_DATA);
        ebpf_vl_field__set_size(&event->vl_fields, field, 0);
        ebpf_ringbuf_write(&ringbuf, event, EVENT_SIZE(event), 0);
    }

    return 0;
}

// Emits one SSL_read/SSL_write call as one or more chunks.
static void tls_emit_call(u64 conn_id, const void *base, u32 len,
                          enum ebpf_tls_direction direction, u64 call_seq)
{
    struct tls_chunk_ctx cctx = {};

    if (len == 0)
        return;

    cctx.base         = base;
    cctx.conn_id      = conn_id;
    cctx.direction    = direction;
    cctx.call_seq     = call_seq;
    cctx.call_len     = len;
    cctx.captured_len = max_tls_call != 0 && len > max_tls_call ? max_tls_call : len;
    cctx.chunk_total  = (cctx.captured_len + TLS_CHUNK_MAX - 1) / TLS_CHUNK_MAX;

    bpf_loop(cctx.chunk_total, tls_emit_chunk, &cctx, 0);
}

// Announces a connection becoming known (EBPF_EVENT_TLS_CONN), from either
// SSL_new (flags 0) or a mid-stream adoption (flags PREFIX_UNKNOWN).
static void tls_emit_conn(u64 conn_id, u32 flags)
{
    struct ebpf_tls_new_event *event;
    struct task_struct *task;

    event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        return;

    task               = (struct task_struct *)bpf_get_current_task();
    event->hdr.type    = EBPF_EVENT_TLS_CONN;
    event->hdr.ts      = bpf_ktime_get_ns();
    event->hdr.ts_boot = bpf_ktime_get_boot_ns_helper();
    ebpf_pid_info__fill(&event->pids, task);
    event->conn_id = conn_id;
    event->flags   = flags;

    bpf_ringbuf_submit(event, 0);
}

// Adopts a connection whose SSL_new was never observed: mints a fresh conn_id,
// records it flagged PREFIX_UNKNOWN, and announces it. The announce is withheld
// until the insert is confirmed so a full map never yields an establish with no
// state behind it; the caller re-resolves the entry from the map (rather than
// this returning a map-value pointer, which not every verifier accepts across a
// call).
static void tls_adopt_conn(struct tls_ssl_key *key)
{
    struct tls_conn conn = {};

    conn.conn_id = tls_mint_conn_id();
    if (conn.conn_id == 0)
        return;
    conn.flags = EBPF_TLS_CONN_F_PREFIX_UNKNOWN;

    bpf_map_update_elem(&tls_conns, key, &conn, BPF_ANY);
    if (!bpf_map_lookup_elem(&tls_conns, key))
        return;

    tls_emit_conn(conn.conn_id, EBPF_TLS_CONN_F_PREFIX_UNKNOWN);
}

// SSL_new has no entry probe: the SSL* it returns is the map key, so nothing
// useful can be done until the return.
SEC("uretprobe")
int BPF_URETPROBE(uretprobe__ssl_new, void *ssl)
{
    struct tls_ssl_key key;
    struct tls_conn conn = {};

    preempt_disable();

    if (ebpf_events_is_trusted_pid())
        goto out;
    if (!ebpf_events_is_tracked_tgid())
        goto out;
    if (!ssl)
        goto out;

    conn.conn_id = tls_mint_conn_id();
    if (conn.conn_id == 0)
        goto out;

    key = (struct tls_ssl_key){
        .tgid = bpf_get_current_pid_tgid() >> 32,
        .ssl  = (u64)ssl,
    };
    bpf_map_update_elem(&tls_conns, &key, &conn, BPF_ANY);

    tls_emit_conn(conn.conn_id, 0);

out:
    preempt_enable();
    return 0;
}

// SSL_free is the connection teardown. If the SSL was never tracked (no entry)
// this is a no-op.
SEC("uprobe")
int BPF_UPROBE(uprobe__ssl_free, void *ssl)
{
    struct ebpf_tls_close_event *event;
    struct task_struct *task;
    struct tls_ssl_key key;
    struct tls_conn *conn;
    u64 conn_id;

    preempt_disable();

    if (!ssl)
        goto out;

    key = (struct tls_ssl_key){
        .tgid = bpf_get_current_pid_tgid() >> 32,
        .ssl  = (u64)ssl,
    };
    conn = bpf_map_lookup_elem(&tls_conns, &key);
    if (!conn)
        goto out;
    conn_id = conn->conn_id;
    bpf_map_delete_elem(&tls_conns, &key);

    event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        goto out;

    task               = (struct task_struct *)bpf_get_current_task();
    event->hdr.type    = EBPF_EVENT_TLS_CONN_CLOSE;
    event->hdr.ts      = bpf_ktime_get_ns();
    event->hdr.ts_boot = bpf_ktime_get_boot_ns_helper();
    ebpf_pid_info__fill(&event->pids, task);
    event->conn_id = conn_id;

    bpf_ringbuf_submit(event, 0);

out:
    preempt_enable();
    return 0;
}

// The read/write entry probes stash the caller's buffer for the matching return
// probe. They gate on the same trusted deny-list / tracked allow-list as the
// capture path.
SEC("uprobe")
int BPF_UPROBE(uprobe__ssl_write, void *ssl, const void *buf, int num)
{
    struct ebpf_events_state state = {};

    preempt_disable();

    if (ebpf_events_is_trusted_pid())
        goto out;
    if (!ebpf_events_is_tracked_tgid())
        goto out;

    state.ssl_write.ssl = ssl;
    state.ssl_write.buf = (void *)buf;
    state.ssl_write.len = (u32)num;
    ebpf_events_state__set(EBPF_EVENTS_STATE_SSL_WRITE, &state);

out:
    preempt_enable();
    return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(uretprobe__ssl_write, int ret)
{
    struct ebpf_events_state *state;
    struct tls_ssl_key key;
    struct tls_conn *conn;
    u64 seq;

    preempt_disable();

    state = ebpf_events_state__get(EBPF_EVENTS_STATE_SSL_WRITE);
    if (!state)
        goto out;
    if (ret <= 0 || (u32)ret > state->ssl_write.len)
        goto out;

    key = (struct tls_ssl_key){
        .tgid = bpf_get_current_pid_tgid() >> 32,
        .ssl  = (u64)state->ssl_write.ssl,
    };
    conn = bpf_map_lookup_elem(&tls_conns, &key);
    if (!conn) {
        // Miss: SSL_new was never seen for this object. Adopt it only for a
        // tracked, non-trusted tgid; these checks are off the hot path.
        if (ebpf_events_is_trusted_pid())
            goto out;
        if (!ebpf_events_is_tracked_tgid())
            goto out;
        tls_adopt_conn(&key);
        conn = bpf_map_lookup_elem(&tls_conns, &key);
        if (!conn)
            goto out;
    }

    seq = __sync_fetch_and_add(&conn->write_seq, 1);
    tls_emit_call(conn->conn_id, state->ssl_write.buf, (u32)ret,
                  EBPF_TLS_DIR_WRITE, seq);

out:
    ebpf_events_state__del(EBPF_EVENTS_STATE_SSL_WRITE);
    preempt_enable();
    return 0;
}

// Same gate rationale as uprobe__ssl_write above.
SEC("uprobe")
int BPF_UPROBE(uprobe__ssl_read, void *ssl, void *buf, int num)
{
    struct ebpf_events_state state = {};

    preempt_disable();

    if (ebpf_events_is_trusted_pid())
        goto out;
    if (!ebpf_events_is_tracked_tgid())
        goto out;

    state.ssl_read.ssl = ssl;
    state.ssl_read.buf = buf;
    state.ssl_read.len = (u32)num;
    ebpf_events_state__set(EBPF_EVENTS_STATE_SSL_READ, &state);

out:
    preempt_enable();
    return 0;
}

SEC("uretprobe")
int BPF_URETPROBE(uretprobe__ssl_read, int ret)
{
    struct ebpf_events_state *state;
    struct tls_ssl_key key;
    struct tls_conn *conn;
    u64 seq;

    preempt_disable();

    state = ebpf_events_state__get(EBPF_EVENTS_STATE_SSL_READ);
    if (!state)
        goto out;
    if (ret <= 0 || (u32)ret > state->ssl_read.len)
        goto out;

    key = (struct tls_ssl_key){
        .tgid = bpf_get_current_pid_tgid() >> 32,
        .ssl  = (u64)state->ssl_read.ssl,
    };
    conn = bpf_map_lookup_elem(&tls_conns, &key);
    if (!conn) {
        // Miss path, same as uretprobe__ssl_write above.
        if (ebpf_events_is_trusted_pid())
            goto out;
        if (!ebpf_events_is_tracked_tgid())
            goto out;
        tls_adopt_conn(&key);
        conn = bpf_map_lookup_elem(&tls_conns, &key);
        if (!conn)
            goto out;
    }

    seq = __sync_fetch_and_add(&conn->read_seq, 1);
    tls_emit_call(conn->conn_id, state->ssl_read.buf, (u32)ret,
                  EBPF_TLS_DIR_READ, seq);

out:
    ebpf_events_state__del(EBPF_EVENTS_STATE_SSL_READ);
    preempt_enable();
    return 0;
}
