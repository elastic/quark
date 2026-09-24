// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2021 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "Helpers.h"
#include "Network.h"
#include "State.h"
#include "Varlen.h"

DECL_FUNC_RET(inet_csk_accept);

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, struct sock *);
    __type(value, u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} sk_to_tgid SEC(".maps");

struct dns_ctx {
    /*
     * which nest index we are, only meaningful on the first one,
     * saves having a map just to store an int
     */
    u32 nest;
    u64 scratch64;
    struct ebpf_dns_event event; /* must be last */
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(struct dns_ctx) + MAX_DNS_PACKET);
    __uint(max_entries, 3);
} dns_ctx_map SEC(".maps");

/*
 * Set from userspace before load.
 */
const volatile int dns_enabled      = 0;
const volatile int udp_flow_enabled = 0;

/*
 * UDP flow accounting lives in two identical hash maps. Programs update the
 * one selected by the low bit of udp_flow_gen, userspace bumps the generation
 * every aggregation period, waits for in-flight programs to finish and then
 * drains the map nobody writes to anymore. That is what makes the drain
 * lossless: a lookup, copy and delete of a live entry would drop whatever
 * a program adds in between.
 *
 * max_entries is set from userspace, to the real size when flows are enabled,
 * '1' otherwise since the programs still reference the maps.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, struct ebpf_udp_flow_key);
    __type(value, struct ebpf_udp_flow_val);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} udp_flows0 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1);
    __type(key, struct ebpf_udp_flow_key);
    __type(value, struct ebpf_udp_flow_val);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} udp_flows1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} udp_flow_gen SEC(".maps");

struct dns_ctx *
get_dns_ctx(void)
{
    struct dns_ctx *ctx, *zero_ctx;

    zero_ctx = bpf_map_lookup_elem(&dns_ctx_map, &(int){0});
    if (zero_ctx == NULL)
        return (NULL);
    ctx = bpf_map_lookup_elem(&dns_ctx_map, &zero_ctx->nest);
    if (ctx == NULL)
        return (NULL);
    zero_ctx->nest++;

    return (ctx);
}

void
put_dns_ctx(void)
{
	struct dns_ctx *zero_ctx;

	zero_ctx = bpf_map_lookup_elem(&dns_ctx_map, &(int){0});
	if (zero_ctx == NULL)
		return;
	zero_ctx->nest--;
}

static int inet_csk_accept__exit(struct sock *sk)
{
    if (!sk)
        goto out;
    if (ebpf_events_is_trusted_pid())
        goto out;

    struct ebpf_net_event *event = get_zeroed_event_buffer(sizeof(*event));
    if (!event)
        goto out;

    if (ebpf_network_event__fill(event, sk))
        goto out;

    event->hdr.type = EBPF_EVENT_NETWORK_CONNECTION_ACCEPTED;
    if (ebpf_ringbuf_write(&ringbuf, event, sizeof(*event), 0) == 0) {
        // Record this socket so we can emit a close
        u32 tgid = event->pids.tgid;
        (void)bpf_map_update_elem(&sk_to_tgid, &sk, &tgid, BPF_ANY);
    }

out:
    return 0;
}

SEC("fexit/inet_csk_accept")
int BPF_PROG(fexit__inet_csk_accept)
{
    struct sock *ret = FUNC_RET_READ(___type(ret), inet_csk_accept);
    int r;

    preempt_disable();
    r = inet_csk_accept__exit(ret);
    preempt_enable();

    return r;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(kretprobe__inet_csk_accept, struct sock *ret)
{
    int r;

    preempt_disable();
    r = inet_csk_accept__exit(ret);
    preempt_enable();

    return r;
}

static int tcp_connect(struct sock *sk, int ret)
{
    if (ret)
        goto out;
    if (ebpf_events_is_trusted_pid())
        goto out;

    struct ebpf_net_event *event = get_zeroed_event_buffer(sizeof(*event));
    if (!event)
        goto out;

    if (ebpf_network_event__fill(event, sk))
        goto out;

    event->hdr.type = EBPF_EVENT_NETWORK_CONNECTION_ATTEMPTED;
    if (ebpf_ringbuf_write(&ringbuf, event, sizeof(*event), 0) == 0) {
        // Record this socket so we can emit a close
        u32 tgid = event->pids.tgid;
        (void)bpf_map_update_elem(&sk_to_tgid, &sk, &tgid, BPF_ANY);
    }

out:
    return 0;
}

SEC("fexit/tcp_v4_connect")
int BPF_PROG(fexit__tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
    int r;

    preempt_disable();
    r = tcp_connect(sk, ret);
    preempt_enable();

    return r;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe__tcp_v4_connect, struct sock *sk)
{
    struct ebpf_events_state state = {};
    state.tcp_v4_connect.sk        = sk;

    preempt_disable();
    if (ebpf_events_is_trusted_pid())
        goto out;
    ebpf_events_state__set(EBPF_EVENTS_STATE_TCP_V4_CONNECT, &state);

out:
    preempt_enable();
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(kretprobe__tcp_v4_connect, int ret)
{
    struct ebpf_events_state *state;
    int r;

    preempt_disable();
    r = 0;
    state = ebpf_events_state__get(EBPF_EVENTS_STATE_TCP_V4_CONNECT);
    if (!state)
        goto out;

    r = tcp_connect(state->tcp_v4_connect.sk, ret);

out:
    preempt_enable();
    return r;
}

SEC("fexit/tcp_v6_connect")
int BPF_PROG(fexit__tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
    int r;

    preempt_disable();
    r = tcp_connect(sk, ret);
    preempt_enable();

    return r;
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(kprobe__tcp_v6_connect, struct sock *sk)
{
    struct ebpf_events_state state = {};
    state.tcp_v6_connect.sk        = sk;

    preempt_disable();
    if (ebpf_events_is_trusted_pid())
        goto out;
    ebpf_events_state__set(EBPF_EVENTS_STATE_TCP_V6_CONNECT, &state);

out:
    preempt_enable();
    return 0;
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(kretprobe__tcp_v6_connect, int ret)
{
    struct ebpf_events_state *state;
    int r;

    preempt_disable();
    r = 0;
    state = ebpf_events_state__get(EBPF_EVENTS_STATE_TCP_V6_CONNECT);
    if (!state)
        goto out;

    r = tcp_connect(state->tcp_v6_connect.sk, ret);

out:
    preempt_enable();

    return r;
}

static int tcp_close__enter(struct sock *sk)
{
    if (ebpf_events_is_trusted_pid())
        goto out;

    struct tcp_sock *tp = (struct tcp_sock *)sk;
    u64 bytes_sent      = BPF_CORE_READ(tp, bytes_sent);
    u64 bytes_received  = BPF_CORE_READ(tp, bytes_received);

    // Only process sockets we added, but since storage is limited, fall back to
    // looking at bytes if we're full
    if (bpf_map_delete_elem(&sk_to_tgid, &sk) != 0 && bytes_sent == 0 && bytes_received == 0)
        goto out;

    struct ebpf_net_event *event = get_zeroed_event_buffer(sizeof(*event));
    if (!event)
        goto out;

    if (ebpf_network_event__fill(event, sk))
        goto out;

    event->net.tcp.close.bytes_sent     = bytes_sent;
    event->net.tcp.close.bytes_received = bytes_received;

    event->hdr.type = EBPF_EVENT_NETWORK_CONNECTION_CLOSED;
    ebpf_ringbuf_write(&ringbuf, event, sizeof(*event), 0);

out:
    return 0;
}

SEC("fentry/tcp_close")
int BPF_PROG(fentry__tcp_close, struct sock *sk, long timeout)
{
    int r;

    preempt_disable();
    r = tcp_close__enter(sk);
    preempt_enable();

    return r;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(kprobe__tcp_close, struct sock *sk, long timeout)
{
    int r;

    preempt_disable();
    r = tcp_close__enter(sk);
    preempt_enable();

    return r;
}

/* linux/if_ether.h */
#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD

/* linux/ipv6.h, the extension headers that may precede UDP.
 * IPv6 extension headers are optional packet headers that a
 * sender can add between the fixed IPv6 base header (40 bytes)
 * and the upper-layer header (e.g. TCP, UDP).
 */
#define NEXTHDR_HOP     0
#define NEXTHDR_UDP     17
#define NEXTHDR_ROUTING 43
#define NEXTHDR_DEST    60

/*
 * RFC 8200 recommends Hop-by-Hop, Destination Options, Routing and a second
 * Destination Options, in that order, each at most once.
 */
#define MAX_IPV6_EXTHDRS 4

/*
 * Walk the IPv6 extension header chain and return the offset of the UDP
 * header or -1 if the datagram isn't UDP / has a header we don't follow.
 *
 * Only Hop-by-Hop, Routing and Destination Options are followed. Real
 * fragments are reassembled before ingress, which removes the Fragment
 * header, and egress runs before fragmentation. An atomic fragment
 * (deprecated in RFC 8021, Linux no longer sends them) keeps its
 * Fragment header through delivery and is not captured.
 */
static int skb_ipv6_udp_offset(struct __sk_buff *skb)
{
    struct {
        u8 nexthdr;
        u8 hdrlen;
    } ext;
    u8 next;
    u32 off;
    int i;

    if (bpf_skb_load_bytes(skb, offsetof(struct ipv6hdr, nexthdr), &next,
        sizeof(next)))
        return (-1);
    off = sizeof(struct ipv6hdr);

#pragma unroll
    for (i = 0; i < MAX_IPV6_EXTHDRS; i++) {
        if (next == NEXTHDR_UDP)
            return (off);
        if (next != NEXTHDR_HOP && next != NEXTHDR_ROUTING &&
            next != NEXTHDR_DEST)
            return (-1);
        if (bpf_skb_load_bytes(skb, off, &ext, sizeof(ext)))
            return (-1);
        next = ext.nexthdr;
        /* hdrlen is in 8 octet units, not counting the first 8 */
        off += ((u32)ext.hdrlen + 1) << 3;
    }

    return (next == NEXTHDR_UDP ? (int)off : -1);
}

/*
 * What the flow and DNS paths need out of the datagram headers.
 */
struct udp_hdrs {
    struct udphdr udp;
    u8 saddr[16];
    u8 daddr[16];
    u32 l4off;
    u16 family; /* enum ebpf_net_info_af */
};

/*
 * Parse the IP and UDP headers of the datagram, if it is one.
 * Returns 0 and fills h, returns -1 if this isn't UDP.
 */
static int skb_parse_udp(struct __sk_buff *skb, struct udp_hdrs *h)
{
    int l4off;

    /*
     * IPv4 fills only the first four bytes of each address and verifiers
     * before 6.4 reject reading stack that was never written, so the flow
     * key copy below needs the whole thing initialized.
     */
    __builtin_memset(h, 0, sizeof(*h));

    if (skb->protocol == bpf_htons(ETH_P_IP)) {
        struct iphdr ip;

        if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip)))
            return (-1);
        if (ip.protocol != IPPROTO_UDP)
            return (-1);
        __builtin_memcpy(h->saddr, &ip.saddr, 4);
        __builtin_memcpy(h->daddr, &ip.daddr, 4);
        h->family = EBPF_NETWORK_EVENT_AF_INET;
        l4off = ip.ihl << 2;
    } else if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
        if ((l4off = skb_ipv6_udp_offset(skb)) < 0)
            return (-1);
        if (bpf_skb_load_bytes(skb, offsetof(struct ipv6hdr, saddr),
            h->saddr, sizeof(h->saddr)))
            return (-1);
        if (bpf_skb_load_bytes(skb, offsetof(struct ipv6hdr, daddr),
            h->daddr, sizeof(h->daddr)))
            return (-1);
        h->family = EBPF_NETWORK_EVENT_AF_INET6;
    } else
        return (-1);

    if (bpf_skb_load_bytes(skb, l4off, &h->udp, sizeof(h->udp)))
        return (-1);
    h->l4off = l4off;

    return (0);
}

/*
 * Add one datagram to its flow in map. Counters are added atomically since
 * the same flow can be worked on by several cpus at once, unconnected sockets
 * in particular are shared across threads. The timestamps are plain stores:
 * first_ns is written once by whoever inserts, last_ns is sampled only after
 * a lookup returned a live entry, so it never predates first_ns. Concurrent
 * writers can still leave it a few ns short of the true last datagram, which
 * costs nothing.
 */
static __always_inline void udp_flow_account1(void *map,
    struct ebpf_udp_flow_key *key, u64 bytes, int direction, u32 tgid)
{
    struct ebpf_udp_flow_val *v, nv;

    v = bpf_map_lookup_elem(map, key);
    if (v == NULL) {
        __builtin_memset(&nv, 0, sizeof(nv));
        nv.first_ns = bpf_ktime_get_boot_ns();
        nv.last_ns  = nv.first_ns;
        nv.tgid     = tgid;
        if (direction == EBPF_NETWORK_DIR_EGRESS) {
            nv.packets_sent = 1;
            nv.bytes_sent   = bytes;
        } else {
            nv.packets_received = 1;
            nv.bytes_received   = bytes;
        }
        if (bpf_map_update_elem(map, key, &nv, BPF_NOEXIST) == 0)
            return;
        /*
         * Another cpu inserted first, fall through to atomic adds.
	 * If the map is full, the datagram is lost.
         */
        v = bpf_map_lookup_elem(map, key);
        if (v == NULL)
            return;
    }

    if (direction == EBPF_NETWORK_DIR_EGRESS) {
        __sync_fetch_and_add(&v->packets_sent, 1);
        __sync_fetch_and_add(&v->bytes_sent, bytes);
    } else {
        __sync_fetch_and_add(&v->packets_received, 1);
        __sync_fetch_and_add(&v->bytes_received, bytes);
    }
    v->last_ns = bpf_ktime_get_boot_ns();
    /*
     * The descriptor may have moved to another process since the flow
     * started, keep the last owner we know of.
     */
    if (tgid != 0)
        v->tgid = tgid;
}

/*
 * Account the datagram to the (socket, 5-tuple) flow it belongs to, in the
 * map of the current generation. The key is always local first then remote
 * so both directions land on the same entry.
 */
static void udp_flow_account(struct __sk_buff *skb, struct udp_hdrs *h,
    int direction, u32 tgid)
{
    struct ebpf_udp_flow_key key;
    u32 *gen, hlen;
    u64 bytes;

    gen = bpf_map_lookup_elem(&udp_flow_gen, &(u32){0});
    if (gen == NULL)
        return;

    __builtin_memset(&key, 0, sizeof(key));
    key.cookie = bpf_get_socket_cookie(skb);
    key.family = h->family;
    if (direction == EBPF_NETWORK_DIR_EGRESS) {
        __builtin_memcpy(key.laddr, h->saddr, sizeof(key.laddr));
        __builtin_memcpy(key.raddr, h->daddr, sizeof(key.raddr));
        key.lport = h->udp.source;
        key.rport = h->udp.dest;
    } else {
        __builtin_memcpy(key.laddr, h->daddr, sizeof(key.laddr));
        __builtin_memcpy(key.raddr, h->saddr, sizeof(key.raddr));
        key.lport = h->udp.dest;
        key.rport = h->udp.source;
    }

    /*
     * skb->len starts at the network header in both directions, payload is
     * what's left after the IP and UDP headers. Matches what tcp_sock's
     * bytes_sent/bytes_received count for TCP.
     */
    hlen = h->l4off + sizeof(struct udphdr);
    bytes = skb->len > hlen ? skb->len - hlen : 0;

    if (*gen & 1)
        udp_flow_account1(&udp_flows1, &key, bytes, direction, tgid);
    else
        udp_flow_account1(&udp_flows0, &key, bytes, direction, tgid);
}

/*
 * See cgroub_skb/egress, pretty please.
 */
static int skb_in_or_egress(struct __sk_buff *skb, int direction,
    struct dns_ctx *ctx)
{
    struct udp_hdrs h;
    struct bpf_sock *sk;
    u32 *tgid, cap_len;
    int is_dns;
    struct ebpf_dns_event *event;

    if (skb->family != AF_INET && skb->family != AF_INET6)
        goto ignore;
    if ((sk = skb->sk) == NULL)
        goto ignore;
    if ((sk = bpf_sk_fullsock(sk)) == NULL)
        goto ignore;
    if (sk->protocol != IPPROTO_UDP)
        goto ignore;

    if (skb_parse_udp(skb, &h))
        goto ignore;

    is_dns = dns_enabled &&
        (bpf_ntohs(h.udp.dest) == 53 || bpf_ntohs(h.udp.source) == 53);
    if (!udp_flow_enabled && !is_dns)
        goto ignore;

    /*
     * Needed for kernels prior to cd17d38f8b28f808c368121041c0a4fa91757e0d
     * bpf: Permits pointers on stack for helper calls
     */
    ctx->scratch64 = (u64)sk;
    tgid = bpf_map_lookup_elem(&sk_to_tgid, &ctx->scratch64);

    /*
     * Flows are accounted even when we don't know the owner: a socket we
     * never saw created or used (tgid:0) is still traffic that's
     * worth reporting as an event.
     */
    if (udp_flow_enabled)
        udp_flow_account(skb, &h, direction, tgid != NULL ? *tgid : 0);

    if (!is_dns || tgid == NULL)
	/*
	 * A DNS event is a captured packet and a tgid, thus without a
	 * tgid the event is unattributable as userspace does the
	 * attribution by looking it up in the process cache.
	 */
        goto ignore;

    cap_len = skb->len;
    /*
     * verifier will complain, even with a skb->len
     * check at the beginning.
     */
    if (cap_len > MAX_DNS_PACKET)
        cap_len = MAX_DNS_PACKET;

    /*
     * The minimum below is sized for IPv4, an IPv6 datagram needs 20 more
     * bytes before it can hold a DNS header. Kept as its own constant
     * comparison, see the verifier notes that follow.
     */
    if (skb->protocol == bpf_htons(ETH_P_IPV6) &&
        cap_len < (sizeof(struct ipv6hdr) + sizeof(struct udphdr) + 12))
        goto ignore;

    /*
     * Yes this code is weird, but it convinces old verifiers (5.10), don't
     * blame me, be sure to test 5.10 if you change it.  The minimal packet
     * should be iphlen + udphlen + 12(dns header size). Old verifiers
     * (5.10) are very sensitive here and a non constant right expression
     * (since iphlen is not constant due to options) fails. Do what we can
     * and filter the remaining bad packets in userspace, same applies to
     * ipv6 extension headers. Also be careful with `if cap_len > 0`, as
     * clang will compile it to a JNZ, which doesn't adjust umin, causing
     * the bpf_skb_load_bytes() down below to think cap_len can be zero.
     */
    if (cap_len >= (sizeof(struct iphdr) + sizeof(struct udphdr) + 12)) {
        event = &ctx->event;

        event->hdr.type    = EBPF_EVENT_NETWORK_DNS_PKT;
        event->hdr.ts      = bpf_ktime_get_boot_ns();
        event->tgid        = *tgid;
        event->cap_len     = cap_len;
        event->orig_len    = skb->len;
        event->direction   = direction;

        /*
         * 5.10 kernels on clang-20+, for $REASONS, will result in code here
         * that loses track of cap_len, so cap_len will be unbound (R4 in
         * bpf_skb_load_bytes()).
         */
        barrier_var(cap_len);
        if (cap_len > MAX_DNS_PACKET ||
            cap_len < (__u32)(sizeof(struct iphdr) + sizeof(struct udphdr) + 12))
                goto ignore;
        if (bpf_skb_load_bytes(skb, 0, event->packet, cap_len))
            goto ignore;

        ebpf_ringbuf_write(&ringbuf, event, sizeof(*event) + cap_len, 0);
    }

ignore:
    return (1);
}

/*
 * This probe can and will trigger from softirq as well as process context!
 * Which means it actually interrupts and runs interleaved with whatever probe
 * the cpu happened to be running. This also means egress/ingress can nest onto
 * *anything*, including another egress/ingress, or a fork, exec or
 * *anything*. Therefore you *MUST* not use any of the per cpu data structures
 * that the others probes do *DON'T* use get_event_buffer(). Use get_dns_ctx()
 * and put_dns_ctx() to properly nest it.
 */
SEC("cgroup_skb/egress")
int skb_egress(struct __sk_buff *skb)
{
    struct dns_ctx *ctx;

    preempt_disable();
    if ((ctx = get_dns_ctx()) != NULL) {
        skb_in_or_egress(skb, EBPF_NETWORK_DIR_EGRESS, ctx);
        put_dns_ctx();
    }
    preempt_enable();

    return 1;
}

/*
 * See cgroub_skb/egress, pretty please.
 */
SEC("cgroup_skb/ingress")
int skb_ingress(struct __sk_buff *skb)
{
    struct dns_ctx *ctx;

    preempt_disable();
    if ((ctx = get_dns_ctx()) != NULL) {
        skb_in_or_egress(skb, EBPF_NETWORK_DIR_INGRESS, ctx);
        put_dns_ctx();
    }
    preempt_enable();

    return 1;
}

static int sk_maybe_save_tgid(struct bpf_sock *sk)
{
    u32 tgid;
    struct dns_ctx *ctx;

    if (sk->protocol != IPPROTO_UDP)
        return (1);

    if (ebpf_events_is_trusted_pid())
        return (1);

    tgid = bpf_get_current_pid_tgid() >> 32;

    /*
     * Needed for kernels prior to f79efcb0075a20633cbf9b47759f2c0d538f78d8
     * bpf: Permits pointers on stack for helper calls
     */
    ctx = get_dns_ctx();
    if (ctx == NULL)
        return (1);
    ctx->scratch64 = (u64)sk;
    bpf_map_update_elem(&sk_to_tgid, &ctx->scratch64, &tgid, BPF_ANY);
    put_dns_ctx();

    return (1);
}

/*
 * We save tgid again in send/recv/connect as the file descriptor might have
 * been passed to another process.
 */
static int sockaddr_hook(struct bpf_sock_addr *sa)
{
    int r;

    preempt_disable();
    r = sk_maybe_save_tgid(sa->sk);
    preempt_enable();

    return r;
}

SEC("cgroup/sendmsg4")
int sendmsg4(struct bpf_sock_addr *sa)
{
    return sockaddr_hook(sa);
}

SEC("cgroup/recvmsg4")
int recvmsg4(struct bpf_sock_addr *sa)
{
    return sockaddr_hook(sa);
}

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *sa)
{
    return sockaddr_hook(sa);
}

SEC("cgroup/sendmsg6")
int sendmsg6(struct bpf_sock_addr *sa)
{
    return sockaddr_hook(sa);
}

SEC("cgroup/recvmsg6")
int recvmsg6(struct bpf_sock_addr *sa)
{
    return sockaddr_hook(sa);
}

SEC("cgroup/connect6")
int connect6(struct bpf_sock_addr *sa)
{
    return sockaddr_hook(sa);
}

SEC("cgroup/sock_create")
int sock_create(struct bpf_sock *sk)
{
    int r;

    preempt_disable();
    r = sk_maybe_save_tgid(sk);
    preempt_enable();

    return r;
}

SEC("cgroup/sock_release")
int sock_release(struct bpf_sock *sk)
{
    struct dns_ctx *ctx;

    preempt_disable();
    if (sk->protocol != IPPROTO_UDP)
        goto out;

    /*
     * Needed for kernels prior to f79efcb0075a20633cbf9b47759f2c0d538f78d8
     * bpf: Permits pointers on stack for helper calls
     */
    ctx = get_dns_ctx();
    if (ctx == NULL)
        goto out;
    ctx->scratch64 = (u64)sk;
    bpf_map_delete_elem(&sk_to_tgid, &ctx->scratch64);
    put_dns_ctx();

out:
    preempt_enable();

    return (1);
}
