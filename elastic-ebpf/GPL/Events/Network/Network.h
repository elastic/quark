// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2021 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

#ifndef EBPF_EVENTPROBE_NETWORK_H
#define EBPF_EVENTPROBE_NETWORK_H

// linux/socket.h
#define AF_INET 2
#define AF_INET6 10

static int ebpf_sock_info__fill(struct ebpf_net_info *net, struct sock *sk)
{
    int err = 0;

    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    switch (family) {
    case AF_INET:
        err = BPF_CORE_READ_INTO(&net->saddr, sk, __sk_common.skc_rcv_saddr);
        if (err) {
            bpf_printk("AF_INET: error while reading saddr");
            goto out;
        }

        err = BPF_CORE_READ_INTO(&net->daddr, sk, __sk_common.skc_daddr);
        if (err) {
            bpf_printk("AF_INET: error while reading daddr");
            goto out;
        }

        net->family = EBPF_NETWORK_EVENT_AF_INET;
        break;
    case AF_INET6:
        err = BPF_CORE_READ_INTO(&net->saddr6, sk, __sk_common.skc_v6_rcv_saddr);
        if (err) {
            bpf_printk("AF_INET6: error while reading saddr");
            goto out;
        }

        err = BPF_CORE_READ_INTO(&net->daddr6, sk, __sk_common.skc_v6_daddr);
        if (err) {
            bpf_printk("AF_INET6: error while reading daddr");
            goto out;
        }

        net->family = EBPF_NETWORK_EVENT_AF_INET6;
        break;
    default:
        err = -1;
        goto out;
    }

    struct inet_sock *inet = (struct inet_sock *)sk;
    u16 sport              = BPF_CORE_READ(inet, inet_sport);
    net->sport             = bpf_ntohs(sport);
    u16 dport              = BPF_CORE_READ(sk, __sk_common.skc_dport);
    net->dport             = bpf_ntohs(dport);
    net->netns             = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);

    u16 proto = BPF_CORE_READ(sk, sk_protocol);
    switch (proto) {
    case IPPROTO_TCP:
        net->transport = EBPF_NETWORK_EVENT_TRANSPORT_TCP;
        break;
    default:
        err = -1;
        goto out;
    }

out:
    return err;
}

static int ebpf_network_event__fill(struct ebpf_net_event *evt, struct sock *sk)
{
    int err = 0;

    if (ebpf_sock_info__fill(&evt->net, sk)) {
        err = -1;
        goto out;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ebpf_pid_info__fill(&evt->pids, task);
    bpf_get_current_comm(evt->comm, TASK_COMM_LEN);
    evt->hdr.ts      = bpf_ktime_get_ns();
    evt->hdr.ts_boot = bpf_ktime_get_boot_ns_helper();

out:
    return err;
}

static int ebpf_network_event__fill_from_sock_ops(struct ebpf_net_event *evt, struct bpf_sock_ops *ops)
{
	int			 err  = 0;
	struct task_struct	*task = (struct task_struct *)bpf_get_current_task();

	switch (ops->family) {
	case AF_INET:
		/* err = bpf_probe_read_kernel(evt->net.saddr, 4, &ops->local_ip4); */
		/* bpf_printk("err = %d\n", err); */
		/* if (err != 0) */
		/* 	goto out; */
		/* err = bpf_probe_read_kernel(evt->net.daddr, 4, &ops->remote_ip4); */
		/* if (err != 0) */
		/* 	goto out; */
		evt->net.saddr_v = ops->local_ip4;
		evt->net.daddr_v = ops->remote_ip4;
		    
		evt->net.family = EBPF_NETWORK_EVENT_AF_INET;
		break;
	case AF_INET6:
		err = bpf_probe_read_kernel(evt->net.saddr6, 16, &ops->local_ip6);
		if (err != 0)
			goto out;
		err = bpf_probe_read_kernel(evt->net.daddr6, 16, &ops->remote_ip6);
		if (err != 0)
			goto out;
		evt->net.family = EBPF_NETWORK_EVENT_AF_INET6;
		break;
	default:
		err = -1;
		goto out;
	}
	evt->net.netns = 0;		/* TODO */
	evt->net.sport = ops->local_port;
	evt->net.dport = bpf_ntohl(ops->remote_port);
	evt->net.state = ops->state;
	evt->net.transport = EBPF_NETWORK_EVENT_TRANSPORT_TCP;
	ebpf_pid_info__fill(&evt->pids, task);
//	bpf_get_current_comm(evt->comm, TASK_COMM_LEN);
	evt->hdr.ts      = bpf_ktime_get_ns();
	evt->hdr.ts_boot = bpf_ktime_get_boot_ns_helper();

out:
	if (err != 0) {
		bpf_printk("FAILED\n");
	} else {
		bpf_printk("evt %d %d %d %d --- %d %d %d %d\n",
		    evt->net.saddr[0], evt->net.saddr[1],
		    evt->net.saddr[2], evt->net.saddr[3],
		    evt->net.daddr[0], evt->net.daddr[1],
		    evt->net.daddr[2], evt->net.daddr[3]);
		bpf_printk("ops 0x%x:%d --- 0x%x:%d\n",
		    ops->local_ip4, ops->local_port, ops->remote_ip4, bpf_ntohl(ops->remote_port));

	}

	return err;
}

#endif // EBPF_EVENTPROBE_NETWORK_H
