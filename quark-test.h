/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2026 Elastic NV */

#ifndef QUARK_TEST_H
#define QUARK_TEST_H

struct test;
struct quark_queue_attr;

int t_bpf_call_stack(const struct test *, struct quark_queue_attr *);
int t_bpf_telemetry(const struct test *, struct quark_queue_attr *);
int t_bpf_telemetry_retprobe(const struct test *, struct quark_queue_attr *);

#endif
