// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2026 Elastic NV */

/* Exercise the backend without opening a queue or loading BPF programs. */
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <bpf/libbpf.h>

/* Keep the included backend's exported names separate from libquark. */
#define queue_ops_bpf test_queue_ops_bpf
#define bpf_queue_open test_bpf_queue_open
#define quark_get_bpf_probes test_quark_get_bpf_probes
#define quark_queue_trusted_pid_reset test_quark_queue_trusted_pid_reset
#define quark_queue_trusted_pid_add test_quark_queue_trusted_pid_add
#include "quark.h"
#include "quark-test.h"
#include "bpf_telemetry_retprobe.h"

static int test_num_possible_cpus(void);
static int test_map_lookup(const struct bpf_map *, const void *, size_t,
    void *, size_t, __u64);
static int test_retprobe_missed(const struct bpf_telemetry_retprobe *, uint64_t *);
static void test_log(int, int, const char *, int, const char *, ...);

#define libbpf_num_possible_cpus test_num_possible_cpus
#define bpf_map__lookup_elem test_map_lookup
#define bpf_telemetry_retprobe_missed test_retprobe_missed
#define qlog_func test_log
#include "bpf_queue.c"
#undef qlog_func
#undef bpf_telemetry_retprobe_missed
#undef bpf_map__lookup_elem
#undef libbpf_num_possible_cpus
#undef quark_queue_trusted_pid_add
#undef quark_queue_trusted_pid_reset
#undef quark_get_bpf_probes
#undef bpf_queue_open
#undef queue_ops_bpf

enum stats_failure { STATS_OK, STATS_CPUS, STATS_MAP, STATS_SECOND_PROBE };
static enum stats_failure stats_failure;
static unsigned int stats_epoch, map_calls, missed_calls, warnings;
static char fake_map, fake_probes[2];

static int
test_num_possible_cpus(void)
{
	return (stats_failure == STATS_CPUS ? -EINVAL : 3);
}

static int
test_map_lookup(const struct bpf_map *map, const void *key, size_t key_size,
    void *value, size_t value_size, __u64 flags)
{
	struct ebpf_event_stats *cpus = value;
	unsigned int i;
	static const struct ebpf_event_stats values[3] = {
		{ .lost = (1ULL << 32) + 3, .sent = 101,
		  .bpf_state_lost = (2ULL << 32) + 5,
		  .bpf_metadata_lost = (3ULL << 32) + 7 },
		{ .lost = (4ULL << 32) + 11, .sent = 103,
		  .bpf_state_lost = (5ULL << 32) + 13,
		  .bpf_metadata_lost = (6ULL << 32) + 17 },
		{ .lost = (7ULL << 32) + 19, .sent = 107,
		  .bpf_state_lost = (8ULL << 32) + 23,
		  .bpf_metadata_lost = (9ULL << 32) + 29 },
	};

	map_calls++;
	assert(map == (struct bpf_map *)&fake_map);
	assert(key_size == sizeof(u32) && *(const u32 *)key == 0);
	assert(value_size == sizeof(values) && flags == 0);
	if (stats_failure == STATS_MAP)
		return (errno = EIO, -EIO);
	memcpy(cpus, values, sizeof(values));
	for (i = 0; i < nitems(values); i++) {
		cpus[i].lost += stats_epoch;
		cpus[i].bpf_state_lost += stats_epoch;
		cpus[i].bpf_metadata_lost += stats_epoch;
	}
	return (0);
}

static int
test_retprobe_missed(const struct bpf_telemetry_retprobe *probe, uint64_t *missed)
{
	unsigned int index = missed_calls++;

	assert(index < nitems(fake_probes));
	assert(probe == (const struct bpf_telemetry_retprobe *)&fake_probes[index]);
	if (stats_failure == STATS_SECOND_PROBE && index == 1)
		return (errno = EIO, -1);
	*missed = (index == 0 ? (10ULL << 32) + 31 : (11ULL << 32) + 37) +
	    stats_epoch;
	return (0);
}

static void
test_log(int level, int error, const char *function, int line,
    const char *format, ...)
{
	warnings++;
}

static void
test_bpf_wire(void)
{
	static const u32 validity[] = {
		0, QUARK_BPF_VALID_ATTR, QUARK_BPF_VALID_OBJECT,
		QUARK_BPF_VALID_ATTR | QUARK_BPF_VALID_OBJECT
	};
	struct ebpf_process_bpf_event wire;
	struct quark_queue qq;
	struct quark_bpf expected;
	struct raw_event *raw;
	const struct quark_event *event;
	size_t i;

	for (i = 0; i < nitems(validity); i++) {
		quark_queue_init_bare(&qq);
		bzero(&wire, sizeof(wire));
		wire.hdr.type = EBPF_EVENT_PROCESS_BPF;
		wire.hdr.ts = (1ULL << 40) + 101;
		wire.pids.start_time_ns = (2ULL << 40) + 103;
		wire.pids.tgid = 107;
		wire.pids.tid = 109;
		wire.ret = -(3LL << 40) - 113;
		wire.cmd = BPF_PROG_LOAD;
		wire.kind = QUARK_BPF_PROG;
		wire.id = 127;
		wire.valid = validity[i];
		wire.type = 131;
		wire.attach_type = 137;
		wire.flags = 139;
		wire.insn_cnt = 149;
		memcpy(wire.name, "0123456789ABCDEF", sizeof(wire.name));

		bzero(&expected, sizeof(expected));
		expected.start_time_ns = (2ULL << 40) + 103;
		expected.tgid = 107;
		expected.tid = 109;
		expected.ret = -(3LL << 40) - 113;
		expected.cmd = BPF_PROG_LOAD;
		expected.kind = QUARK_BPF_PROG;
		expected.id = 127;
		expected.valid = validity[i];
		expected.type = 131;
		expected.attach_type = 137;
		expected.flags = 139;
		expected.insn_cnt = 149;
		/* All 16 input bytes are nonzero; the public name must terminate. */
		memcpy(expected.name, "0123456789ABCDE", sizeof(expected.name));

		assert(bpf_ringbuf_cb(&qq, &wire, sizeof(wire)) == 0);
		assert(qq.length == 1);
		raw = RB_ROOT(&qq.raw_event_by_time);
		assert(raw != NULL && raw->type == RAW_BPF);
		assert(raw->pid == 107 && raw->time == (1ULL << 40) + 101);
		assert(!memcmp(&raw->bpf.quark_bpf, &expected, sizeof(expected)));
		event = quark_queue_get_event(&qq);
		assert(event != NULL && event->events == QUARK_EV_BPF);
		assert(event->process == NULL && event->time == (1ULL << 40) + 101);
		assert(!memcmp(&event->bpf, &expected, sizeof(expected)));
		assert(quark_queue_get_event(&qq) == NULL);
		quark_queue_close(&qq);
	}
}

static void
test_stats_totals(const struct quark_queue_stats *stats, unsigned int epoch)
{
	assert(stats->lost == (12ULL << 32) + 33 + 3 * epoch);
	assert(stats->bpf_state_lost == (15ULL << 32) + 41 + 3 * epoch);
	assert(stats->bpf_metadata_lost == (18ULL << 32) + 53 + 3 * epoch);
	/* Backend refreshes must not alter the queue's own counters. */
	assert(stats->insertions == 151 && stats->removals == 157);
}

static void
test_stats_refresh(struct quark_queue *qq, struct quark_queue_stats *stats,
    enum stats_failure failure)
{
	stats_failure = failure;
	map_calls = missed_calls = warnings = 0;
	quark_queue_get_stats(qq, stats);
	assert(map_calls == (failure == STATS_CPUS ? 0 : 1));
	assert(warnings == (failure == STATS_OK ? 0 : 1));
}

static void
test_bpf_stats(void)
{
	struct bpf_probes probes = {0};
	struct bpf_queue backend = {0};
	struct quark_queue qq;
	struct quark_queue_stats stats;
	u64 previous_missed;
	unsigned int failure, previous_epoch;

	bzero(&qq, sizeof(qq));
	probes.maps.ringbuf_stats = (struct bpf_map *)&fake_map;
	backend.probes = &probes;
	backend.bpf_boundary_count = 2;
	backend.bpf_return[0] = (struct bpf_telemetry_retprobe *)&fake_probes[0];
	backend.bpf_return[1] = (struct bpf_telemetry_retprobe *)&fake_probes[1];
	qq.queue_be = &backend;
	qq.queue_ops = &test_queue_ops_bpf;
	qq.stats.insertions = 151;
	qq.stats.removals = 157;
	stats_epoch = 0;
	for (failure = STATS_CPUS; failure <= STATS_SECOND_PROBE; failure++) {
		test_stats_refresh(&qq, &stats, STATS_OK);
		test_stats_totals(&stats, stats_epoch);
		assert(missed_calls == 2 && stats.bpf_retprobe_stats_valid);
		assert(stats.bpf_retprobe_missed == (21ULL << 32) + 68 + 2 * stats_epoch);
		previous_missed = stats.bpf_retprobe_missed;
		previous_epoch = stats_epoch++;

		test_stats_refresh(&qq, &stats, failure);
		assert(!stats.bpf_retprobe_stats_valid);
		assert(stats.bpf_retprobe_missed == previous_missed);
		assert(missed_calls == (failure == STATS_SECOND_PROBE ? 2 : 0));
		test_stats_totals(&stats,
		    failure == STATS_SECOND_PROBE ? stats_epoch : previous_epoch);

		stats_epoch++;
		test_stats_refresh(&qq, &stats, STATS_OK);
		test_stats_totals(&stats, stats_epoch);
		assert(missed_calls == 2 && stats.bpf_retprobe_stats_valid);
		assert(stats.bpf_retprobe_missed == (21ULL << 32) + 68 + 2 * stats_epoch);
	}
	backend.bpf_boundary_count = 0;
	test_stats_refresh(&qq, &stats, STATS_OK);
	test_stats_totals(&stats, stats_epoch);
	assert(missed_calls == 0 && !stats.bpf_retprobe_stats_valid);
	assert(stats.bpf_retprobe_missed == 0);
}

int
t_bpf_queue(const struct test *t, struct quark_queue_attr *qa)
{
	test_bpf_wire();
	test_bpf_stats();
	return (0);
}
