// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Elastic NV

//go:build linux && (amd64 || arm64)

package quark

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStatsConversion(t *testing.T) {
	queue := newTestQueue()
	defer queue.Close()
	require.Equal(t, Stats{}, queue.Stats())

	// The bare backend leaves these C counters unchanged during refresh.
	cStats := &queue.quarkQueue.stats
	cStats.insertions = 1<<32 + 3
	cStats.removals = 2<<32 + 5
	cStats.aggregations = 3<<32 + 7
	cStats.non_aggregations = 4<<32 + 11
	cStats.lost = 5<<32 + 13
	cStats.garbage_collections = 6<<32 + 17
	cStats.bpf_state_lost = 7<<32 + 19
	cStats.bpf_metadata_lost = 8<<32 + 23
	cStats.bpf_retprobe_missed = 9<<32 + 29
	cStats.stalls = 10<<32 + 31
	cStats.bpf_retprobe_stats_valid = -1
	cStats.backend = 4 // QQ_EBPF
	want := Stats{
		Insertions:            1<<32 + 3,
		Removals:              2<<32 + 5,
		Aggregations:          3<<32 + 7,
		NonAggregations:       4<<32 + 11,
		Lost:                  5<<32 + 13,
		GarbageCollections:    6<<32 + 17,
		BPFStateLost:          7<<32 + 19,
		BPFMetadataLost:       8<<32 + 23,
		BPFRetprobeMissed:     9<<32 + 29,
		Stalls:                10<<32 + 31,
		BPFRetprobeStatsValid: true,
		Backend:               QQ_EBPF,
	}
	require.Equal(t, want, queue.Stats())

	// A later invalid refresh must not retain the previous true flag.
	cStats.bpf_retprobe_stats_valid = 0
	want.BPFRetprobeStatsValid = false
	require.Equal(t, want, queue.Stats())
}
