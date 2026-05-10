// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024 Elastic NV

package quark

import (
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestQuark(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("skipping: quark tests must be run as root")
	}

	t.Run("Snapshot", func(t *testing.T) {
		queue, err := OpenQueue(DefaultQueueAttr())
		require.NoError(t, err)

		defer queue.Close()

		require.NotEmpty(t, queue.Snapshot())
	})

	t.Run("Lookup", func(t *testing.T) {
		queue, err := OpenQueue(DefaultQueueAttr())
		require.NoError(t, err)

		defer queue.Close()

		fetchPid := uint32(1)
		pid1, ok := queue.Lookup(int(fetchPid))
		require.True(t, ok)

		require.Equal(t, fetchPid, pid1.Pid)
		require.NotEmpty(t, pid1.Comm)
		require.NotEmpty(t, pid1.Cwd)
	})

	t.Run("GetEvent", func(t *testing.T) {
		queue, err := OpenQueue(DefaultQueueAttr())
		require.NoError(t, err)

		defer queue.Close()

		_, _ = queue.GetEvent()
	})

	t.Run("StatsEbpf", func(t *testing.T) {
		attr := DefaultQueueAttr()
		attr.HoldTime = 100

		attr.Flags |= QQ_EBPF
		testStats(t, attr)
	})

	t.Run("StatsKprobe", func(t *testing.T) {
		attr := DefaultQueueAttr()
		attr.HoldTime = 100

		attr.Flags |= QQ_KPROBE
		testStats(t, attr)
	})
}

func testStats(t *testing.T, attr QueueAttr) {
	queue, err := OpenQueue(attr)
	require.NoError(t, err)

	defer queue.Close()

	// XXX assumes /bin/echo exists
	cmd := exec.Command("/bin/echo", "hi", "from", "echo")
	err = cmd.Run()
	require.NoError(t, err)

	qevs, err := drainFor(queue, 200*time.Millisecond)
	require.NoError(t, err)

	stats := queue.Stats()
	require.NotZero(t, stats.Insertions)
	require.NotZero(t, stats.Removals)
	require.NotZero(t, stats.Aggregations)
	// We can't be sure of NonAggregations
	require.Zero(t, stats.Lost)
	require.True(t, stats.Backend == QQ_EBPF || stats.Backend == QQ_KPROBE)

	require.NotEmpty(t, qevs)
}

func drainFor(qq *Queue, d time.Duration) ([]Event, error) {
	var allQevs []Event

	start := time.Now()

	for {
		qev, ok := qq.GetEvent()
		if ok {
			allQevs = append(allQevs, qev)
		}
		if time.Since(start) > d {
			break
		}
		// Intentionally placed at the end so that we always
		// get one more try after the last block
		if !ok {
			qq.Block()
		}
	}

	return allQevs, nil
}
