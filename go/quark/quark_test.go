// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Elastic NV

package quark

import (
	"fmt"
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

		attr.Flags &= ^(QQ_EBPF | QQ_KPROBE)
		attr.Flags |= QQ_EBPF
		testStats(t, attr)
	})

	t.Run("StatsKprobe", func(t *testing.T) {
		attr := DefaultQueueAttr()
		attr.HoldTime = 100

		attr.Flags &= ^(QQ_EBPF | QQ_KPROBE)
		attr.Flags |= QQ_KPROBE
		testStats(t, attr)
	})

	t.Run("DisableAggregation", func(t *testing.T) {
		attr := DefaultQueueAttr()
		attr.HoldTime = 25

		queue, err := OpenQueue(attr)
		require.NoError(t, err)
		defer queue.Close()

		require.NoError(t, queue.DisableAggregation())

		// XXX assumes /bin/true exists
		cmd := exec.Command("/bin/true")
		err = cmd.Run()
		require.NoError(t, err)

		qevs, err := drainFor(queue, 200*time.Millisecond)
		require.NoError(t, err)

		var childEvents []uint64
		for _, qev := range qevs {
			if qev.Process.Pid == uint32(cmd.Process.Pid) {
				childEvents = append(childEvents, qev.Events)
			}
		}

		require.Len(t, childEvents, 3)
		processEvents := QUARK_EV_FORK | QUARK_EV_EXEC | QUARK_EV_EXIT
		require.Equal(t, []uint64{
			QUARK_EV_FORK,
			QUARK_EV_EXEC,
			QUARK_EV_EXIT,
		}, []uint64{
			childEvents[0] & processEvents,
			childEvents[1] & processEvents,
			childEvents[2] & processEvents,
		})
	})

	t.Run("RulePoison", func(t *testing.T) {
		const poisonTag = 1805

		// Poison our children, pass only poisoned events, drop the
		// rest, as in t_rule_poison of quark-test.
		attr := DefaultQueueAttr()
		attr.HoldTime = 25
		attr.RuleText = fmt.Sprintf(
			"poison %d on process.ppid %d\n"+
				"pass on poison %d\n"+
				"drop on any",
			poisonTag, os.Getpid(), poisonTag)

		queue, err := OpenQueue(attr)
		require.NoError(t, err)

		defer queue.Close()

		// XXX assumes /bin/true exists
		cmd := exec.Command("/bin/true")
		err = cmd.Run()
		require.NoError(t, err)

		qevs, err := drainFor(queue, 200*time.Millisecond)
		require.NoError(t, err)
		require.NotEmpty(t, qevs)

		// Everything that survived the ruleset must carry the tag,
		// and our child must be in there.
		foundChild := false
		for _, qev := range qevs {
			require.Equal(t, uint64(poisonTag), qev.Process.PoisonTag)
			if qev.Process.Pid == uint32(cmd.Process.Pid) {
				foundChild = true
			}
		}
		require.True(t, foundChild)
	})

	t.Run("PasswdGroupLookup", func(t *testing.T) {
		queue, err := OpenQueue(DefaultQueueAttr())
		require.NoError(t, err)

		defer queue.Close()

		passwd, ok := queue.PasswdLookup(0)
		require.True(t, ok)
		require.Equal(t, "root", passwd.Name)
		require.Zero(t, passwd.Uid)
		require.Zero(t, passwd.Gid)

		group, ok := queue.GroupLookup(0)
		require.True(t, ok)
		require.Equal(t, "root", group.Name)
		require.Zero(t, group.Gid)

		_, ok = queue.PasswdLookup(4294967290)
		require.False(t, ok)
		_, ok = queue.GroupLookup(4294967290)
		require.False(t, ok)
	})
}

// TestRuleText tests ruleset parsing, which happens before any
// privileged operation, so it doesn't require root.
func TestRuleText(t *testing.T) {
	ruleset, err := rulesetFromText("drop on any")
	require.NoError(t, err)
	require.NotNil(t, ruleset)
	freeRuleset(ruleset)

	attr := DefaultQueueAttr()
	attr.RuleText = "this is not a valid rule"
	_, err = OpenQueue(attr)
	require.ErrorContains(t, err, "can't parse ruleset")
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

func TestBoottime(t *testing.T) {
	require.NoError(t, UpdateBoottime())

	boottime := Boottime()
	require.NotZero(t, boottime)
	require.Equal(t, boottime+12345, TimeToWallclock(12345))
}
