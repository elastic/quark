package quark

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQuarkSnapshot(t *testing.T) {
	queue, err := OpenQueue(DefaultQueueAttr(), 64)
	require.NoError(t, err)

	defer queue.Close()

	require.NotEmpty(t, queue.Snapshot())
}

func TestQuarkLookup(t *testing.T) {
	queue, err := OpenQueue(DefaultQueueAttr(), 64)
	require.NoError(t, err)

	defer queue.Close()

	fetchPid := uint32(1)
	pid1, ok := queue.Lookup(int(fetchPid))
	require.True(t, ok)

	require.Equal(t, fetchPid, pid1.Pid)
	require.NotEmpty(t, pid1.Comm)
	require.NotEmpty(t, pid1.Cwd)
}

func TestQuarkGetEvents(t *testing.T) {
	queue, err := OpenQueue(DefaultQueueAttr(), 64)
	require.NoError(t, err)

	defer queue.Close()

	qevs, err := queue.GetEvents()
	require.NoError(t, err)

	for _, qev := range qevs {
		require.NotEmpty(t, qev.Process.Comm)
		require.NotEmpty(t, qev.Process.Cwd)
	}
}
