// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Elastic NV

//go:build linux && (amd64 || arm64)

package quark

import (
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOCISnapshots(t *testing.T) {
	queue := newTestQueue()
	t.Cleanup(func() {
		if queue.quarkQueue != nil {
			queue.Close()
		}
	})

	wantPod := PodInfo{UID: "pod", Name: "test-pod", NS: "test-ns", Phase: "Running"}
	pod, err := queue.CreatePod("pod", "test-pod", "test-ns", "Running")
	require.NoError(t, err)
	require.Equal(t, wantPod, pod)
	container, err := queue.CreateContainer("container", "pod", "test-container", "test-image")
	require.NoError(t, err)
	wantContainer := ContainerInfo{
		ContainerID: "container", Name: "test-container", Image: "test-image", Pod: &wantPod,
	}
	require.Equal(t, wantContainer, container)

	savedPod, ok := queue.LookupPod("pod")
	require.True(t, ok)
	savedContainer, ok := queue.LookupContainer("container")
	require.True(t, ok)
	changed, ok := queue.LookupContainer("container")
	require.True(t, ok)
	changed.Pod.Name = "changed"
	current, ok := queue.LookupContainer("container")
	require.True(t, ok)
	require.Equal(t, wantContainer, current)

	require.NoError(t, queue.RemovePod("pod"))
	require.NoError(t, queue.RemovePod("pod"), "repeated removal must succeed")
	_, ok = queue.GetEvent()
	require.False(t, ok)
	_, ok = queue.LookupPod("pod")
	require.True(t, ok, "pod must remain during the grace period")

	expireTestGrace(queue)
	_, ok = queue.GetEvent()
	require.False(t, ok)
	_, ok = queue.LookupPod("pod")
	require.False(t, ok)
	_, ok = queue.LookupContainer("container")
	require.False(t, ok)
	require.ErrorIs(t, queue.RemovePod("pod"), syscall.ESRCH)
	require.ErrorIs(t, queue.RemoveContainer("container"), syscall.ESRCH)
	queue.GetEvent()

	require.Equal(t, wantPod, pod)
	require.Equal(t, wantPod, savedPod)
	require.Equal(t, wantContainer, container)
	require.Equal(t, wantContainer, savedContainer)

	// Close also frees objects that were not scheduled for collection.
	livePod, err := queue.CreatePod("live-pod", "live", "ns", "Running")
	require.NoError(t, err)
	liveContainer, err := queue.CreateContainer("live-container", "live-pod", "live", "image")
	require.NoError(t, err)
	queue.Close()
	require.Equal(t, PodInfo{UID: "live-pod", Name: "live", NS: "ns", Phase: "Running"}, livePod)
	require.Equal(t, "live-container", liveContainer.ContainerID)
	require.Equal(t, livePod, *liveContainer.Pod)
	require.Equal(t, wantContainer, savedContainer)
}

func TestOCIRemoveByID(t *testing.T) {
	queue := newTestQueue()
	defer queue.Close()

	container, err := queue.CreateContainer("container", "", "", "")
	require.NoError(t, err)
	require.Equal(t, ContainerInfo{ContainerID: "container"}, container)
	duplicate, err := queue.CreateContainer("container", "", "new", "image")
	require.ErrorIs(t, err, syscall.EEXIST)
	require.Equal(t, ContainerInfo{}, duplicate)
	missing, err := queue.CreateContainer("missing", "absent-pod", "", "")
	require.ErrorIs(t, err, syscall.ESRCH)
	require.Equal(t, ContainerInfo{}, missing)

	require.ErrorIs(t, queue.RemovePod("absent"), syscall.ESRCH)
	require.ErrorIs(t, queue.RemoveContainer("absent"), syscall.ESRCH)
	require.NoError(t, queue.RemoveContainer("container"))
	require.NoError(t, queue.RemoveContainer("container"), "repeated removal must succeed")
	queue.GetEvent()
	_, ok := queue.LookupContainer("container")
	require.True(t, ok, "container must remain during the grace period")
	expireTestGrace(queue)
	queue.GetEvent()
	_, ok = queue.LookupContainer("container")
	require.False(t, ok)
	require.ErrorIs(t, queue.RemoveContainer("container"), syscall.ESRCH)
	queue.GetEvent()
	require.Equal(t, ContainerInfo{ContainerID: "container"}, container)

	// Removal by ID targets the current object, even if the ID was reused.
	replacement, err := queue.CreateContainer("container", "", "replacement", "image")
	require.NoError(t, err)
	require.NoError(t, queue.RemoveContainer("container"))
	queue.GetEvent()
	_, ok = queue.LookupContainer("container")
	require.False(t, ok)
	require.Equal(t, "replacement", replacement.Name)
}
