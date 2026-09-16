// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Elastic NV

//go:build linux && (amd64 || arm64) && quarktest

package quark

/*
#include <stdlib.h>
#include "quark.h"

static int
oci_test_populate(struct quark_queue *qq)
{
	return 0;
}

static void
oci_test_close(struct quark_queue *qq)
{
}

static struct quark_queue_ops oci_test_ops = {
	.populate = oci_test_populate,
	.close = oci_test_close,
};

static struct quark_queue *
oci_test_queue(void)
{
	struct quark_queue *qq = calloc(1, sizeof(*qq));

	if (qq != NULL) {
		qq->epollfd = -1;
		qq->queue_ops = &oci_test_ops;
		qq->cache_grace_time = UINT64_MAX;
		TAILQ_INIT(&qq->event_gc);
	}
	return qq;
}
*/
import "C"

// cgo is not supported in _test.go files. Keep this helper behind a test tag.
func newOCITestQueue() *Queue {
	qq := C.oci_test_queue()
	if qq == nil {
		panic("cannot allocate test queue")
	}
	return &Queue{quarkQueue: qq}
}

func expireOCITestGrace(queue *Queue) {
	queue.quarkQueue.cache_grace_time = 0
}
