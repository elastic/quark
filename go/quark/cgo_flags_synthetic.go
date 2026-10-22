// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Elastic NV

//go:build linux && (amd64 || arm64) && quark_synthetic

package quark

// The synthetic queue declarations in quark.h are only visible with
// WITH_SYNTHETIC defined. The define lives here rather than in synthetic.go
// so that synthetic.go, like quark.go, carries no cgo directives and can be
// copied verbatim to the go-quark repository, which keeps its own flags
// files. libquark_big.a must be built with WITH_SYNTHETIC=1 for this tag to
// link. The build constraint above must match the one on synthetic.go.

/*
#cgo CFLAGS: -DWITH_SYNTHETIC
*/
import "C"
