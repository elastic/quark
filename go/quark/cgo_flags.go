// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 Elastic NV

//go:build linux && (amd64 || arm64)

package quark

// The cgo build flags for quark live here, separate from the bindings in
// quark.go. This allows for quark.go to be copied verbatim to go-quark
// repository, and use different cgo build flags.
//
// All cgo CFLAGS in a package apply to every C preamble in the package, and
// all LDFLAGS are concatenated at link time, so these directives take effect
// for quark.go even though they are declared in a separate file. The build
// constraint above must match the one on quark.go.

/*
#cgo CFLAGS: -I${SRCDIR}/../../
#cgo LDFLAGS: -Wl,--wrap=fmemopen ${SRCDIR}/../../libquark_big.a
*/
import "C"
