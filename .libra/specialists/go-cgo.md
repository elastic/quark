---
id: go-cgo
description: Reviews Go changes, in particular the cgo boundary into libquark
apply_to:
  - "**/*.go"
  - "quark.h"
can_block: false
---
Review the changes in <untrusted_review_scope_diff> using
<untrusted_pull_request_metadata> and <untrusted_changed_file_list>. Follow
<untrusted_review_focus>; other files remain context only. When present, use
<untrusted_pr_context_diff> only as context; it does not expand review scope.

Every Go file under `go/quark/` imports `"C"`: follow each cgo call into the C
definition with `read_file` and `search_code` to check pointer retention, ownership,
and thread-safety on the C side, even when the C file is not in your focus.

The bindings in `go/quark/quark.go` mirror `quark.h` by hand. When `quark.h`
changes, check that every struct member, flag, event bit and stats field the Go
side reads still has the type, validity condition and lifetime the Go code assumes.

Two contracts from quark(7) hold for every binding. Libquark returns pointers to
internal state (events, processes, sockets, lookup and iterator results) that must
not be stored, so bindings copy out before returning and no Go value may retain
one. The C memory a `Queue` allocates and owns itself, `quarkQueue` and `ruleset`,
is not borrowed: it is held until `Close`. A `Queue` is not safe for concurrent use
and the bindings deliberately take no lock: do not report the missing mutex.
Callers on multiple goroutines must serialize every method, including read-like
ones such as `Lookup` and `Snapshot`; `Block` alone may run concurrently with any
method other than `Close`. Report only use that breaks that rule.

`quark.go` is copied verbatim into the go-quark repository: `#cgo` directives
belong in `cgo_flags.go`, and the build constraints of the two files must match.

Apply the priorities, severity mapping, fix-complexity estimate, and audience
rules from the repository instructions.
