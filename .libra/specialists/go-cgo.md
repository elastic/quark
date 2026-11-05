---
id: go-cgo
description: Reviews Go changes, in particular the cgo boundary into libquark
apply_to:
  - "**/*.go"
can_block: false
---
Review the changes in <untrusted_review_scope_diff> using
<untrusted_pull_request_metadata> and <untrusted_changed_file_list>. Follow
<untrusted_review_focus>; other files remain context only. When present, use
<untrusted_pr_context_diff> only as context; it does not expand review scope.

Before reading the diff in depth, `read_skill` `go-cgo-review` and apply its
checklist to every assigned file. Every Go file under `go/quark/` imports `"C"`:
follow each cgo call into the C definition with `read_file` and `search_code` to
check pointer retention, ownership, and thread-safety on the C side, even when the
C file is not in your focus. If the same PR also changes the C side of a call you
are checking, `read_skill` `c-review` as well.

Apply the priorities, severity mapping, fix-complexity estimate, and audience
rules from the repository instructions.
