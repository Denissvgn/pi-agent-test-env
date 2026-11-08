# Fresh ownership reads with bounded descriptor IO

The registry and ownership-proof readers use `os.open` with their existing
no-follow/nonblocking flags, then read bytes directly from that descriptor.
They close the descriptor in a `finally` block. This avoids allocating a second
Python file wrapper for an already open descriptor.

Every requested read still opens the original file and reads fresh contents.
Whole-registry replay scans, proof hashes, directory walks, identity and privacy
checks, original lease handling, source families and reference limits remain in
place. There is no decoded-record snapshot, proof-body cache, held-parent cache,
metadata-based freshness assumption or persistent inspection token. Shared
memory-mapped writes must be observed by a new read or rejected by the proof's
existing content reference, even when filesystem timestamps remain unchanged.

The internal descriptor reader joins short reads and stops at the caller's byte
ceiling or EOF. Registry reads stop at one byte beyond the existing 1 MiB bound
and reject excess bytes, including growth after the initial size observation.
Proof reads retain their existing per-file/aggregate ceilings and the special
zero-byte read behavior. Schema parsing and bounded verified-replacement retries
remain unchanged.

Each real open remains visible to the audit hook. The redundant file-wrapper
audit entry disappears because that wrapper is no longer created. No consumer
audit policy, event filter, counter, deadline or resource threshold changes.

For N registry rows and H replay scans, record opens still cost N(1+H).
Avoiding wrapper construction reduces Python audit events and allocation work;
it does not eliminate those scans or secure ancestor walks. Synthetic read-stage
counts exclude startup and the rest of a proof graph. They cannot establish
end-to-end fit within a consumer's fixed audit or time budget. That requires a
separate measurement of the exact immutable candidate and admitted input scope.

The retained legacy empty-file check already opens and validates a no-follow
parent directory before checking that the leaf is regular and zero length.
It supplies that same freshly acquired descriptor to the reader within this
single call. The reader still checks the zero-byte/private role and performs
its full post-read named-parent walk; the helper closes its parent on every
exit. No descriptor is retained across calls, and no payload read is permitted.
This removes one redundant initial traversal while keeping the existing initial
helper traversal and final reader traversal.
