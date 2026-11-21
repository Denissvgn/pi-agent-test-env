kind: fixed

A run is now cleaned up when its terminal closes or its SSH session drops, and
a second Ctrl-C no longer interrupts container removal. Interrupted runs and
campaign tools exit with status 130, even as background jobs. A steer,
extend-budget or patch command stopped while holding a lock no longer freezes
the supervisor. Control waits give up after two seconds and record
`control_lock_busy`. An unreadable budget request is moved to
`budget-requests/rejected/` instead of failing the stage. A check that exceeds
its `timeout_seconds` is killed and exits with status 124.
