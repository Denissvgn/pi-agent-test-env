kind: fixed

The guard inside the agent container no longer blocks commands that only read or run files under `/opt`, such as the bundled verifier after a `cp`. It now blocks only writes under `/opt`, and the write and edit tools accept paths under `$TMPDIR` as well as `/workspace`.
