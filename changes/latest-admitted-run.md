kind: fixed

Update `latest` only after a run acquires the host lease, so a busy attempt
cannot displace the active run.
