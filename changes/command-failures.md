kind: changed

Blocked runs print the failing phase and error message to stderr. Diagnostic
messages redact resolved credentials and endpoint URLs. Set `PI_LAB_DEBUG=1`
to include a traceback. Both `run` and `validate-plan` require a regular plan
file and report a symlinked plan path as a blocker.

Upgrade note: command wrappers should handle exit code 70 for unexpected
internal errors. Exit code 1 remains reserved for FAIL, ASSISTED and RECOVERED.
