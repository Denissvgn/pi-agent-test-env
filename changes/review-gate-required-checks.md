kind: changed

`pr-review-gate` no longer requires a Copilot review by default. Use `--expect-reviewer` to require named reviewers; without it, `--independent-review TEXT` is mandatory and records who accepted the change as `review_of_record`. The new `--require-check NAME` option, repeatable, blocks unless a check run with that name is present and successful on the exact head; an absent or pending check blocks. The JSON output adds `required_checks` and `review_of_record`. Commands that pass `--expect-reviewer Copilot` behave as before.
