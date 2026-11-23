kind: changed

`summary.json` and `result.json` gain `changes`: counts of added, modified, deleted, mode-only, type-changed and link entries, and `omitted`, the paths `changes.json` cannot name with the rule that kept each out (excluded names such as `node_modules` and `.npmrc`, special files, unreadable paths). An unreadable path no longer blocks scoring or hashing, and a check whose working directory was removed is recorded as failed with `check-target-missing` while the other checks run.
