kind: fixed
Help text now states the default that each option's parser uses:

- `env list --json` and `env inspect --json`: the default is off; the output is always JSON.
- `ensure-image --pi-version`: the default is empty, so reuse takes no pin and a build requires one.
- `env check --platform`: the default is none. With `--id`, admission uses `linux/arm64` when the flag is omitted; without `--id` the flag is ignored.
- `--allow-browser-no-sandbox` for `browser-check`: the help says that the command refuses the flag with `browser-policy-invalid`.
- `cleanup --json` and `leftovers --json`: the default is off, which prints text.

Command behavior, options, choices and exit codes are unchanged.
