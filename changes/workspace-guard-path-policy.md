kind: fixed

The guard inside the agent container no longer blocks commands that only read, run or mention files under `/opt`, such as running the bundled verifier after a `cp`, or `echo "a > /opt/b"`, where the `>` is quoted text. The write and edit tools now accept paths under `$TMPDIR` as well as `/workspace`. A `$TMPDIR` of `/` or inside `/opt` is ignored. The obsolete `.pi-runtime/inbox` rule is gone.

The Bash check is now a shell lexer instead of a regular expression, and it is stricter about real writes under `/opt`. It now blocks:

- writes after any unquoted `;`, `&`, `|`, `&&`, `||`, newline, `(`, `)`, `{`, `}`, `!`, `then`, `do` or `else`
- writes behind a wrapper command (`env`, `command`, `exec`, `nice`, `nohup`, `time`, `timeout`, `sudo`, `xargs`, `flock`, `stdbuf` and similar)
- writes inside `$( )`, backticks, `<( )`, `sh`/`bash -c` strings, `eval`, `trap`, here-documents fed to a shell, and `find -exec`
- `>|` redirections and glued `cp -t/opt/...`
- `dd of=`, `find -delete`, `sed -i`, `perl -i` and `tar -C` aimed at `/opt`
- inline Python, Node, Perl or awk code that both names a path under `/opt` and looks like it writes

Before comparing, the check normalises each path: it collapses repeated slashes, resolves `.` and `..`, expands `~`, braces, globs and known variables, and resolves symlinks in the existing part of the path. It also follows `cd`, `pushd` and `popd`; inside `/opt`, only read-only commands such as `ls`, `cat` and `grep` may run. A command that cannot be parsed is refused if it mentions `/opt`.

`/opt/pi-control/outbox` is mounted writable, so for the outbox this check is the only one inside the container. It is a lexical check, not confinement: a script file or a program the agent runs can still write wherever the mounts allow.
