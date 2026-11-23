kind: changed

Contributor documentation now describes one review and merge path for every
change: one task, branch and pull request; an independent review of record; and
a merge only after the required checks and the read-only review gate pass on the
exact head. An automatic Copilot review is read when one arrives but no longer
blocks a merge. Pull requests add a changelog fragment instead of editing the
changelog, and a pull request that changes package files regenerates the
manifest, which CI checks strictly.
