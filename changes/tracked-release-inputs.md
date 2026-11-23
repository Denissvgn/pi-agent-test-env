kind: changed

Release archives and Docker CI staging use Git’s tracked files and respect
export-ignore. Release builds report the source commit, tree, dirty flag, Python
and zlib versions, and archive epoch. They reject dirty checkouts, stray files
under skill/, tests/ or tools/, and stale manifests. Candidate archives and CI
staging generate checksums from the packaged bytes without modifying the checkout.
