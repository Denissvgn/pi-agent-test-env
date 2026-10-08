# Stable ASCII slug helper

Implement `slug.slugify(value: str) -> str`.

- Accept strings only. Raise `TypeError` for other values.
- Normalize to lowercase using Python's string lowercase operation.
- Keep only ASCII letters `a-z` and digits `0-9` as characters in the result.
- Replace every contiguous run of all other characters with one hyphen.
- Remove leading and trailing hyphens.
- Empty strings or strings without retained characters produce an empty string.
- Do not modify this specification or the acceptance tests.

This project intentionally starts unimplemented. Passing requires real implementation,
not hardcoding the visible examples. It needs no third-party Python packages.
