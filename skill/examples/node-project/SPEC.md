# Stable normalized tags

Implement `normalizeTags(values)` in `normalize.mjs`.

- `values` must be an array and every element must be a string; otherwise throw `TypeError`.
- Trim leading/trailing whitespace from every string and lowercase it.
- Omit empty normalized tags.
- Deduplicate normalized tags while preserving first-appearance order.
- Return a new array. Never mutate the input.
- Do not change this spec or the test directory.

Run `node --test test/normalize.test.mjs`. No npm dependencies are required.
