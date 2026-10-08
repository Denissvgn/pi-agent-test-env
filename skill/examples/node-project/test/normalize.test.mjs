import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeTags } from '../normalize.mjs';

test('normalizes and preserves order', () => {
  assert.deepEqual(normalizeTags([' B ', 'a', 'b', ' C ', 'A']), ['b', 'a', 'c']);
});
test('skips empty values', () => {
  assert.deepEqual(normalizeTags(['', '   ', ' x ']), ['x']);
  assert.deepEqual(normalizeTags([]), []);
});
test('validates every input', () => {
  for (const input of [null, 1, 'x', {}, ['a', 1]]) {
    assert.throws(() => normalizeTags(input), TypeError);
  }
});
test('does not mutate input and returns a new array', () => {
  const source = Object.freeze([' A ', 'a']);
  const result = normalizeTags(source);
  assert.deepEqual(result, ['a']);
  assert.notEqual(result, source);
  assert.deepEqual(source, [' A ', 'a']);
});
