/** Reviewed Pi 0.87.1 fixture lookup: fixed read-only data, no shell/network/write operation. */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { Type } from '@earendil-works/pi-ai';

export function lookup(table, key, maxBytes = 4096) {
  if (typeof key !== 'string' || !/^[a-z0-9-]{1,64}$/.test(key)) throw new Error('Invalid fixture key');
  const found = Object.hasOwn(table, key);
  const value = { key, found, value: found ? table[key] : null };
  if (Buffer.byteLength(JSON.stringify(value)) > maxBytes) throw new Error('Fixture result exceeded its declared bound');
  return value;
}

export default function (pi) {
  const root = path.dirname(fileURLToPath(import.meta.url));
  const bytes = fs.readFileSync(path.join(root, 'fixtures.json'));
  const table = JSON.parse(bytes.toString('utf8'));
  const config = JSON.parse(fs.readFileSync(path.join(root, 'config.json'), 'utf8'));
  const tableSha = createHash('sha256').update(bytes).digest('hex');
  pi.registerTool({
    name: 'fixture_lookup', label: 'Fixture lookup',
    description: 'Look up one exact key in the declared read-only fixture table. Returns key, found, and value.',
    parameters: Type.Object({ key: Type.String({ minLength: 1, maxLength: 64, pattern: '^[a-z0-9-]+$' }) }, { additionalProperties: false }),
    async execute(_callId, params) {
      const value = lookup(table, params.key, config.max_result_bytes);
      return { content: [{ type: 'text', text: JSON.stringify(value) }],
               details: { schema: 1, component_id: 'fixture-lookup', table_sha256: tableSha, ...value } };
    }
  });
}
