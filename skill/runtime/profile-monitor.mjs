/** Trusted observer/allowlist guard. Metadata never authorizes a control mutation. */
import fs from 'node:fs';
import { createHash } from 'node:crypto';

export default function (pi) {
  const context = JSON.parse(fs.readFileSync(process.env.PI_LAB_PROFILE_CONTEXT, 'utf8'));
  const assets = {};
  for (const asset of context.profile.assets) {
    const file = '/opt/pi-profile/' + asset.target;
    const fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > 1048576) throw new Error('Unsafe profile asset');
    const body = fs.readFileSync(fd); fs.closeSync(fd);
    assets[asset.target] = createHash('sha256').update(body).digest('hex');
    if (assets[asset.target] !== asset.sha256) throw new Error('Profile hash mismatch');
  }
  pi.on('session_start', () => pi.setActiveTools(context.allowed_tools));
  pi.on('before_agent_start', () => {
    const active = [...pi.getActiveTools()].sort();
    const registered = pi.getAllTools().map(t => t.name).sort();
    if (JSON.stringify(active) !== JSON.stringify(context.allowed_tools)) throw new Error('Unexpected active tool set');
    if (context.profile.kind === 'builtin' && registered.includes('fixture_lookup')) throw new Error('Custom tool registered in built-in baseline');
    if (!context.profile.tools.every(t => registered.includes(t))) throw new Error('Declared tool missing');
    pi.appendEntry('pi_lab_profile', { schema: 1, ...Object.fromEntries(['run_id','attempt_id','stage_id','segment_id','profile_sha256'].map(k => [k, context[k]])),
      active_tools: active, registered_tools: registered, assets_sha256: assets });
  });
}
