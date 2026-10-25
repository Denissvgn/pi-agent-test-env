/** Awaited assistant-batch admission plus fail-closed native effect grants.
 * This trusted extension never requests another turn or repairs a report.
 * Its fixed parent-selected extension order/loadout is an admission prerequisite;
 * a worker RPC is an observation, not cryptographic proof of a Pi callback.
 */
import fs from 'node:fs';
import { createHash } from 'node:crypto';

const NATIVE = /^[\x21-\x7E]{1,128}$/;
const TOKEN = /^[a-f0-9]{64}$/;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const MAX_REQUEST_BYTES = 2 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 256 * 1024;
let activeGuard;
const validToken = value => typeof value === 'string' && TOKEN.test(value);
const validUuid = value => typeof value === 'string' && UUID.test(value);

function error(reason = 'accounting_unavailable') {
  const value = new Error(reason); value.reason = reason; return value;
}

function exact(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')) throw error();
}

function canonical(value, depth = 0) {
  if (depth > 64) throw error();
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') { if (!Number.isFinite(value)) throw error(); return JSON.stringify(value); }
  if (Array.isArray(value)) {
    if (Object.keys(value).length !== value.length || Object.getOwnPropertySymbols(value).length
        || Array.from({length: value.length}, (_, index) => Object.hasOwn(value, index)).some(own => !own)) throw error();
    return '[' + value.map(item => canonical(item, depth + 1)).join(',') + ']';
  }
  if (value && typeof value === 'object' && [Object.prototype, null].includes(Object.getPrototypeOf(value))) {
    if (Object.getOwnPropertySymbols(value).length || Object.values(Object.getOwnPropertyDescriptors(value))
        .some(descriptor => !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable)) throw error();
    // Serialize directly: own __proto__/constructor keys never invoke a setter.
    // These local fingerprints are compared only with other JS fingerprints.
    // The Python helper computes its own authoritative raw-value digest.
    return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key], depth + 1)).join(',') + '}';
  }
  throw error();
}

function fingerprint(value) {
  const raw = canonical(value);
  if (Buffer.byteLength(raw) > 320 * 1024) throw error();
  return createHash('sha256').update(raw).digest('hex');
}

function contextValue(value) {
  exact(value, ['schema', 'pi_release', 'scope', 'allowed_tools', 'prepare_arguments',
                'extension_order_sha256', 'tool_schema_sha256', 'base_url', 'capability']);
  if (value.schema !== 1 || !['0.87.1', '1.2.0'].includes(value.pi_release)
      || value.base_url !== 'http://pi-application:8081/budget'
      || !validToken(value.capability) || !validToken(value.extension_order_sha256)
      || !validToken(value.tool_schema_sha256)
      || !Array.isArray(value.allowed_tools) || !value.allowed_tools.length
      || value.allowed_tools.length > 64 || new Set(value.allowed_tools).size !== value.allowed_tools.length
      || !value.allowed_tools.includes('budget_status')
      || value.allowed_tools.some(name => typeof name !== 'string' || !/^[A-Za-z_][A-Za-z0-9_.-]{0,63}$/.test(name))) throw error();
  exact(value.prepare_arguments, value.allowed_tools);
  if (Object.values(value.prepare_arguments).some(kind => !['none', 'reviewed_pure'].includes(kind))) throw error();
  if (!value.scope || typeof value.scope !== 'object' || !validToken(value.scope.plan_sha256)
      || !['run_id', 'attempt_id', 'stage_id', 'segment_id', 'session_id'].every(k => validUuid(value.scope[k]))
      || !(value.scope.trial_id === null || validUuid(value.scope.trial_id))) throw error();
  return JSON.parse(canonical(value));
}

async function transport(context, action, payload) {
  const body = canonical({schema: 1, scope: context.scope, action, payload});
  if (Buffer.byteLength(body) > MAX_REQUEST_BYTES) throw error();
  const response = await fetch(context.base_url, {method: 'POST', redirect: 'error',
    headers: {'Authorization': 'Bearer ' + context.capability, 'Content-Type': 'application/json'},
    body, signal: AbortSignal.timeout(5000)});
  const reader = response.body.getReader(); let size = 0; const chunks = [];
  try {
    while (true) {
      const next = await reader.read(); if (next.done) break;
      size += next.value.byteLength;
      if (size > MAX_RESPONSE_BYTES) throw error();
      chunks.push(Buffer.from(next.value));
    }
  } finally { await reader.cancel().catch(() => {}); }
  const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  if (response.status !== 200 || value.ok !== true) throw error(value.reason || 'accounting_unavailable');
  return value.result;
}

export function createBudgetGuard(pi, suppliedContext, {request} = {}) {
  const context = contextValue(suppliedContext);
  const send = request || ((action, payload) => transport(context, action, payload));
  let poisoned = true, fatal = false, initialized = false, current = null, ordinal = 0;
  let snapshot = null;
  let executionContext = null, abortRequested = false;
  const grants = new Map();

  function remember(ctx) { if (ctx && typeof ctx.abort === 'function') executionContext = ctx; }
  function requestAbort() {
    if (!abortRequested && executionContext) {
      abortRequested = true;
      try { executionContext.abort(); } catch (_) {}
    }
  }

  async function rpc(action, payload) {
    try { return await send(action, payload); }
    catch (_) { poisoned = true; fatal = true; requestAbort(); throw error(); }
  }

  async function poison() {
    poisoned = true; fatal = true;
    requestAbort();
    // Self-revocation cannot grow authority. Failure leaves the local gate closed.
    try { await send('poison', {}); } catch (_) {}
  }

  async function checkpoint() {
    if (!initialized || poisoned || fatal) throw error();
    snapshot = await rpc('checkpoint', {});
    if (snapshot.accounting !== 'available') { poisoned = true; throw error(); }
    return snapshot;
  }

  function executionGrant(nativeCallId, toolName, rawInput) {
    const found = grants.get(nativeCallId);
    if (poisoned || fatal || !current || !found || !found.consumed || found.name !== toolName
        || found.fingerprint !== fingerprint(rawInput) || !validToken(found.nonce)) throw error();
    return found.nonce;
  }

  pi.registerTool({name: 'budget_status', label: 'Budget status',
    description: 'Return post-charge trusted remaining budgets.',
    parameters: {type: 'object', properties: {}, required: [], additionalProperties: false},
    async execute(id, args) {
      const nonce = executionGrant(id, 'budget_status', args);
      await rpc('entry', {grant: nonce, native_call_id: id, tool_name: 'budget_status', raw_input: args});
      snapshot = await rpc('status', {});
      const text = JSON.stringify(snapshot);
      const projection = Buffer.byteLength(text) <= 8192 ? snapshot
        : {schema: 1, ok: false, reason: 'evidence_unavailable'};
      return {content: [{type: 'text', text: JSON.stringify(projection)}], details: projection};
    }});

  pi.on('before_agent_start', async (_event, ctx) => {
    remember(ctx);
    try {
    if (fatal) throw error();
    poisoned = true;
    const active = [...pi.getActiveTools()].sort();
    if (canonical(active) !== canonical([...context.allowed_tools].sort())) throw error();
    const definitions = pi.getAllTools();
    if (canonical(definitions.map(tool => tool.name).sort()) !== canonical([...context.allowed_tools].sort())) throw error();
    for (const tool of definitions) {
      if (context.allowed_tools.includes(tool.name) && typeof tool.prepareArguments === 'function'
          && context.prepare_arguments[tool.name] !== 'reviewed_pure') throw error();
    }
    // TypeBox metadata is nonenumerable and absent from the actual JSON schema.
    // Compare its JSON projection, preserving omitted required/additionalProperties.
    const wireTools = definitions.map(tool => ({name: tool.name, description: tool.description,
      parameters: JSON.parse(JSON.stringify(tool.parameters))})).sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
    if (createHash('sha256').update(canonical(wireTools)).digest('hex') !== context.tool_schema_sha256) throw error();
    // Parent loadout admission also freezes extension order and pure preparation.
    // Neither a descriptor author claim nor a public start event grants authority.
    snapshot = await rpc('checkpoint', {});
    if (snapshot.accounting !== 'available') throw error();
    initialized = true; poisoned = false;
    } catch (_) { await poison(); throw error(); }
  });

  pi.on('message_end', async (event, ctx) => {
    remember(ctx);
    if (event.message?.role !== 'assistant') return;
    try {
    // Pi catches message_end exceptions. Close the gate before inspecting anything.
    const previousPoison = poisoned; poisoned = true;
    if (!initialized || previousPoison || current !== null || !Array.isArray(event.message.content)) throw error();
    const calls = event.message.content.filter(block => block?.type === 'toolCall').map(block =>
      ({id: block.id, name: block.name, arguments: block.arguments}));
    if (!calls.length) { poisoned = false; return; }
    if (calls.length > 500) throw error();
    const local = calls.map(call => ({...call, fingerprint: fingerprint(call.arguments)}));
    const batchId = 'batch-' + (++ordinal);
    const result = await rpc('reserve', {batch_id: batchId, calls,
                                       stop_reason: event.message.stopReason || 'stop'});
    if (fatal || !result || !Array.isArray(result.calls) || result.calls.length !== calls.length
        || result.snapshot?.accounting !== 'available') throw error();
    grants.clear();
    for (let index = 0; index < calls.length; index++) {
      const row = result.calls[index], call = local[index];
      if (row.id !== call.id || row.name !== call.name || typeof row.id !== 'string'
          || !NATIVE.test(row.id) || typeof row.name !== 'string' || !NATIVE.test(row.name)
          || typeof row.admitted !== 'boolean') throw error();
      grants.set(call.id, {name: call.name, fingerprint: call.fingerprint, admitted: row.admitted,
                           reason: row.reason, started: false, consumed: false, completed: false, nonce: null});
    }
    current = batchId; snapshot = result.snapshot; poisoned = false;
    } catch (_) { await poison(); throw error(); }
  });

  pi.on('tool_execution_start', async (event, ctx) => {
    remember(ctx);
    try {
      const call = grants.get(event.toolCallId);
      if (poisoned || fatal || !current || !call || call.started || call.name !== event.toolName
          || call.fingerprint !== fingerprint(event.args)) throw error();
      // This is reconciliation only. Pi emits start before validation; it proves
      // neither execution nor authority and never spends another native slot.
      call.started = true;
    } catch (_) { await poison(); throw error(); }
  });

  pi.on('tool_call', async (event, ctx) => {
    remember(ctx);
    try {
      if (poisoned || fatal || !initialized || !current || event.parentToolCallId !== undefined) throw error();
      const call = grants.get(event.toolCallId);
      if (!call || !call.started || call.name !== event.toolName || call.consumed || call.completed
          || call.fingerprint !== fingerprint(event.input)) throw error();
      if (!call.admitted) return {block: true, reason: call.reason || 'accounting_unavailable'};
      const result = await rpc('consume', {batch_id: current, native_call_id: event.toolCallId,
                                         tool_name: event.toolName, raw_input: event.input});
      if (!validToken(result?.execution_nonce)) throw error();
      call.consumed = true; call.nonce = result.execution_nonce; snapshot = result.snapshot;
      return undefined;
    } catch (_) {
      await poison();
      return {block: true, reason: 'accounting_unavailable'};
    }
  });

  pi.on('tool_execution_end', async (event, ctx) => {
    remember(ctx);
    try {
    if (poisoned || !current) throw error();
    const call = grants.get(event.toolCallId);
    if (!call || !call.started || call.name !== event.toolName || call.completed || typeof event.isError !== 'boolean') {
      throw error();
    }
    snapshot = await rpc('complete', {batch_id: current, native_call_id: event.toolCallId,
                                    tool_name: event.toolName, is_error: event.isError});
    call.completed = true;
    } catch (_) { await poison(); throw error(); }
  });

  async function finishBatch(_event, ctx) {
    remember(ctx);
    try {
    if (poisoned) throw error();
    if (current !== null) {
      if ([...grants.values()].some(call => !call.completed)) throw error();
      snapshot = await rpc('reconcile', {batch_id: current});
      current = null; grants.clear();
    }
    } catch (_) { await poison(); throw error(); }
  }
  pi.on('turn_end', finishBatch);
  pi.on('agent_end', finishBatch);
  pi.on('context', async (_event, ctx) => {
    remember(ctx);
    try { await checkpoint(); } catch (_) { await poison(); throw error(); }
  });

  return {executionGrant, checkpoint, snapshot: () => snapshot ? JSON.parse(canonical(snapshot)) : null};
}

export function getExecutionGrant(nativeCallId, toolName, rawInput) {
  if (!activeGuard) throw error();
  return activeGuard.executionGrant(nativeCallId, toolName, rawInput);
}

export default function install(pi) {
  const path = process.env.PI_LAB_TOOL_BUDGET_CONTEXT;
  if (!path) throw error();
  const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const info = fs.fstatSync(fd);
    if (!info.isFile() || info.nlink !== 1 || info.size > 65536 || (info.mode & 0o077)
        || typeof process.getuid === 'function' && info.uid !== process.getuid()) throw error();
    activeGuard = createBudgetGuard(pi, JSON.parse(fs.readFileSync(fd, 'utf8')));
  } finally { fs.closeSync(fd); }
}
