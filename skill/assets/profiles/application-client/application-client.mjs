/** Reviewed closed application tools; only a private parent context grants scope. */
import fs from 'node:fs';
import {createHash} from 'node:crypto';
import {createBudgetGuard} from '/opt/pi-lab/tool-budget.mjs';

const TOOLS = new Set(['app_api','app_browser','artifact_read','artifact_write','report_write','budget_status']);
const TOKEN = /^[a-f0-9]{64}$/;
const NATIVE = /^[\x21-\x7e]{1,128}$/;
const MAX_REQUEST = 320 * 1024;
const MAX_RESPONSE = 8192;
const fail = () => new Error('application_tool_unavailable');
const exact = (value, keys) => {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join('\0') !== [...keys].sort().join('\0')) throw fail();
};

function canonical(value, depth=0) {
  if (depth>64) throw fail();
  if (value===null || typeof value==='boolean' || typeof value==='string') return JSON.stringify(value);
  if (typeof value==='number') {if (!Number.isFinite(value)) throw fail(); return JSON.stringify(value);}
  if (Array.isArray(value)) {
    if (Object.keys(value).length!==value.length || Object.getOwnPropertySymbols(value).length ||
        Array.from({length:value.length},(_,index)=>Object.hasOwn(value,index)).some(own=>!own)) throw fail();
    return '['+value.map(item=>canonical(item,depth+1)).join(',')+']';
  }
  if (value && typeof value==='object' && [Object.prototype,null].includes(Object.getPrototypeOf(value))) {
    if (Object.getOwnPropertySymbols(value).length || Object.values(Object.getOwnPropertyDescriptors(value))
        .some(item=>!Object.hasOwn(item,'value') || !item.enumerable)) throw fail();
    return '{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+canonical(value[key],depth+1)).join(',')+'}';
  }
  throw fail();
}

function privateContext() {
  const path=process.env.PI_LAB_APPLICATION_CONTEXT;
  if (typeof path!=='string' || !path.startsWith('/') || path.includes('\0') ||
      path.split('/').some((part,index)=>index>0&&(!part||part==='.'||part==='..'))) throw fail();
  const fd=fs.openSync(path,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW);
  try {
    const info=fs.fstatSync(fd);
    if (!info.isFile() || info.nlink!==1 || info.size>65536 || (info.mode&0o777)!==0o400 ||
        typeof process.getuid!=='function' || info.uid!==process.getuid()) throw fail();
    const value=JSON.parse(fs.readFileSync(fd,'utf8'));
    exact(value,['schema','scope','capability','base_url','tool_schemas','budget_context']);
    if (value.schema!==1 || value.base_url!=='http://pi-application:8081/tool' ||
        typeof value.capability!=='string'||!TOKEN.test(value.capability) ||
        !Array.isArray(value.tool_schemas)||!value.tool_schemas.length||value.tool_schemas.length>6) throw fail();
    const names=[];
    for (const tool of value.tool_schemas) {
      exact(tool,['name','description','parameters']);
      if (!TOOLS.has(tool.name)||typeof tool.description!=='string'||!tool.description||
          !tool.parameters||typeof tool.parameters!=='object'||Array.isArray(tool.parameters)) throw fail();
      names.push(tool.name);
    }
    if (new Set(names).size!==names.length||!names.includes('budget_status')||
        canonical(value.budget_context.scope)!==canonical(value.scope)||
        canonical(value.budget_context.allowed_tools)!==canonical(names)||
        value.capability===value.budget_context.capability||
        createHash('sha256').update(canonical([...value.tool_schemas].sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0))).digest('hex')
          !==value.budget_context.tool_schema_sha256) throw fail();
    return value;
  } finally {fs.closeSync(fd);}
}

async function request(context, nativeCallId, name, input, grant) {
  const body=canonical({schema:1,scope:context.scope,native_call_id:nativeCallId,tool_name:name,input,budget_grant:grant});
  if (Buffer.byteLength(body)>MAX_REQUEST) throw fail();
  const response=await fetch(context.base_url,{method:'POST',redirect:'error',
    headers:{Authorization:'Bearer '+context.capability,'Content-Type':'application/json'},
    body,signal:AbortSignal.timeout(20000)});
  const reader=response.body.getReader(), chunks=[];let size=0;
  try {
    for (;;) {
      const row=await reader.read();if(row.done)break;
      size+=row.value.byteLength;if(size>MAX_RESPONSE)throw fail();chunks.push(Buffer.from(row.value));
    }
  } finally {await reader.cancel().catch(()=>{});}
  const value=JSON.parse(Buffer.concat(chunks).toString('utf8'));
  exact(value,['schema','ok','result']);
  if(response.status!==200||value.schema!==1||value.ok!==true||!value.result||
     typeof value.result!=='object'||Array.isArray(value.result))throw fail();
  return value.result;
}

export default function install(pi) {
  let context;
  try {context=privateContext();} catch (_) {throw fail();}
  const names=context.tool_schemas.map(tool=>tool.name);
  const guard=createBudgetGuard(pi,context.budget_context);
  for (const definition of context.tool_schemas) {
    if(definition.name==='budget_status')continue;
    const native=JSON.parse(canonical(definition));
    pi.registerTool({...native,label:native.name,
      async execute(id,input) {
        try {
          if(typeof id!=='string'||!NATIVE.test(id))throw fail();
          const grant=guard.executionGrant(id,native.name,input);
          const result=await request(context,id,native.name,input,grant);
          return {content:[{type:'text',text:JSON.stringify(result)}],details:result,isError:result.ok===false};
        } catch (_) {
          const result={ok:false,reason:'application_tool_unavailable'};
          return {content:[{type:'text',text:JSON.stringify(result)}],details:result,isError:true};
        }
      }});
  }
  pi.on('session_start',()=>pi.setActiveTools(names));
  pi.on('before_agent_start',()=>{
    if(canonical([...pi.getActiveTools()].sort())!==canonical([...names].sort())||
       canonical(pi.getAllTools().map(tool=>tool.name).sort())!==canonical([...names].sort()))throw fail();
  });
}
