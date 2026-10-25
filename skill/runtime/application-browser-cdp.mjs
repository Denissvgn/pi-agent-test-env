/** Private dependency-free Chromium CDP pipe bridge. No generic CDP/JS RPC. */
import {spawn} from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import readline from 'node:readline';
import {browserOptions} from './browser-options.mjs';

const MAX_FRAME = 8 * 1024 * 1024;
const DOM_LIMIT = 262144;
const PNG_LIMIT = 2097152;
export const RENDERER_CHECKPOINT = 'new Promise(resolve=>setTimeout(()=>resolve(true),0))';
let browser, proxy, cdp, context, session, targetId, active = null, fatal = false, mainReady = false, lastVerified = null;
const pendingNetwork = new Map();
const emit = value => {
  const wire = JSON.stringify(value);
  if (Buffer.byteLength(wire) > MAX_FRAME) throw new Error('bridge_limit');
  process.stdout.write(wire + '\n');
};
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
const hardening = `(() => {
  const deny = function(){throw new Error('unsupported application transport');};
  for (const name of ['Worker','SharedWorker','WebSocket','WebTransport','RTCPeerConnection','webkitRTCPeerConnection']) {
    try { Object.defineProperty(globalThis,name,{value:deny,writable:false,configurable:false}); } catch { throw new Error('transport policy unavailable'); }
  }
  Object.defineProperty(globalThis,'open',{value:deny,writable:false,configurable:false});
  if (globalThis.ServiceWorkerContainer) Object.defineProperty(ServiceWorkerContainer.prototype,'register',{value:deny,writable:false,configurable:false});
})();`;

class CDP {
  constructor(child) {
    this.child = child; this.sequence = 0; this.pending = new Map(); this.buffer = Buffer.alloc(0);
    child.stdio[4].on('data', chunk => {
      try {
        this.buffer = Buffer.concat([this.buffer,chunk]);
        if (this.buffer.length > MAX_FRAME) throw new Error('cdp_limit');
        for (;;) {
          const end = this.buffer.indexOf(0); if (end < 0) break;
          const raw = this.buffer.subarray(0,end); this.buffer = this.buffer.subarray(end+1);
          if (!raw.length) continue;
          const event = JSON.parse(raw.toString('utf8'));
          if (event.id) {
            const waiter = this.pending.get(event.id); if (!waiter) throw new Error('unknown_cdp_reply');
            this.pending.delete(event.id); clearTimeout(waiter.timer);
            event.error ? waiter.reject(new Error('cdp_capability_unavailable')) : waiter.resolve(event.result || {});
          } else onEvent(event).catch(() => stop('browser_policy_unavailable'));
        }
      } catch { stop('browser_protocol_invalid'); }
    });
    child.on('exit', () => {
      for (const waiter of this.pending.values()) {clearTimeout(waiter.timer); waiter.reject(new Error('browser_exited'));}
      this.pending.clear();
      if (!fatal) stop('browser_exited');
    });
  }
  send(method,params={},sessionId) {
    const id = ++this.sequence;
    return new Promise((resolve,reject) => {
      const timer = setTimeout(() => {this.pending.delete(id); reject(new Error('cdp_timeout'));}, 15000);
      this.pending.set(id,{resolve,reject,timer});
      this.child.stdio[3].write(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})})+'\0');
    });
  }
}

async function failRequest(sessionId,requestId) {
  try {await cdp.send('Fetch.failRequest',{requestId,errorReason:'BlockedByClient'},sessionId);} catch {}
}

async function freeze() {
  if (session) try {await cdp.send('Page.setWebLifecycleState',{state:'frozen'},session);} catch {}
  for (const [key,row] of pendingNetwork) {
    pendingNetwork.delete(key); await failRequest(row.session,row.requestId);
  }
}

async function stop(reason) {
  if (fatal) return; fatal = true;
  try {emit({kind:'fatal',reason});} catch {}
  if (browser && browser.exitCode === null) browser.kill('SIGKILL');
  if (proxy) proxy.close();
  setTimeout(() => process.exit(2),20).unref();
}

async function configure(sessionId) {
  await cdp.send('Page.enable',{},sessionId);
  await cdp.send('Network.enable',{maxTotalBufferSize:1048576,maxResourceBufferSize:1048576},sessionId);
  await cdp.send('Network.setBypassServiceWorker',{bypass:true},sessionId);
  await cdp.send('Network.setCacheDisabled',{cacheDisabled:true},sessionId);
  await cdp.send('Fetch.enable',{patterns:[{urlPattern:'*',requestStage:'Request'}]},sessionId);
  await cdp.send('Page.setLifecycleEventsEnabled',{enabled:true},sessionId);
  await cdp.send('Page.addScriptToEvaluateOnNewDocument',{source:hardening},sessionId);
  await cdp.send('Target.setAutoAttach',{autoAttach:true,waitForDebuggerOnStart:true,flatten:true},sessionId);
  await cdp.send('Emulation.setDeviceMetricsOverride',{width:1280,height:960,deviceScaleFactor:1,mobile:false},sessionId);
  await cdp.send('Runtime.runIfWaitingForDebugger',{},sessionId);
}

async function onEvent(event) {
  if (fatal) return;
  const params = event.params || {};
  if (active && ++active.events > 1000) return stop('browser_event_limit');
  if (event.method === 'Target.attachedToTarget') {
    const info = params.targetInfo;
    if (info.type !== 'page' || info.browserContextId !== context || session) {
      await cdp.send('Target.closeTarget',{targetId:info.targetId}); return;
    }
    session = params.sessionId; targetId = info.targetId;
    await configure(session);
    mainReady = true;
    return;
  }
  if (event.method === 'Fetch.requestPaused') {
    const key = event.sessionId + ':' + params.requestId;
    if (!active || active.closed || ++active.requests > 16 || event.sessionId !== session || params.redirectedRequestId) {
      await failRequest(event.sessionId,params.requestId); return;
    }
    const request = params.request;
    if (typeof request.url !== 'string' || request.url.length > 8192 ||
        typeof request.postData === 'string' && Buffer.byteLength(request.postData)>65536 ||
        !['Document','Stylesheet','Script','XHR','Fetch','Other','Image','Font','Media'].includes(params.resourceType)) {
      await failRequest(event.sessionId,params.requestId); return;
    }
    active.seen = true;
    if(typeof params.networkId!=='string'){active.denied.push('network_identity_unavailable');await failRequest(event.sessionId,params.requestId);return;}
    active.loading.add(params.networkId);
    pendingNetwork.set(key,{session:event.sessionId,requestId:params.requestId,actionId:active.id,networkId:params.networkId});
    emit({kind:'request',request_id:key,action_id:active.id,url:request.url,method:request.method,
      headers:request.headers,post_data:request.postData ?? null,resource_type:params.resourceType,
      redirected:false});
    return;
  }
  if (event.method === 'Page.lifecycleEvent' && active && params.name === 'DOMContentLoaded') {
    active.ready = true; if (active.waiter) active.waiter();
  }
  if (['Network.loadingFinished','Network.loadingFailed'].includes(event.method) && active) {
    active.finished++;
    if(!active.loading.has(params.requestId))active.unmatchedFinished++;
    active.loading.delete(params.requestId);
    if(active.waiter)active.waiter();
  }
  if (event.method === 'Browser.downloadWillBegin') {
    try {await cdp.send('Browser.cancelDownload',{guid:params.guid,browserContextId:context});} catch {}
    if (active) active.denied.push('download');
  }
  if (['Network.webSocketCreated','Network.webTransportCreated'].includes(event.method)) {
    // Hardening plus the deny-only proxy is the egress boundary; an unsupported
    // transport event also terminates the action, never opening a successor.
    if (active) active.denied.push('unsupported_transport');
    await freeze();
  }
}

async function isolated() {
  const tree = await cdp.send('Page.getFrameTree',{},session);
  const world = await cdp.send('Page.createIsolatedWorld',{frameId:tree.frameTree.frame.id,worldName:'pi-reviewed-browser',grantUniveralAccess:false},session);
  return {id:world.executionContextId,url:tree.frameTree.frame.url};
}

async function evaluateFixed(expression,contextId) {
  const response = await cdp.send('Runtime.evaluate',{expression,contextId,returnByValue:true,awaitPromise:true},session);
  if (response.exceptionDetails || !response.result || !Object.hasOwn(response.result,'value')) throw new Error('dom_unavailable');
  return response.result.value;
}

async function capture(expected,initial=false) {
  const world = await isolated();
  const info = await evaluateFixed(`(() => {const nodes=document.querySelectorAll('meta[name="pi-application-page"]');
    const identities=Array.from(nodes,x=>x.content);const fields=document.querySelectorAll('input,textarea,select');
    if(fields.length>500)return {url:location.href,identities,html:null};
    const form_state=Array.from(fields,x=>({tag:x.tagName,test_id:x.getAttribute('data-testid'),type:x.type,value:x.value,checked:!!x.checked}));
    const raw=JSON.stringify({url:location.href,page_identity:identities,html:document.documentElement?.outerHTML||'',form_state,
      text_content:document.documentElement?.textContent||'',inner_text:document.documentElement?.innerText||''});
    const bytes=new TextEncoder().encode(raw).length;
    return {url:location.href,identities,html:bytes<=${DOM_LIMIT}?raw:null,
      opaque:!!document.querySelector('img,canvas,svg,video,audio,object,embed,iframe,frame')||
        document.styleSheets.length>0||document.adoptedStyleSheets.length>0||!!document.querySelector('[style]'),ready:document.readyState};})()`,world.id);
  if (!(initial && info.url==='about:blank') && (info.url!==expected.url || info.identities.length!==1 || info.identities[0]!==expected.page_identity)) throw new Error('page_identity_mismatch');
  if (info.html===null) throw new Error('dom_limit');
  return info;
}

function safeScreenshotTree(root) {
  const stack = [{node:root,userAgent:false}]; let count = 0;
  const opaque = new Set(['IMG','CANVAS','SVG','VIDEO','AUDIO','OBJECT','EMBED','IFRAME','FRAME','STYLE']);
  while (stack.length) {
    const {node,userAgent} = stack.pop();
    if (!node || typeof node !== 'object' || typeof node.nodeName !== 'string'
        || !Number.isInteger(node.nodeType) || node.nodeType < 1 || node.nodeType > 12
        || ++count > 16384 || (!userAgent && opaque.has(node.nodeName.toUpperCase()))) return false;
    const attributes = node.attributes || [];
    for (let index=0;index<attributes.length;index+=2) {
      const name = String(attributes[index]).toLowerCase();
      if(!userAgent && (name==='style' || (node.nodeName.toUpperCase()==='LINK' && name==='rel'
          && String(attributes[index+1]).toLowerCase().split(/\s+/).includes('stylesheet')))) return false;
    }
    for (const shadow of node.shadowRoots || []) {
      // Browser-owned form internals are distinct from application-created
      // closed/open shadow trees, which cannot be sanitized by outerHTML.
      if (shadow.shadowRootType !== 'user-agent') return false;
      stack.push({node:shadow,userAgent:true});
    }
    if (node.contentDocument) return false;
    stack.push(...(node.children || []).map(child=>({node:child,userAgent})));
  }
  return true;
}

async function nodeFor(locator) {
  if (!/^\[data-testid="[a-z0-9-]{1,64}"\]$/.test(locator || '')) throw new Error('locator_invalid');
  const document = await cdp.send('DOM.getDocument',{depth:0,pierce:false},session);
  const found = await cdp.send('DOM.querySelectorAll',{nodeId:document.root.nodeId,selector:locator},session);
  if (found.nodeIds.length!==1) throw new Error('locator_not_unique');
  return found.nodeIds[0];
}

async function boundary() {
  const id = active.id;
  emit({kind:'effect_boundary',action_id:id});
  await new Promise((resolve,reject) => {
    active.boundary = {resolve,reject};
    setTimeout(() => reject(new Error('action_boundary_timeout')),1000).unref();
  });
}

async function mutate(command) {
  const nodeId = await nodeFor(command.target.locator);
  if (command.action==='click') {
    const box = await cdp.send('DOM.getBoxModel',{nodeId},session);
    const q = box.model.content; const x=(q[0]+q[2]+q[4]+q[6])/4, y=(q[1]+q[3]+q[5]+q[7])/4;
    if (![x,y].every(Number.isFinite)||x<0||x>=1280||y<0||y>=960) throw new Error('element_outside_viewport');
    await boundary();
    await cdp.send('Input.dispatchMouseEvent',{type:'mousePressed',x,y,button:'left',clickCount:1},session);
    await cdp.send('Input.dispatchMouseEvent',{type:'mouseReleased',x,y,button:'left',clickCount:1},session);
  } else {
    const world = await isolated();
    const object = await cdp.send('DOM.resolveNode',{nodeId,executionContextId:world.id},session);
    await boundary();
    if (command.action==='fill') {
      const response = await cdp.send('Runtime.callFunctionOn',{objectId:object.object.objectId,
        functionDeclaration:`function(){if(!['INPUT','TEXTAREA'].includes(this.tagName)||this.type==='password'||this.disabled||this.readOnly)throw Error('unsupported input');this.focus();this.select();}`,
        returnByValue:true},session);
      if (response.exceptionDetails) throw new Error('unsupported_input');
      await cdp.send('Input.insertText',{text:command.value},session);
    } else {
      const response = await cdp.send('Runtime.callFunctionOn',{objectId:object.object.objectId,
        functionDeclaration:`function(value){if(this.tagName!=='SELECT'||this.disabled)throw Error('unsupported select');const matches=Array.from(this.options).filter(x=>x.value===value&&!x.disabled);if(matches.length!==1)throw Error('option not unique');this.value=value;this.dispatchEvent(new Event('input',{bubbles:true}));this.dispatchEvent(new Event('change',{bubbles:true}));}`,
        arguments:[{value:command.option_id}],returnByValue:true},session);
      if (response.exceptionDetails) throw new Error('unsupported_option');
    }
  }
}

async function readiness(command) {
  if (!['navigate','click','fill','select'].includes(command.action)) return;
  const start = Date.now();
  // One event-driven bounded wait; it never starts another UI action or polls
  // the application. A matching first request wakes the same waiter.
  const current=active;
  await new Promise((resolve,reject) => {
    let checking=false, wakePending=false, settled=false;
    const timer = setTimeout(()=>{settled=true;reject(new Error('readiness_limit'));},5000);
    active.waiter = async () => {
      if(settled)return;
      if (checking) {wakePending=true;return;}
      if (active!==current||current.closed||!current.seen||current.loading.size||
          [...pendingNetwork.values()].some(x=>x.actionId===current.id)||(command.action==='navigate'&&!current.ready))return;
      checking=true;
      try {
        // Fetch fulfillment is not renderer delivery. One queued renderer task
        // lets response.json()/UI promises settle without compositor RAF, which
        // can remain suspended in a headless isolated world.
        const world=await isolated();
        current.frameStarted=true;
        await evaluateFixed(RENDERER_CHECKPOINT,world.id);
        current.frameCompleted=true;
        if(active===current&&!current.closed&&!current.loading.size&&![...pendingNetwork.values()].some(x=>x.actionId===current.id)){
          settled=true;clearTimeout(timer);resolve();
        }
      }catch{settled=true;clearTimeout(timer);reject(new Error('readiness_unavailable'));}
      finally{
        checking=false;
        if(!settled&&wakePending&&active===current&&!current.closed){wakePending=false;queueMicrotask(()=>current.waiter?.());}
      }
    };
    active.waiter();
    if (!command.target.allowed_operation_ids.length && command.action!=='navigate') {settled=true;clearTimeout(timer);resolve();}
  });
  if (Date.now()-start>5100) throw new Error('readiness_limit');
  if (command.action==='navigate'&&!active.ready) throw new Error('navigation_unready');
}

async function runAction(command) {
  if (active || !exact(command,['kind','action_id','action','target',...command.action==='fill'?['value']:command.action==='select'?['option_id']:[]]) ||
      !['navigate','snapshot','screenshot','click','fill','select'].includes(command.action)) throw new Error('action_invalid');
  active={id:command.action_id,requests:0,events:0,seen:false,ready:false,denied:[],closed:false,loading:new Set(),
    finished:0,unmatchedFinished:0,frameStarted:false,frameCompleted:false,phase:'prepare'};
  const deadline = setTimeout(()=>{if(active){active.closed=true;freeze().catch(()=>{});}},15000);
  let result, before = null, after = null;
  try {
    await cdp.send('Page.setWebLifecycleState',{state:'active'},session);
    before = await capture(command.action==='navigate'?(lastVerified||command.target):command.target,
                                 command.action==='navigate'&&!lastVerified);
    active.phase='perform';
    if (command.action==='navigate') await cdp.send('Page.navigate',{url:command.target.url},session);
    else if (['click','fill','select'].includes(command.action)) await mutate(command);
    active.phase='readiness';await readiness(command);
    if (active.closed) throw new Error('action_deadline');
    active.phase='after_capture';after = await capture(command.target);
    lastVerified = command.target;
    let screenshot = null;
    if (command.action==='screenshot') {
      active.phase='screenshot';
      // Stop renderer mutation before inspecting all shadow trees and pixels.
      // A failed freeze cannot authorize a capture from an unchecked page.
      await cdp.send('Page.setWebLifecycleState',{state:'frozen'},session);
      after = await capture(command.target);
      const tree = await cdp.send('DOM.getDocument',{depth:-1,pierce:true},session);
      if (!safeScreenshotTree(tree.root)) throw new Error('unsupported_opaque_capture');
      if (after.opaque) throw new Error('unsupported_opaque_capture');
      const shot = await cdp.send('Page.captureScreenshot',{format:'png',fromSurface:true,captureBeyondViewport:false,
        clip:{x:0,y:0,width:1280,height:960,scale:1}},session);
      if (Buffer.from(shot.data,'base64').length>PNG_LIMIT) throw new Error('screenshot_limit');
      screenshot=shot.data;
    }
    result={kind:'result',action_id:active.id,ok:true,dom_before:before.html,dom_after:after.html,
      screenshot,opaque:after.opaque,denied:active.denied};
  } catch(error) {
    const safe=['readiness_limit','readiness_unavailable','navigation_unready','dom_limit','page_identity_mismatch',
      'unsupported_opaque_capture','screenshot_limit','locator_not_unique','element_outside_viewport','unsupported_input','unsupported_option','action_deadline'];
    result={kind:'result',action_id:active.id,ok:false,reason:'browser_action_failed',denied:active.denied,
      dom_before:before?.html??null,dom_after:after?.html??null,screenshot:null,
      diagnostic:{code:safe.includes(error.message)?error.message:'bridge_action_failed',phase:active.phase,
        loading_count:active.loading.size,pending_count:[...pendingNetwork.values()].filter(x=>x.actionId===active.id).length,
        dom_ready:active.ready,network_seen:active.seen,frame_started:active.frameStarted,frame_completed:active.frameCompleted,
        network_finished:active.finished,unmatched_finished:active.unmatchedFinished}};
  } finally {
    clearTimeout(deadline); active.closed=true;
    await freeze(); active=null;
  }
  emit(result);
}

async function boot(configuration) {
  if (!exact(configuration,['kind','schema','platform','browser_sandbox_policy']) || configuration.schema!==1 ||
      configuration.platform!=='linux/arm64'||configuration.browser_sandbox_policy!=='chromium-userns'||
      process.platform!=='linux'||process.arch!=='arm64'||process.getuid()===0||
      process.env.CHROME_NO_SANDBOX==='1'||process.env.CHROME_SOFTWARE_WEBGL==='1'||
      Object.keys(process.env).some(key=>key.startsWith('PI_APP_'))||Number(process.versions.node.split('.')[0])!==24) throw new Error('runtime_mismatch');
  let proxyRequests=0;
  proxy=net.createServer(socket=>{
    if(++proxyRequests>1000){socket.destroy();stop('proxy_limit');return;}
    socket.end('HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');
  });
  await new Promise((resolve,reject)=>{proxy.once('error',reject);proxy.listen(0,'127.0.0.1',resolve);});
  const options=browserOptions({args:[]});
  const flags=['--headless=new','--remote-debugging-pipe','--no-startup-window','--no-first-run','--no-default-browser-check',
    '--disable-extensions','--disable-background-networking','--disable-component-update','--disable-sync','--disable-default-apps',
    '--disable-client-side-phishing-detection','--disable-quic','--dns-prefetch-disable','--host-resolver-rules=MAP * ~NOTFOUND',
    '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',`--proxy-server=http://127.0.0.1:${proxy.address().port}`,
    '--proxy-bypass-list=<-loopback>',`--user-data-dir=${options.userDataDir}`,...options.args];
  if(flags.some(x=>/^--(?:no-sandbox|disable-.*sandbox|single-process|use-gl|use-angle|enable-unsafe-swiftshader)/.test(x))) throw new Error('sandbox_policy_invalid');
  browser=spawn(options.executablePath,flags,{stdio:['ignore','ignore','pipe','pipe','pipe'],env:process.env});
  let stderrBytes=0;
  browser.stderr.on('data',bytes=>{stderrBytes+=bytes.length;if(stderrBytes>65536)stop('browser_log_limit');});
  cdp=new CDP(browser);
  const version=await cdp.send('Browser.getVersion');
  await cdp.send('Target.setDiscoverTargets',{discover:true});
  await cdp.send('Target.setAutoAttach',{autoAttach:true,waitForDebuggerOnStart:true,flatten:true});
  context=(await cdp.send('Target.createBrowserContext',{disposeOnDetach:true})).browserContextId;
  await cdp.send('Browser.setDownloadBehavior',{behavior:'deny',browserContextId:context,eventsEnabled:true});
  await cdp.send('Target.createTarget',{url:'about:blank',browserContextId:context,width:1280,height:960});
  const end=Date.now()+10000;
  while(!mainReady && Date.now()<end) await delay(10); // Internal target setup, never application polling.
  if(!mainReady)throw new Error('page_unavailable');
  await cdp.send('Target.activateTarget',{targetId});
  await cdp.send('Page.bringToFront',{},session);
  await freeze();
  emit({kind:'ready',schema:1,platform:'linux/arm64',browser:version.product,protocol_version:version.protocolVersion});
}

let booted=false;
const input=readline.createInterface({input:process.stdin,crlfDelay:Infinity});
input.on('line',line=>{
  if(Buffer.byteLength(line)>2*1024*1024){stop('ipc_limit');return;}
  let message;try{message=JSON.parse(line);}catch{stop('ipc_invalid');return;}
  (async()=>{
    if(!booted){booted=true;await boot(message);return;}
    if(message.kind==='action'){await runAction(message);return;}
    if(message.kind==='effect_ack'&&active&&message.action_id===active.id&&active.boundary){active.boundary.resolve();active.boundary=null;return;}
    if(message.kind==='response'){
      const row=pendingNetwork.get(message.request_id);
      if(!row||!active||row.actionId!==active.id||message.action_id!==active.id)throw Error('request_binding_invalid');
      pendingNetwork.delete(message.request_id);
      if(message.ok!==true){await failRequest(row.session,row.requestId);}
      else {
        const body=Buffer.from(message.body_base64,'base64');
        if(body.length>1048576||!Array.isArray(message.headers)||message.headers.length>8||!Number.isInteger(message.status)||message.status<200||message.status>299)throw Error('response_invalid');
        await cdp.send('Fetch.fulfillRequest',{requestId:row.requestId,responseCode:message.status,responseHeaders:message.headers,body:message.body_base64},row.session);
      }
      if(message.abort===true){active.closed=true;await freeze();}
      if(active?.waiter)active.waiter();
      return;
    }
    if(message.kind==='close'){fatal=true;await freeze();try{await cdp.send('Browser.close');}catch{}proxy.close();if(browser.exitCode===null)browser.kill('SIGTERM');process.exit(0);}
    else throw Error('ipc_invalid');
  })().catch(()=>stop('browser_capability_unavailable'));
});
input.on('close',()=>{if(browser&&browser.exitCode===null)browser.kill('SIGKILL');if(proxy)proxy.close();});
