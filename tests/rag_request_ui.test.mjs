import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';

const source=readFileSync(new URL('../src/zhidu/static/workspace-week6.js',import.meta.url),'utf8');
const mapping=source.slice(source.indexOf('function applyAgentGeneration(body) {'),source.indexOf('// End Agent selection mapping.'));
const state=source.slice(source.indexOf('let pendingRequest = null;'),source.indexOf('async function conversations('));
const handlers=source.slice(source.indexOf('function emitRunState('),source.indexOf('\nPromise.all([conversations().then(history)'));
assert.ok(mapping && state && handlers);

function harness(options={}) {
  const elements=new Map(),requests=[],events=[],renders=[],listeners=new Map();
  let uuidCount=0;
  const faults={render:false,monitor:false,history:false,conversation:false,...options.faults};
  const answer={id:'saved-run',answer_class:'evidence',answer:'server result',generation:{status:'completed'},cost:{external_requests:1,billed_tokens:15},...options.answer};
  const el=id=>{
    if(!elements.has(id)) elements.set(id,{value:'',textContent:'',hidden:true,disabled:false,
      append(){},prepend(){},replaceChildren(){},focus(){},closest(){return {};}});
    return elements.get(id);
  };
  el('rag-question').value='original question';el('rag-query').value='original query';
  el('rag-generation').value='agent_team';el('rag-mode').value='hybrid';
  el('rag-conversation').value=options.newConversation ? '' : 'conversation-1';
  el('rag-key').value='mock-admin-key';
  const context=vm.createContext({
    el,crypto:{randomUUID(){uuidCount++;return 'request-'+uuidCount;}},performance:{now(){return 123;}},
    CustomEvent:class {constructor(type,{detail}){this.type=type;this.detail=detail;}},
    window:{dispatchEvent(event){events.push(event);},addEventListener(name,listener){listeners.set(name,listener);}},
    fetch:async(path,init)=>{
      const request={path,body:JSON.parse(init.body),key:init.headers['X-Admin-Key']};requests.push(request);
      const planned=options.response?.(request,requests) || {status:200,data:path==='/api/v1/conversations' ? {id:'conversation-created'} : answer};
      if(planned.throw) throw new Error(planned.throw);
      return {ok:planned.status>=200 && planned.status<300,status:planned.status,json:async()=>planned.data};
    },
    notice(id,text,state){el(id).textContent=text;el(id).className=state;},node(_tag,text){return {textContent:text};},
    renderAnswer(data){renders.push(data);if(faults.render)throw new Error('render failure');},
    async updateMonitoring(){if(faults.monitor)throw new Error('monitor failure');},
    async conversations(selected){if(faults.conversation)throw new Error('conversation failure');el('rag-conversation').value=selected || 'conversation-1';},
    async history(){if(faults.history)throw new Error('history failure');},Option:class {},
  });
  vm.runInContext(mapping+state+handlers+'\nglobalThis.inspectState=()=>({pendingRequest,completedReceipt,retryReceipt,sending});',context);
  el('rag-form').requestSubmit=()=>el('rag-form').onsubmit({preventDefault(){}});
  return {el,requests,events,renders,faults,answer,
    submit:()=>el('rag-form').requestSubmit(),retry:()=>el('rag-retry').onclick(),
    replay:data=>listeners.get('zhidu-receipt-replay')({detail:{data}}),
    snapshot:()=>JSON.parse(JSON.stringify(context.inspectState())),
    modelPosts:()=>requests.filter(r=>r.path==='/api/v1/rag/answers'),uuidCount:()=>uuidCount};
}

test('a render exception after a successful model POST only redisplays its saved local receipt',async()=>{
  const h=harness({faults:{render:true}});await h.submit();
  assert.equal(h.modelPosts().length,1);assert.equal(h.uuidCount(),1);
  assert.equal(h.snapshot().completedReceipt.id,'request-1');
  assert.equal(h.snapshot().completedReceipt.data.answer,'server result');
  assert.equal(h.snapshot().pendingRequest,null);
  assert.equal(h.el('rag-retry').textContent,'重新显示已保存结果');
  assert.equal(h.snapshot().sending,false);
  assert.doesNotMatch(JSON.stringify(h.snapshot().completedReceipt),/mock-admin-key/);
  await h.retry();assert.equal(h.modelPosts().length,1);assert.equal(h.uuidCount(),1);
  h.faults.render=false;await h.retry();
  assert.equal(h.modelPosts().length,1);
  const displayed=h.renders.at(-1);
  assert.equal(displayed.local_receipt_display,true);
  assert.equal(displayed.cost.current_attempt_external_requests,0);
  assert.equal(displayed.cost.external_requests,1);
  assert.equal(h.snapshot().completedReceipt.data.cost.current_attempt_external_requests,undefined);
});

for(const failure of ['monitor','history','conversation']) {
  test(`a ${failure} failure after receipt cannot create another paid POST`,async()=>{
    const h=harness({faults:{[failure]:true}});await h.submit();
    assert.equal(h.modelPosts().length,1);assert.equal(h.snapshot().completedReceipt.id,'request-1');
    await h.retry();assert.equal(h.modelPosts().length,1);assert.equal(h.uuidCount(),1);
    assert.equal(h.renders.at(-1).local_receipt_display,true);
  });
}

test('a known generation fallback retry displays the same receipt without resubmitting',async()=>{
  const h=harness({answer:{generation:{status:'fallback',reason:'invalid_claim_text'}}});await h.submit();
  assert.equal(h.el('rag-retry').hidden,false);
  assert.equal(h.el('rag-retry').textContent,'重新显示已保存结果');
  await h.retry();assert.equal(h.modelPosts().length,1);
});

test('unknown model outcome retries the exact original body and request ID despite form changes',async()=>{
  const h=harness({answer:{generation:{status:'fallback',reason:'model_request_outcome_unknown'}}});
  await h.submit();const first=h.modelPosts()[0].body;
  assert.equal(h.el('rag-retry').textContent,'读取原请求结果');
  h.el('rag-query').value='a different query';h.el('rag-event').value='changed-event';
  h.el('rag-generation').value='agent_workflow';h.el('rag-question').value='changed question';
  h.el('rag-key').value='replacement-admin-key';
  await h.retry();
  assert.equal(h.modelPosts().length,2);assert.deepEqual(h.modelPosts()[1].body,first);
  assert.equal(h.modelPosts()[1].key,'replacement-admin-key');assert.equal(h.uuidCount(),1);
});

test('a model POST connection failure keeps the original request ID for explicit record lookup',async()=>{
  let failed=false;
  const h=harness({response(request){if(request.path==='/api/v1/rag/answers' && !failed){failed=true;return {throw:'connection lost'};}}});
  await h.submit();assert.equal(h.snapshot().completedReceipt,null);
  const first=h.modelPosts()[0].body;
  h.el('rag-query').value='rendered query changed';await h.retry();
  assert.deepEqual(h.modelPosts()[1].body,first);assert.equal(h.uuidCount(),1);
});

test('conversation creation 401 has no model request or request ID and permits correcting the key',async()=>{
  let unauthorized=true;
  const h=harness({newConversation:true,response(request){
    if(request.path==='/api/v1/conversations' && unauthorized)return {status:401,data:{detail:'unauthorized'}};
  }});
  await h.submit();assert.equal(h.modelPosts().length,0);assert.equal(h.uuidCount(),0);
  assert.equal(h.snapshot().pendingRequest,null);assert.equal(h.snapshot().retryReceipt,null);
  assert.equal(h.el('rag-retry').textContent,'重新提交本轮');
  unauthorized=false;h.el('rag-key').value='corrected-admin-key';await h.retry();
  assert.equal(h.modelPosts().length,1);assert.equal(h.uuidCount(),1);
  assert.equal(h.modelPosts()[0].body.conversation_id,'conversation-created');
});

test('a previous receipt cannot hijack retry when a later conversation creation fails authentication',async()=>{
  let unauthorized=false;
  const h=harness({response(request){if(request.path==='/api/v1/conversations' && unauthorized)return {status:401,data:{detail:'unauthorized'}};}});
  await h.submit();assert.equal(h.snapshot().completedReceipt.id,'request-1');
  unauthorized=true;h.el('rag-conversation').value='';await h.submit();
  assert.equal(h.snapshot().retryReceipt,null);assert.equal(h.modelPosts().length,1);
  unauthorized=false;h.el('rag-key').value='corrected-admin-key';await h.retry();
  assert.equal(h.modelPosts().length,2);assert.equal(h.modelPosts()[1].body.request_id,'request-2');
});

test('received response is saved before the completed event and separate from event consumers',async()=>{
  const h=harness();await h.submit();
  const event=h.events.find(e=>e.type==='zhidu-run-state' && e.detail.phase==='completed');
  assert.ok(event);event.detail.data.answer='mutated by display consumer';
  assert.equal(h.snapshot().completedReceipt.data.answer,'server result');
  assert.equal(event.detail.request_id,h.snapshot().completedReceipt.id);
});

test('historical receipt replay makes no POST, changes no conversation, and preserves recorded costs',()=>{
  const h=harness();const conversation=h.el('rag-conversation').value;
  const data={historical_replay:true,answer:'historical evidence',answer_class:'partial',generation:{status:'completed'},cost:{external_requests:5,billed_tokens:123,monetary:{status:'confirmed'}},citations:[{origin:'replay',original_origin:'live',text:'exact citation'}]};
  const original=JSON.stringify(data);h.replay(data);
  assert.equal(h.requests.length,0);assert.equal(h.uuidCount(),0);
  assert.equal(h.el('rag-conversation').value,conversation);assert.equal(h.snapshot().completedReceipt,null);
  assert.equal(h.el('rag-retry').hidden,true);
  const event=h.events.at(-1);
  assert.equal(event.detail.phase,'completed');assert.equal(event.detail.historical_replay,true);
  assert.equal(event.detail.data.deduplicated,false);assert.equal(event.detail.data.cost.external_requests,5);
  assert.equal(event.detail.data.cost.current_attempt_external_requests,0);
  assert.equal(event.detail.data.citations[0].text,'exact citation');assert.equal(JSON.stringify(data),original);
});

test('historical replay is ignored while a current POST is running',async()=>{
  let h;
  h=harness({response(request){
    if(request.path==='/api/v1/rag/answers')h.replay({historical_replay:true,answer:'must not replace current result'});
  }});
  await h.submit();assert.equal(h.modelPosts().length,1);
  assert.ok(!h.renders.some(data=>data.historical_replay));
  assert.equal(h.snapshot().completedReceipt.data.answer,'server result');
});

test('historical replay cannot overwrite a pending unknown outcome or its request ID',async()=>{
  const h=harness({answer:{generation:{status:'fallback',reason:'model_request_outcome_unknown'}}});await h.submit();
  const pending=h.snapshot().pendingRequest;const count=h.renders.length;
  h.replay({historical_replay:true,answer:'must not overwrite unknown request'});
  assert.deepEqual(h.snapshot().pendingRequest,pending);assert.equal(h.renders.length,count);
  assert.equal(h.modelPosts().length,1);
});

test('a historical replay display error cannot expose a submit-model retry action',()=>{
  const h=harness({faults:{render:true}});h.replay({historical_replay:true,answer:'historical'});
  assert.equal(h.requests.length,0);assert.equal(h.el('rag-retry').hidden,true);
  assert.equal(h.events.at(-1).detail.historical_replay,true);
});
