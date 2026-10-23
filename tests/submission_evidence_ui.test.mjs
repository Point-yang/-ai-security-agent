import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import {publishedEvidenceView} from '../src/zhidu/static/submission-evidence-ui.js';
import {DEMO_IDENTIFIER,TASK_PRESETS} from '../src/zhidu/static/workspace-console.js';

const evidence=JSON.parse(readFileSync(new URL('../config/submission-evidence.json',import.meta.url),'utf8'));
test('frozen enrichment and small complex QA results retain distinct scopes and true zero passes',()=>{
  const before=JSON.stringify(evidence);
  const view=publishedEvidenceView({status:'available',...evidence});
  assert.equal(view.available,true);assert.equal(view.modes.length,3);
  assert.match(view.paragraphs.join('\n'),/AI 来源核验，不标记为人工审核/);
  assert.match(view.paragraphs.join('\n'),/24 条记录 \/ 99 项事实/);
  assert.match(view.paragraphs.join('\n'),/尚未证明 Agent 稳定优于普通 RAG/);
  assert.equal(view.modes[0].strict,'0 / 6（0.00%）');
  assert.equal(view.modes[1].strict,'2 / 6（33.33%）');
  assert.match(view.paragraphs.join('\n'),/总 token 与费用含未知项，不计作零/);
  assert.equal(JSON.stringify(evidence),before);
});

test('missing or unrecognized published evidence never fabricates scores',()=>{
  for(const data of [null,{}, {status:'unavailable',reason:'missing'}, {...evidence,status:'available',schema_version:'future-contract'}]) {
    const view=publishedEvidenceView(data);
    assert.equal(view.available,false);assert.deepEqual(view.modes,[]);
    assert.match(view.paragraphs.join(''),/未知/);assert.doesNotMatch(view.paragraphs.join(''),/100%/);
  }
});

test('unknown and malformed numerical metrics remain unknown rather than becoming zero or NaN',()=>{
  const view=publishedEvidenceView({status:'available',schema_version:'submission-evidence-v1',
    enrichment:{records:null,facts:-1,precision:null,recall:'1'},
    complex_qa:{cases:6,modes:[{strict_passes:null,strict_accuracy:2,fact_recall:-1,mean_elapsed_ms:null}]}});
  assert.equal(view.modes[0].strict,'未知 / 6（未知）');
  assert.equal(view.modes[0].recall,'未知');assert.equal(view.modes[0].elapsed,'未记录');
  assert.doesNotMatch(view.paragraphs.join(''),/NaN|100\.00%|精确率 0/);
});

test('review source opening actually makes the reader view visible before loading the record',async()=>{
  const source=readFileSync(new URL('../src/zhidu/static/workspace.js',import.meta.url),'utf8');
  const section=source.slice(source.indexOf('function openSource(eventId) {'),source.indexOf('window.addEventListener(\'zhidu-source-example\''));
  const order=[];
  const context=vm.createContext({window:{dispatchEvent(event){order.push(event.detail.view);}},
    CustomEvent:class{constructor(type,{detail}){this.type=type;this.detail=detail;}},
    show(id){order.push(id);return Promise.resolve(id);}});
  vm.runInContext(section+'\nglobalThis.open=openSource;',context);
  await context.open('source-event');assert.deepEqual(order,['intelligence','source-event']);
});

test('source example opens real saved sources without automatically submitting a model task',()=>{
  const source=readFileSync(new URL('../src/zhidu/static/workspace.js',import.meta.url),'utf8');
  const section=source.slice(source.indexOf('window.addEventListener(\'zhidu-source-example\''),source.indexOf('function showAssetSummary()'));
  const elements=new Map(),listeners=new Map();let loads=0;
  const $=id=>{if(!elements.has(id))elements.set(id,{value:'old filter',checked:true});return elements.get(id);};
  const context=vm.createContext({$,window:{addEventListener(name,handler){listeners.set(name,handler);}},modeChanged(){loads++;}});
  vm.runInContext(section,context);
  listeners.get('zhidu-source-example')({detail:{identifier:DEMO_IDENTIFIER}});
  assert.equal($('alias').value,'CVE-2026-73557');assert.equal($('mode').value,'events');
  for(const id of ['query','package','severity','source','kind'])assert.equal($(id).value,'');
  assert.equal($('withdrawn').checked,false);assert.equal(loads,1);
  assert.match(TASK_PRESETS.compare,/GitHub、NVD 与厂商公告/);assert.match(TASK_PRESETS.compare,/CVE-2026-73557/);
});

test('a workspace opens a new task instead of silently inheriting a saved conversation and asset',async()=>{
  const source=readFileSync(new URL('../src/zhidu/static/workspace-week6.js',import.meta.url),'utf8');
  const section=source.slice(source.indexOf('async function conversations('),source.indexOf('async function history()'));
  const control={value:'',replaceChildren(){},append(){}};
  const context=vm.createContext({el:()=>control,read:async()=>[{id:'old-private-context',title:'saved task',message_count:8}],Option:class{}});
  vm.runInContext(section+'\nglobalThis.loadConversations=conversations;',context);
  await context.loadConversations();assert.equal(control.value,'');
  await context.loadConversations('old-private-context');assert.equal(control.value,'old-private-context');
  await context.loadConversations('deleted-task');assert.equal(control.value,'');
});
