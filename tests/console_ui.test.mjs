import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {knownNumber,receiptSummary,roleReceipts,sourceState} from '../src/zhidu/static/workspace-console.js';

test('missing telemetry stays unknown and negative or nonnumeric values are rejected',()=>{
  for(const value of [null,undefined,'0',NaN,Infinity,-1])assert.equal(knownNumber(value),null);
  assert.equal(knownNumber(0),0);
  const summary=receiptSummary({});
  assert.equal(summary.currentCalls,null);assert.equal(summary.toolCalls,null);assert.equal(summary.verified,null);
});

test('unrecorded roles do not become invented completed stages',()=>{
  for(const item of Object.values(roleReceipts()))assert.deepEqual(item,{status:'unrecorded',label:'未记录',calls:0});
  const roles=roleReceipts([{role:'planner',status:'completed'},{role:'researcher',status:'uncertain',error:'unknown'}]);
  assert.equal(roles.planner.status,'completed');assert.equal(roles.researcher.status,'failed');
  assert.equal(roles.composer.status,'unrecorded');assert.equal(roles.verifier.status,'unrecorded');
});

test('paid validation failures count as returned but blocked, not successful role output',()=>{
  const value=roleReceipts([{role:'composer',status:'completed',error:'invalid_role_response'}]);
  assert.equal(value.composer.label,'输出受阻');assert.equal(value.composer.calls,1);
});

test('replay separates original model calls from this display without mutating the receipt',()=>{
  const data={historical_replay:true,cost:{external_requests:5,current_attempt_external_requests:0},tools:[],citations:[{}],elapsed_ms:15000};
  const before=structuredClone(data),summary=receiptSummary(data);
  assert.equal(summary.originalCalls,5);assert.equal(summary.currentCalls,0);assert.equal(summary.replay,true);
  assert.equal(summary.citations,1);assert.equal(summary.verified,null);assert.deepEqual(data,before);
});

test('source freshness only uses actual collection counters',()=>{
  assert.deepEqual(sourceState(),{fresh:null,total:null});
  assert.deepEqual(sourceState({collection:{targets_fresh:9,configured_targets:10}}),{fresh:9,total:10});
  assert.deepEqual(sourceState({enrichment:{coverage:1}}),{fresh:null,total:null});
});

test('historical demonstration has an original hash, exact source quotes, zero new requests and a visible known gap',()=>{
  const demo=JSON.parse(readFileSync(new URL('../src/zhidu/static/console-receipt-onnx.json',import.meta.url),'utf8'));
  assert.match(demo.source_artifact_sha256,/^[a-f0-9]{64}$/);
  assert.equal(demo.data.historical_replay,true);assert.equal(demo.data.cost.current_attempt_external_requests,0);
  assert.ok(demo.data.cost.external_requests>0);assert.equal(demo.known_gap,'onnx-untrusted-model-scope');
  assert.match(demo.data.historical_notice,/非当前新生成/);
  for(const claim of demo.data.generated_claims)for(const ref of claim.evidence)assert.equal(ref.quote,demo.data.citations[ref.citation-1].text);
  assert.ok(demo.data.citations.every(c=>c.origin==='replay' && c.original_origin==='live'));
});

test('console HTML retains original functional ids, details scope, UTF8 and the service entry',()=>{
  const html=readFileSync(new URL('../src/zhidu/static/workspace.html',import.meta.url),'utf8');
  assert.match(html,/<meta charset="utf-8">/);assert.doesNotMatch(html,/\uFFFD/);
  assert.match(html,/location\.protocol==='file:'.*location\.replace\('http:\/\/127\.0\.0\.1:8010\/workspace'\)/);
  const ids=[...html.matchAll(/\bid="([^"]+)"/g)].map(m=>m[1]);assert.equal(new Set(ids).size,ids.length);
  for(const id of ['rag-form','rag-question','rag-key','rag-generation','rag-mode','rag-event','rag-conversation','search','events','detail','evidence','review-queue','comparisons','asset-context','conversation-select','audits','rag-evaluations'])assert.ok(ids.includes(id),id);
  assert.match(html,/<details class="rag-options">[\s\S]*id="rag-event"[\s\S]*?<\/details>/);
});
