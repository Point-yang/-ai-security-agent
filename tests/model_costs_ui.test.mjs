import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

// Extract the pure function, avoiding document/fetch side effects in the page.
const source=readFileSync(new URL('../src/zhidu/static/workspace-week6.js',import.meta.url),'utf8');
const start=source.indexOf('function modelCostText(data) {');
const end=source.indexOf('// End model cost presentation.',start);
assert.ok(start>=0 && end>start);
const modelCostText=new Function(source.slice(start,end)+'\nreturn modelCostText;')();
const money=(status,values)=>({cost:{external_requests:1,monetary:{status,...values}}});

test('confirmed token prices and estimated single values have distinct labels',()=>{
  const confirmed=modelCostText(money('confirmed',{currency:'USD',amount:0.12}));
  assert.match(confirmed,/0\.12 USD/);
  assert.doesNotMatch(confirmed,/估算/);
  const estimated=modelCostText(money('estimated',{currency:'USD',amount:0.12}));
  assert.match(estimated,/0\.12 USD（估算）/);
  assert.match(estimated,/未换汇/);
  assert.match(estimated,/不代表发票金额/);
});

test('estimated ranges remain ranges and very small nonzero amounts do not round to zero',()=>{
  const interval=modelCostText(money('estimated',{currency:'USD',amount:null,amount_min:0.01,amount_max:0.02}));
  assert.match(interval,/0\.01–0\.02 USD（估算）/);
  const tiny=modelCostText(money('confirmed',{currency:'USD',amount:0.000000009,amount_decimal:'0.000000009'}));
  assert.match(tiny,/0\.000000009 USD/);
  assert.doesNotMatch(tiny,/0\.000000 USD/);
});

test('unknown calls retain a known subtotal and never expose it as the complete total',()=>{
  const result=modelCostText(money('unknown',{unknown_calls:1,currency_totals:{USD:{
    complete:false,amount:null,priced_calls:5,unknown_calls:1,
    known_subtotal_min:0.006062964,known_subtotal_max:0.006062964,
  }}}));
  assert.match(result,/USD 已知小计 0\.006062964/);
  assert.match(result,/1 次调用费用未知；总额未知/);
  assert.doesNotMatch(result,/：0\.006062964 USD/);
});

test('incomplete mixed currencies show every currency and the global unknown count',()=>{
  const result=modelCostText(money('unknown',{unknown_calls:2,currency_totals:{
    USD:{complete:true,amount:0.1,amount_min:0.1,amount_max:0.1,priced_calls:1,known_subtotal_min:0.1,known_subtotal_max:0.1},
    CNY:{complete:false,amount:null,priced_calls:1,known_subtotal_min:0.2,known_subtotal_max:0.2},
  }}));
  assert.match(result,/USD 已知小计 0\.1/);
  assert.match(result,/CNY 已知小计 0\.2/);
  assert.match(result,/2 次调用费用未知；总额未知/);
  assert.doesNotMatch(result,/0\.3/);
});

test('fully unknown usage has no fabricated zero subtotal',()=>{
  const result=modelCostText(money('unknown',{unknown_calls:3,currency_totals:{USD:{
    complete:false,priced_calls:0,known_subtotal_min:0,known_subtotal_max:0,
  }}}));
  assert.match(result,/USD 暂无可计价小计/);
  assert.match(result,/3 次调用费用未知/);
  assert.doesNotMatch(result,/已知小计 0/);
  assert.match(modelCostText(money('unknown',{currency:'USD',amount:null})),/USD 费用未知/);
});

test('complete estimated currency totals still mark a single value as estimated',()=>{
  const result=modelCostText(money('estimated',{estimated_calls:1,unknown_calls:0,currency_totals:{USD:{
    complete:true,amount:0.1,amount_min:0.1,amount_max:0.1,
  }}}));
  assert.match(result,/0\.1 USD（估算）/);
});

test('explicit self-hosted zero prices remain distinguishable from absent prices',()=>{
  assert.match(modelCostText(money('confirmed',{currency:'CNY',amount:0})),/0 CNY/);
  assert.match(modelCostText({cost:{external_requests:1,api_usd:null}}),/费用未知/);
  assert.doesNotMatch(modelCostText({cost:{external_requests:1,api_usd:null}}),/0 USD/);
});

test('no dispatched model calls are explicitly free for the current attempt',()=>{
  assert.equal(modelCostText({cost:{external_requests:0}}),'本次未调用付费模型');
  assert.equal(modelCostText({cost:{external_requests:0,api_usd:0}}),'本次未调用付费模型');
});

test('a duplicate response labels prior pricing as history rather than a new charge',()=>{
  const input=money('confirmed',{currency:'USD',amount:0.12});
  input.deduplicated=true;
  input.cost.current_attempt_external_requests=0;
  const result=modelCostText(input);
  assert.match(result,/^本次未调用付费模型/);
  assert.match(result,/原轮次使用量计价（历史记录，不计作本次新增费用）/);
  assert.match(result,/0\.12 USD/);
});

test('checkpoint-only replay and partial resume separate this attempt from cumulative pricing',()=>{
  const replay=money('confirmed',{currency:'USD',amount:0.12});
  replay.cost.external_requests=5;
  replay.cost.current_attempt_external_requests=0;
  assert.match(modelCostText(replay),/^本次未调用付费模型；原轮次/);
  replay.cost.current_attempt_external_requests=2;
  const resumed=modelCostText(replay);
  assert.match(resumed,/^本次新增 2 次模型请求；本轮累计使用量计价/);
  assert.doesNotMatch(resumed,/本次未调用付费模型/);
});

test('legacy amounts and missing telemetry do not assert invoice confirmation',()=>{
  assert.match(modelCostText({cost:{external_requests:1,api_usd:0.2}}),/0\.2 USD（历史估算，计价明细未记录）/);
  assert.match(modelCostText({}),/费用未知/);
  assert.doesNotMatch(modelCostText(money('unknown',{currency:'USD',amount:9})),/9 USD/);
});

test('Agent token presentation uses the complete backend ledger instead of treating missing usage as zero',()=>{
  assert.match(source,/模型 token \$\{data\.cost\?\.billed_tokens \?\? '未完整返回'\}/);
  assert.doesNotMatch(source,/planner_usage\.reduce/);
});
