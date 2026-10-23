import test from 'node:test';
import assert from 'node:assert/strict';
import {errorType, gapsFor, summarize, sourceNotices, overviewText} from '../src/zhidu/static/monitoring-ui.js';

test('counts preserve successful but stale states and sanitize network errors',()=>{
  const monitoring={targets:[{id:'a',enabled:true,status:'completed'},{id:'b',enabled:true,status:'failed'}]};
  const operations={collection:{targets:[{id:'a',fresh_within_two_intervals:false},{id:'b',fresh_within_two_intervals:false}]}};
  const summary=summarize(monitoring,operations);
  assert.deepEqual([summary.total,summary.successful,summary.failed,summary.stale],[2,1,1,2]);
  assert.equal(errorType('nvd: network failure after 3 attempts (ConnectTimeout) https://secret:token@proxy'), 'ConnectTimeout');
  assert.equal(errorType('private secret arbitrary error'), '来源处理失败（详情已脱敏）');
  assert.equal(summarize(monitoring,null).stale,null);
  assert.match(overviewText({monitoring,operations:null}),/当前超期 未验证/);
});
test('stale and replay warnings do not change citation hashes',()=>{
  const citations=[{source_id:'github-advisories',origin:'live',revision:2,sha256:'immutable'}];
  const before=JSON.stringify(citations);
  const monitoring={targets:[{id:'ghsa',enabled:true,source_id:'github-advisories',last_success_at:'2026-10-04T01:00:00Z'}]};
  const state=fresh=>({collection:{targets:[{id:'ghsa',fresh_within_two_intervals:fresh}]}});
  assert.match(sourceNotices(citations,monitoring,state(false))[0].text,/资料截至上次成功采集；最新状态未验证/);
  assert.match(sourceNotices(citations,monitoring,state(true))[0].text,/引用仅代表所示版本/);
  assert.equal(JSON.stringify(citations),before);
  assert.match(sourceNotices([{...citations[0],origin:'replay'}],monitoring,state(true))[0].text,/replay 回放资料/);
});
test('coverage complements retained successful intervals into actual gaps',()=>{
  const report={window_start:'2026-10-04T00:00:00Z',window_end:'2026-10-05T00:00:00Z'};
  const gaps=gapsFor(report,{intervals:[{from:'2026-10-04T12:00:00Z',to:'2026-10-05T00:00:00Z'}]});
  assert.equal(gaps.length,1);assert.equal(gaps[0].to,'2026-10-04T12:00:00.000Z');
});
