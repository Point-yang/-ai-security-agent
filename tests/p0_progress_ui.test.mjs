import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const source=readFileSync(new URL('../src/zhidu/static/workspace-week6.js',import.meta.url),'utf8');
const start=source.indexOf('function p0ProgressLines(data) {');
const end=source.indexOf('// End P0 progress presentation.',start);
assert.ok(start>=0 && end>start);
const p0ProgressLines=new Function(source.slice(start,end)+'\nreturn p0ProgressLines;')();
const known=chars=>({status:'known',new_source_chars:chars});

function fixture() {
  return {answer_class:'partial',requirement_ledger:{complete:false,tasks:[{
    task_id:'trust',requirement:'说明不可信输入的联合暴露条件',status:'partial',source_policy:'any',source_ids:['github-advisories'],
    element_coverage:[{element:'不可信结构化输入',status:'covered'},{element:'未规范化为惰性数据',status:'missing'}],
  }],unplanned_requirements:[]},question_coverage:{complete:false,remaining_answer_requirements:['load() 的窄 allowlist 边界']},
  claim_support:[{status:'supported',retained:true}],evidence_novelty:{logical:known(153),current_attempt:known(23)},
  batch_tool_calls:[{call_id:'research:1:0',action:'batch',admission:{admitted:[{child_id:'batch-0'},{child_id:'batch-1'}],skipped:[{child_id:'batch-2'}]},
    tool_observations:[{child_id:'batch-0',actual_tool_attempts:0,replayed:true},{child_id:'batch-1',actual_tool_attempts:1,replayed:false}]}]};
}

test('partial completeness remains visible even when every retained claim is supported',()=>{
  const lines=p0ProgressLines(fixture()).join('\n');
  assert.match(lines,/内部 AI 完整性核查：未完整覆盖/);
  assert.match(lines,/部分覆盖（partial）/);
  assert.match(lines,/未规范化为惰性数据/);
  assert.match(lines,/load\(\) 的窄 allowlist 边界/);
  assert.doesNotMatch(lines,/已覆盖本轮记录的要求/);
  assert.match(lines,/不是独立金标或准确率/);
});

test('every source policy is explained in Chinese and all task states are retained',()=>{
  const data=fixture();data.requirement_ledger.tasks=[
    {task_id:'a',requirement:'单源机制',status:'covered',source_policy:'any'},
    {task_id:'b',requirement:'逐源范围',status:'partial',source_policy:'each'},
    {task_id:'c',requirement:'来源分歧',status:'missing',source_policy:'compare'},
  ];
  const lines=p0ProgressLines(data).join('\n');
  assert.match(lines,/已覆盖（covered）/);assert.match(lines,/部分覆盖（partial）/);assert.match(lines,/未回答（missing）/);
  assert.match(lines,/任一指定来源的自身引文可支持/);assert.match(lines,/每个指定来源分别覆盖/);assert.match(lines,/同一比较结论须引用双方/);
  const covered=fixture();covered.answer_class='evidence';covered.requirement_ledger.complete=true;
  covered.question_coverage={complete:true};covered.requirement_ledger.tasks=[{
    task_id:'any',requirement:'单源机制',status:'covered',source_policy:'any',
    source_check:{sufficient:true,observed:['github-advisories'],missing:['nvd']},
  }];
  const optional=p0ProgressLines(covered).join('\n');
  assert.match(optional,/已覆盖本轮记录的要求/);assert.match(optional,/尚未引用的候选来源：nvd/);
  assert.doesNotMatch(optional,/引文尚未覆盖的指定来源：nvd/);
});

test('unknown or unrecorded provenance never displays a fabricated zero increment',()=>{
  for(const status of ['unknown','unrecorded']) {
    const data=fixture();data.evidence_novelty.current_attempt={status,new_source_chars:null,known_new_source_chars:999};
    const lines=p0ProgressLines(data).join('\n');
    assert.match(lines,/本次新增原文覆盖：未知/);
    assert.doesNotMatch(lines,/本次新增原文覆盖：0/);assert.doesNotMatch(lines,/999 字符/);
  }
});

test('deduplication, local redisplay and historical replay set only current metrics to zero',()=>{
  for(const flag of ['deduplicated','local_receipt_display','historical_replay']) {
    const data=fixture();data[flag]=true;const before=JSON.stringify(data);
    const lines=p0ProgressLines(data).join('\n');
    assert.match(lines,/本次新增原文覆盖：0 字符（本次仅回放）/);
    assert.match(lines,/本次研究工具实际尝试：0 次（本次仅回放）/);
    assert.match(lines,/原轮逻辑新增原文覆盖：153 字符/);
    assert.equal(JSON.stringify(data),before);
  }
});

test('actual child attempts count only recorded execution and never skipped admission',()=>{
  const data=fixture();data.batch_tool_calls.push(structuredClone(data.batch_tool_calls[0]));
  const lines=p0ProgressLines(data).join('\n');
  assert.match(lines,/本次研究工具实际尝试：1 次/);
  assert.doesNotMatch(lines,/本次研究工具实际尝试：2 次/);
  assert.match(lines,/未获预算准入，未计为已执行/);
  assert.match(lines,/本次新增原文覆盖：23 字符/);
  assert.match(lines,/不代表新增事实或 Agent 增益/);
});

test('missing child receipts or attempt telemetry stay unknown rather than inferred as one or zero',()=>{
  const data=fixture();delete data.batch_tool_calls[0].tool_observations[1].actual_tool_attempts;
  assert.match(p0ProgressLines(data).join('\n'),/本次研究工具实际尝试：未知/);
  data.batch_tool_calls[0].tool_observations=[];
  assert.match(p0ProgressLines(data).join('\n'),/另有 2 项缺回执/);
});

test('old records without P0 data have no invented complete indicator',()=>{
  assert.deepEqual(p0ProgressLines({answer_class:'evidence',answer:'old result'}),[]);
  const lines=p0ProgressLines({evidence_novelty:{logical:known(0),current_attempt:{status:'unrecorded'}}}).join('\n');
  assert.match(lines,/内部 AI 完整性核查：未知（未记录）/);
  assert.match(lines,/本次研究工具实际尝试：未知/);
  assert.doesNotMatch(lines,/已覆盖本轮记录的要求/);
});

test('a semantic covered label cannot conceal missing structural proof',()=>{
  const data=fixture();data.answer_class='evidence';data.question_coverage={complete:true};
  data.requirement_ledger={complete:true,tasks:[{task_id:'all',status:'covered',source_policy:'any',
    requirement:'完整条件',context_check:{required:true,sufficient:false}}]};
  const lines=p0ProgressLines(data).join('\n');
  assert.match(lines,/内部 AI 完整性核查：未完整覆盖/);
  assert.match(lines,/完整结构引用尚未确认/);
  data.requirement_ledger.tasks[0].context_check.sufficient=true;
  assert.match(p0ProgressLines(data).join('\n'),/是否答完整仍需逐项语义核查/);
});

test('structure-only review gaps do not invent a missing answer condition',()=>{
  const data=fixture();data.question_coverage={complete:false,remaining_answer_requirements:['完整结构引用待补核：完整条件']};
  data.requirement_ledger={complete:false,tasks:[{task_id:'all',status:'partial',semantic_status:'covered',context_only:true,
    source_policy:'any',requirement:'完整条件',context_check:{required:true,sufficient:false},
    element_coverage:[{element:'全部联合条件',status:'covered'}]}]};
  const lines=p0ProgressLines(data).join('\n');
  assert.match(lines,/正文已覆盖，结构引用待核（partial）/);
  assert.match(lines,/未据此判定具体条件漏答/);
  assert.doesNotMatch(lines,/遗漏或未完整回答的条件|具体条件未记录/);
  assert.match(lines,/仍待回答或补核/);
  delete data.requirement_ledger.tasks[0].semantic_status;
  assert.doesNotMatch(p0ProgressLines(data).join('\n'),/正文已覆盖，结构引用待核/);
});

test('read allocation skips are not falsely described as spent calls or budget failures',()=>{
  const data=fixture();data.batch_tool_calls=[{call_id:'r',action:'read_plan',admission:{admitted:[],
    skipped:[{reason:'all_requested_fields_known_missing'}],feedback:[{code:'missing_task_ids'}],
    allocation:{audit:[{action:'deferred_containing_context'}]}},tool_observations:[]}];
  const lines=p0ProgressLines(data).join('\n');
  assert.match(lines,/本次研究工具实际尝试：0 次/);
  assert.match(lines,/字段不可读、已有原文或重叠选择/);
  assert.match(lines,/被暂缓的范围未计为已读/);
  assert.match(lines,/阅读意图不等于答案完整性/);
  assert.match(lines,/该计划未执行读取/);
  assert.doesNotMatch(lines,/未获预算准入/);
});
