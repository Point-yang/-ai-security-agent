import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

const source=readFileSync(new URL('../src/zhidu/static/workspace-week6.js',import.meta.url),'utf8');
const html=readFileSync(new URL('../src/zhidu/static/workspace.html',import.meta.url),'utf8');
const start=source.indexOf('function applyAgentGeneration(body) {');
const end=source.indexOf('// End Agent selection mapping.',start);
assert.ok(start>=0 && end>start);
const applyAgentGeneration=new Function(source.slice(start,end)+'\nreturn applyAgentGeneration;')();

test('the original control explicitly selects legacy after the service default changed',()=>{
  assert.match(html,/<option value="agent_legacy">原 Agent 工具选择（对照）<\/option>/);
  assert.deepEqual(applyAgentGeneration({generation:'agent_legacy'}),{generation:'agent',agent_backend:'legacy'});
  assert.doesNotMatch(html,/<option value="agent">原 Agent/);
});

test('every explicit Agent option passes its own backend to the API',()=>{
  for(const backend of ['legacy','langchain','workflow','auto','team']) {
    assert.match(html,new RegExp(`<option value="agent_${backend}">`));
    assert.deepEqual(applyAgentGeneration({generation:`agent_${backend}`,question:'Q'}),{generation:'agent',agent_backend:backend,question:'Q'});
  }
  assert.match(source,/applyAgentGeneration\(body\);/);
});

test('ordinary model and extractive choices retain their generation method',()=>{
  for(const generation of ['configured','deepseek','model','extractive','agent']) {
    assert.deepEqual(applyAgentGeneration({generation}),{generation});
  }
});

test('the recommended first option remains workflow',()=>{
  assert.match(html,/id="rag-generation"><option value="agent_workflow">/);
});
