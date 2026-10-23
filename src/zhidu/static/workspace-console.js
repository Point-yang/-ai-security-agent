/* The observatory renders receipts, never guessed live model stages. */
export const VIEW_NAMES = {
  control:'Agent 指挥中心', intelligence:'情报与证据检索', review:'来源复核与比较',
  assets:'资产影响研判', archive:'会话与执行审计', evaluation:'系统状态与评测',
};
const ROLE_NAMES = {planner:'规划',researcher:'检索与补证',composer:'形成结论',verifier:'引文核验'};
const TOOL_NAMES = {retrieve:'检索来源',read_fields:'读取字段',event_details:'读取详情',compare_sources:'比较来源',asset_exposure:'资产条件判断',verify_evidence:'原文核验'};
export const DEMO_IDENTIFIER = 'CVE-2026-73557';
export const TASK_PRESETS = {
  compare:`比较 GitHub、NVD 与厂商公告对 ${DEMO_IDENTIFIER} 的受影响版本和修复版本表述，说明差异并逐项给出来源引用。`,
  conditions:'根据 GHSA-94f4-hr76-p5j6 的来源证据，说明受影响条件、版本范围与修复建议；保留来源中的限定词。',
  asset:'我的资产是否受影响？请结合我明确选择的组件版本和公告证据说明判断条件。',
};
export function knownNumber(value) {
  return typeof value==='number' && Number.isFinite(value) && value>=0 ? value : null;
}
export function receiptSummary(data={}) {
  const cost=data.cost || {}, agent=data.agent || {};
  const original=knownNumber(cost.external_requests), current=knownNumber(cost.current_attempt_external_requests);
  const check=agent.final_citation_check;
  return {
    toolCalls:knownNumber(data.tool_calls), originalCalls:original, currentCalls:current ?? original,
    citations:Array.isArray(data.citations) ? data.citations.length : null,
    verified:knownNumber(check?.verified), citationTotal:knownNumber(check?.total),
    elapsed:knownNumber(data.elapsed_ms),
    replay:data.historical_replay===true || data.deduplicated===true || (current===0 && original>0),
    roles:Array.isArray(agent.role_calls) ? agent.role_calls : [],
    tools:Array.isArray(data.tools) ? data.tools : [],
  };
}
export function roleReceipts(calls=[]) {
  return Object.fromEntries(Object.keys(ROLE_NAMES).map(role=>{
    const rows=calls.filter(call=>call.role===role);
    if(!rows.length) return [role,{status:'unrecorded',label:'未记录',calls:0}];
    const failed=rows.some(call=>call.error || !['completed','success'].includes(call.status));
    return [role,{status:failed ? 'failed' : 'completed',label:failed ? '输出受阻' : `已返回 · ${rows.length}`,calls:rows.length}];
  }));
}
export function sourceState(operations) {
  const collection=operations?.collection;
  return {fresh:knownNumber(collection?.targets_fresh),total:knownNumber(collection?.configured_targets)};
}

if(typeof document!=='undefined') {
  const el=id=>document.getElementById(id);
  const node=(tag,text,cls)=>{const n=document.createElement(tag);if(text!=null)n.textContent=text;if(cls)n.className=cls;return n;};
  const set=(id,text)=>{if(el(id))el(id).textContent=text;};
  const state={phase:'idle',started:0,timer:null,lastResult:null,system:{}};
  const number=value=>value==null ? '—' : value.toLocaleString('zh-CN');
  const seconds=value=>value==null ? '—' : `${(value/1000).toFixed(1)} s`;

  function showView(value,changeHash=false,focus=false) {
    const view=Object.hasOwn(VIEW_NAMES,value) ? value : 'control';
    document.querySelectorAll('.console-view').forEach(n=>{n.hidden=n.dataset.view!==view;});
    document.querySelectorAll('[data-nav]').forEach(n=>{
      const active=n.dataset.nav===view;n.classList.toggle('active',active);
      if(active)n.setAttribute('aria-current','page');else n.removeAttribute('aria-current');
    });
    set('console-view-title',VIEW_NAMES[view]);
    if(changeHash)history.replaceState(null,'',`#${view}`);
    if(focus) {
      const heading=document.querySelector(`.console-view[data-view="${view}"] h1`);
      if(heading){heading.tabIndex=-1;heading.focus({preventScroll:true});}
    }
  }
  document.querySelectorAll('[data-nav]').forEach(n=>{n.title=VIEW_NAMES[n.dataset.nav];n.addEventListener('click',event=>{event.preventDefault();showView(n.dataset.nav,true,true);window.scrollTo({top:0,behavior:'smooth'});});});
  window.addEventListener('hashchange',()=>showView(location.hash.slice(1),false,true));
  window.addEventListener('zhidu-open-view',event=>{showView(event.detail?.view,true,true);window.scrollTo({top:0,behavior:'smooth'});});
  document.querySelector('.skip-link').addEventListener('click',event=>{event.preventDefault();showView('control',true);el('rag-question').focus();});
  showView(location.hash.slice(1));

  document.querySelectorAll('[data-preset]').forEach(button=>button.addEventListener('click',()=>{
    el('rag-question').value=TASK_PRESETS[button.dataset.preset];el('rag-query').value='';el('rag-question').focus();
    document.querySelectorAll('[data-preset]').forEach(n=>n.classList.toggle('selected',n===button));
    if(button.dataset.preset==='asset'){el('rag-asset').closest('details').open=true;el('rag-asset').focus();}
  }));
  el('source-example').addEventListener('click',()=>{showView('intelligence',true,true);window.scrollTo({top:0,behavior:'smooth'});window.dispatchEvent(new CustomEvent('zhidu-source-example',{detail:{identifier:DEMO_IDENTIFIER}}));});
  el('local-example').addEventListener('click',()=>{
    el('rag-generation').value='extractive';el('rag-mode').value='lexical';
    el('rag-question').value=`请摘录 ${DEMO_IDENTIFIER} 当前来源中的受影响版本与修复信息。`;
    el('rag-query').value=DEMO_IDENTIFIER;describe();el('rag-question').focus();
    set('rag-conversation-status','已准备本地摘录示例，尚未提交。启动任务仍需本项目管理员密钥，用于保存会话。');
  });
  const descriptions={
    agent_workflow:'固定工作流收集证据后回答，适合稳定展示。',
    agent_team:'规划、研究、生成与核验协作，共享调用预算。实验策略，质量仍需核查。',
    agent_auto:'先收集必答字段；有证据缺口时交给 Agent 补查。实验策略。',
    agent_langchain:'模型根据工具结果选择只读工具，在预算内继续查询或结束。',
    agent_legacy:'使用原有有界工具编排，供对照观察。',
    extractive:'只显示已保存来源的原文摘录，不调用付费模型。',
    configured:'按服务配置生成回答，实际模型与调用以回执为准。',
    model:'检索当前来源后用配置模型回答，不启用多角色编排。',
    deepseek:'根据检索到的当前来源，用 DeepSeek 生成带引用回答。',
  };
  const describe=()=>set('strategy-description',descriptions[el('rag-generation').value] || '实际执行以服务回执为准。');
  el('rag-generation').addEventListener('change',describe);describe();
  el('console-refresh').addEventListener('click',()=>{el('week6-refresh').click();refreshHealth();});
  el('presentation-toggle').addEventListener('click',()=>{
    const active=document.body.classList.toggle('presentation-mode');
    el('presentation-toggle').setAttribute('aria-pressed',String(active));
    el('presentation-toggle').querySelector('span').textContent=active ? '退出答辩模式' : '答辩模式';
  });
  function mergeSystem(update) {
    for(const [key,value] of Object.entries(update || {}))if(value!==undefined)state.system[key]=value;
    const model=state.system.model;
    if(Object.hasOwn(state.system,'model')) {
      set('metric-chunks',number(knownNumber(model?.chunks)));
      set('metric-index-caption',model?.status==='ready' ? `${number(knownNumber(model.current_vectors))} 条向量就绪` : '索引状态未就绪或未验证');
      const gen=model?.generation;
      set('metric-model',gen?.model || (gen?.provider==='extractive' ? '本地摘录' : '—'));
      set('metric-model-caption',gen?.status==='configured' ? '已配置 · 连接由任务回执核验' : gen?.provider==='extractive' ? '不调用云端模型' : '模型配置尚未就绪');
    }
    const operations=state.system.operations || state.system.ops;
    const sources=sourceState(operations);
    set('metric-sources',`${number(sources.fresh)} / ${number(sources.total)}`);
    set('metric-source-caption',sources.fresh==null || sources.total==null ? '来源新鲜度未验证' : sources.fresh<sources.total ? `${sources.total-sources.fresh} 个目标当前超期` : '最近两个配置周期内成功采集');
    el('metric-sources').closest('.stat-card').classList.toggle('has-warning',sources.fresh!=null && sources.total!=null && sources.fresh<sources.total);
    if(operations?.enrichment?.events!=null)set('metric-events',number(knownNumber(operations.enrichment.events)));
  }
  window.addEventListener('zhidu-system-state',event=>mergeSystem(event.detail));
  async function readJSON(path) {const response=await fetch(path);if(!response.ok)throw new Error(`状态读取失败 ${response.status}`);return response.json();}
  async function refreshHealth() {
    try {const health=await readJSON('/health');set('metric-events',number(knownNumber(health.events)));set('console-service','● 服务已连接');el('console-service').dataset.state='ready';}
    catch {set('console-service','● 服务未连接');el('console-service').dataset.state='failed';set('metric-events','—');}
  }
  Promise.allSettled([readJSON('/api/v1/rag/status'),readJSON('/api/v1/operations/status')]).then(rows=>{
    mergeSystem({model:rows[0].status==='fulfilled' ? rows[0].value : null,operations:rows[1].status==='fulfilled' ? rows[1].value : null});
  });
  refreshHealth();

  function stopClock(){if(state.timer)clearInterval(state.timer);state.timer=null;}
  function emptyTelemetry(){for(const id of ['run-tools','run-calls','run-citations','run-elapsed'])set(id,'—');}
  function roles(data={}) {
    const summary=roleReceipts(receiptSummary(data).roles);
    document.querySelectorAll('.role-node').forEach(n=>{
      const item=summary[n.dataset.role];n.dataset.state=item.status;n.querySelector('em').textContent=item.label;
    });
  }
  function log(data,summary) {
    const root=el('run-timeline');root.replaceChildren();
    for(const call of summary.roles) {
      const failed=Boolean(call.error || call.status!=='completed');
      const row=node('div',null,`timeline-entry ${failed ? 'failed' : 'completed'}`);row.dataset.status=failed ? 'failed' : 'completed';
      row.append(node('strong',`${ROLE_NAMES[call.role] || '模型调用'} · ${call.call_id || call.attempt || '回执'}`),node('time',`${failed ? '输出受阻' : '已返回'} · ${seconds(knownNumber(call.elapsed_ms))} · token ${number(knownNumber(call.usage?.total_tokens))}`));root.append(row);
    }
    if(summary.tools.length) {
      const tools=node('details');tools.append(node('summary',`${summary.tools.length} 条工具执行记录`));
      for(const step of summary.tools)tools.append(node('p',`${TOOL_NAMES[step.tool] || step.tool} · ${step.status==='completed' ? '已返回' : '未完成'}${step.error ? ' · '+step.error : ''}`,'muted'));
      root.append(tools);
    }
    if(!summary.roles.length)root.prepend(node('p','本轮未提供独立角色回执，不能推测各角色已执行。','muted'));
    if(data.agent?.verification) {
      const coverage=data.agent.verification.coverage || [],missing=coverage.filter(item=>item.status!=='covered').length;
      root.append(node('p',`模型核验：${coverage.length-missing}/${coverage.length} 项计划任务覆盖。此结果不是独立准确率。`,'flow-caption'));
    }
  }
  window.addEventListener('zhidu-run-state',event=>{
    const detail=event.detail || {};stopClock();state.phase=detail.phase || 'idle';
    const busy=state.phase==='running';
    el('rag-form').setAttribute('aria-busy',String(busy));el('rag-output').setAttribute('aria-busy',String(busy));
    set('rag-submit-label',busy ? '等待任务回执…' : '启动任务');
    for(const control of document.querySelectorAll('[data-preset], #local-example'))control.disabled=busy;
    el('receipt-demo').disabled=state.phase==='running' || Boolean(detail.outcome_unknown);
    if(state.phase==='running') {
      state.lastResult=null;el('run-export').disabled=true;emptyTelemetry();roles();
      set('run-status','执行中');el('run-status').dataset.state='running';set('run-title','任务已提交');set('run-subtitle','等待服务端返回，当前角色进度未提供');
      set('run-time-label','浏览器等待');state.started=performance.now();
      state.timer=setInterval(()=>set('run-elapsed',seconds(performance.now()-state.started)),250);
      el('run-timeline').replaceChildren(node('p','正在等待执行回执；不会把等待动画当作角色已完成。','muted'));
      set('run-flow-caption','多角色流程示意，角色状态以返回回执为准。');return;
    }
    if(state.phase==='completed' && detail.data) {
      const data=detail.data,summary=receiptSummary(data);state.lastResult=data;el('run-export').disabled=false;
      const rejected=data.generation?.status==='fallback' || detail.outcome_unknown;
      const label=data.historical_replay ? '历史回放' : rejected ? '输出受阻' : data.answer_class==='partial' ? '部分证据' : data.answer_class==='clarification' ? '待澄清' : '回执已返回';
      set('run-status',label);el('run-status').dataset.state=rejected ? 'failed' : 'completed';set('run-title',data.historical_replay ? 'ONNX · 历史真实运行' : label);
      set('run-subtitle',data.historical_replay ? '冻结实验回执 · 本次无模型调用' : summary.replay ? '复用已有回执 · 本次没有重新调用模型' : '耗时、调用与角色来自实际执行记录');
      set('run-tools',number(summary.toolCalls));
      set('run-calls',summary.replay ? `本次 ${number(summary.currentCalls)} / 原 ${number(summary.originalCalls)}` : number(summary.currentCalls));
      set('run-citations',summary.verified!=null && summary.citationTotal!=null ? `${summary.verified} / ${summary.citationTotal}` : number(summary.citations));
      set('run-time-label',data.historical_replay ? '历史后端耗时' : '后端耗时');set('run-elapsed',seconds(summary.elapsed));
      roles(data);log(data,summary);set('run-flow-caption','角色“已返回”指收到输出，不表示结论已证明正确。');return;
    }
    if(state.phase==='error') {
      set('run-status',detail.outcome_unknown ? '结果待核实' : '请求受阻');el('run-status').dataset.state='failed';
      set('run-title',detail.outcome_unknown ? '保留原请求身份' : '任务尚未完成');set('run-subtitle',detail.message || '请检查服务状态');
      set('run-elapsed',seconds(knownNumber(detail.browser_elapsed_ms)));set('run-time-label','浏览器往返');
      el('run-timeline').replaceChildren(node('p',detail.outcome_unknown ? '模型是否完成仍未知，后续读取使用同一请求编号。费用尚未核实。' : '没有完整任务回执，角色与模型使用量保持未验证。','muted'));
      if(detail.status===401){el('rag-key').closest('details').open=true;el('rag-key').focus();}return;
    }
    state.lastResult=null;el('run-export').disabled=true;emptyTelemetry();roles();set('run-status','待命');el('run-status').dataset.state='idle';set('run-title','等待任务指令');set('run-subtitle','返回后显示本轮真实执行回执');set('run-time-label','后端耗时');el('run-timeline').replaceChildren(node('p','执行日志将在任务返回后显示。','muted'));
  });
  el('receipt-demo').addEventListener('click',async()=>{
    if(state.phase==='running')return;
    el('receipt-demo').disabled=true;
    try {const receipt=await readJSON('/static/console-receipt-onnx.json');window.dispatchEvent(new CustomEvent('zhidu-receipt-replay',{detail:{data:receipt.data}}));}
    catch {set('run-subtitle','历史回执读取失败，可稍后重试。');}
    finally {el('receipt-demo').disabled=state.phase==='running';}
  });
  el('run-export').addEventListener('click',()=>{
    if(!state.lastResult)return;
    const payload={exported_at:new Date().toISOString(),historical_replay:Boolean(state.lastResult.historical_replay),result:state.lastResult};
    const url=URL.createObjectURL(new Blob([JSON.stringify(payload,null,2)],{type:'application/json;charset=utf-8'}));
    const a=node('a');a.href=url;a.download=`zhidu-receipt-${Date.now()}.json`;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
  });
  window.addEventListener('error',event=>{if(event.target?.tagName==='SCRIPT' || event.message){el('console-app-error').hidden=false;set('console-app-error','页面模块出现异常，请刷新服务工作台。已保存的执行回执不会因此重新调用模型。');}});
  window.addEventListener('unhandledrejection',()=>{el('console-app-error').hidden=false;set('console-app-error','部分状态读取失败，可刷新状态。未核实的数据不会显示为已完成。');});
}
