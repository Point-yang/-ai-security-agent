import {overview, overviewText, sourceNotices} from './monitoring-ui.js';
import {publishedEvidenceView} from './submission-evidence-ui.js';
const el = id => document.getElementById(id);
let monitoringSnapshot = {};
async function updateMonitoring() {
  monitoringSnapshot = await overview();
  el('research-monitor-summary').textContent = overviewText(monitoringSnapshot);
  window.dispatchEvent(new CustomEvent('zhidu-system-state',{detail:{monitoring:monitoringSnapshot.monitoring,operations:monitoringSnapshot.operations,read_at:new Date().toISOString()}}));
}
function node(tag, text) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; return n; }
async function read(path) { const response = await fetch(path); if (!response.ok) throw new Error(String(response.status)); return response.json(); }
function notice(id, text, state = '') { el(id).textContent = text; el(id).className = state; }
// Pure model-cost presentation; also exercised without a browser or live model.
function modelCostText(data) {
  const cost=data.cost || {};
  const money=cost.monetary || cost.pricing;
  const valid=value=>typeof value==='number' && Number.isFinite(value) && value>=0;
  const count=value=>Number.isInteger(value) && value>=0 ? value : null;
  const format=(value,decimal)=>{
    if(!valid(value)) return null;
    if(typeof decimal==='string' && /^\d+(\.\d+)?$/.test(decimal)) return decimal;
    return value.toLocaleString('en-US',{useGrouping:false,maximumSignificantDigits:12});
  };
  const range=(value,kind='amount')=>{
    const single=format(value[kind],value[kind+'_decimal']);
    if(single!=null) return single;
    const low=format(value[kind+'_min'],value[kind+'_min_decimal']);
    const high=format(value[kind+'_max'],value[kind+'_max_decimal']);
    return low==null || high==null ? null : value[kind+'_min']===value[kind+'_max'] ? low : low+'–'+high;
  };
  const current=count(cost.current_attempt_external_requests);
  const original=count(cost.external_requests);
  const replay=data.deduplicated===true || (current===0 && original>0);
  const noNewRequest=replay || current===0 || original===0;
  const prefix=noNewRequest ? '本次未调用付费模型' :
    current!=null && original!=null && current<original ? `本次新增 ${current} 次模型请求；本轮累计使用量计价` : '本轮使用量计价';
  if(noNewRequest && !replay) return prefix;
  let details='价格或用量信息不完整，费用未知';
  if(money) {
    const estimated=money.status==='estimated';
    const unknown=count(money.unknown_calls);
    const incomplete=money.status==='unknown' || unknown>0 ||
      Object.values(money.currency_totals || {}).some(value=>value.complete!==true);
    const parts=[];
    if(money.currency_totals) {
      for(const [currency,value] of Object.entries(money.currency_totals)) {
        const total=value.complete===true ? range(value) : null;
        if(total!=null && !incomplete) parts.push(`${total} ${currency}${estimated ? '（估算）' : ''}`);
        else {
          const subtotal=count(value.priced_calls)>0 ? range(value,'known_subtotal') : null;
          parts.push(subtotal!=null ? `${currency} 已知小计 ${subtotal}${estimated || money.estimated_calls>0 ? '（估算）' : ''}` : `${currency} 暂无可计价小计`);
        }
      }
    } else if(money.currency) {
      const total=money.status!=='unknown' ? range(money) : null;
      parts.push(total==null ? `${money.currency} 费用未知` : `${total} ${money.currency}${estimated ? '（估算）' : ''}`);
    }
    if(incomplete) parts.push(unknown!=null ? `${unknown} 次调用费用未知；总额未知` : '调用费用有未知项；总额未知');
    if(parts.length) details=parts.join('；');
  } else if(valid(cost.api_usd)) details=`${format(cost.api_usd)} USD（历史估算，计价明细未记录）`;
  return `${prefix}${replay ? '；原轮次使用量计价（历史记录，不计作本次新增费用）' : ''}：${details}；各币种分别记录，未换汇，不代表发票金额`;
}
// End model cost presentation.
function p0ProgressLines(data) {
  const names=['requirement_ledger','question_coverage','claim_support','evidence_novelty','batch_tool_calls'];
  if(!names.some(name=>data[name]!=null)) return [];
  const object=value=>value && typeof value==='object' && !Array.isArray(value) ? value : {};
  const list=value=>Array.isArray(value) ? value : [];
  const ledger=object(data.requirement_ledger),coverage=object(data.question_coverage);
  const tasks=list(ledger.tasks),omissions=[...list(ledger.unplanned_requirements),...list(coverage.unanswered_question_requirements)];
  const unanswered=[...list(coverage.remaining_answer_requirements),...omissions.map(item=>typeof item==='string' ? item : item.requirement)].filter(Boolean);
  const hasMissing=tasks.some(task=>task.status!=='covered' || task.context_check?.required===true && task.context_check.sufficient!==true) || unanswered.length>0 || data.answer_class==='partial';
  const completeness=[ledger.complete,coverage.complete].filter(value=>typeof value==='boolean');
  const complete=hasMissing || completeness.includes(false) ? '未完整覆盖' : completeness.includes(true) ? '已覆盖本轮记录的要求' : '未知（未记录）';
  const lines=[`内部 AI 完整性核查：${complete}；不是独立金标或准确率。`];
  const statuses={covered:'已覆盖（covered）',partial:'部分覆盖（partial）',missing:'未回答（missing）'};
  const policies={any:'任一指定来源的自身引文可支持',each:'每个指定来源分别覆盖',compare:'同一比较结论须引用双方'};
  for(const task of tasks) {
    const sourceNames=list(task.source_ids).join('、');
    const contextOnly=task.context_only===true && task.semantic_status==='covered' && task.context_check?.required===true && task.context_check.sufficient!==true;
    lines.push(`任务 ${task.task_id || '未标识'}：${contextOnly ? '正文已覆盖，结构引用待核（partial）' : statuses[task.status] || '未知（未记录）'} · ${task.requirement || '要求未记录'}`);
    lines.push(`来源要求：${policies[task.source_policy] || '未知（未记录）'}${sourceNames ? '；'+sourceNames : ''}。`);
    const gaps=list(task.element_coverage).filter(item=>item.status!=='covered').map(item=>item.element).filter(Boolean);
    if(gaps.length) lines.push(`遗漏或未完整回答的条件：${[...new Set(gaps)].join('；')}。`);
    else if(contextOnly) lines.push('当前核查认为正文已表达要求；尚需确认完整结构引用，未据此判定具体条件漏答。');
    else if(task.status!=='covered') lines.push('该任务仍有完整性缺口，具体条件未记录。');
    if(task.context_check?.required===true) lines.push(task.context_check.sufficient===true ?
      '引用范围已覆盖所选结构；是否答完整仍需逐项语义核查。' : '完整结构引用尚未确认，需要继续读取对应列表或段落。');
    const missingSources=list(object(task.source_check).missing);
    if(missingSources.length) lines.push(`${task.source_policy==='any' ? '尚未引用的候选来源' : '本轮引文尚未覆盖的指定来源'}：${missingSources.join('、')}。`);
  }
  if(unanswered.length) lines.push(`仍待回答或补核的原问题要求：${[...new Set(unanswered)].join('；')}。`);
  const replay=data.deduplicated===true || data.local_receipt_display===true || data.historical_replay===true;
  const novelty=object(data.evidence_novelty);
  const chars=value=>object(value).status==='known' && Number.isInteger(value.new_source_chars) && value.new_source_chars>=0 ? `${value.new_source_chars} 字符` : '未知（未记录或来源坐标不完整）';
  lines.push(`本次新增原文覆盖：${replay ? '0 字符（本次仅回放）' : chars(novelty.current_attempt)}。`);
  lines.push(`原轮逻辑新增原文覆盖：${chars(novelty.logical)}；仅为规范原文区间覆盖，不代表新增事实或 Agent 增益。`);
  const batch=data.batch_tool_calls;
  const entries=Array.isArray(batch) ? batch : Array.isArray(batch?.calls) ? batch.calls : Array.isArray(batch?.items) ? batch.items : null;
  let attempts=0,unknown=0,skipped=0,allocationSkipped=0,overlaps=0,readPlans=0,invalidPlans=0;
  const seen=new Set();
  const parents=new Map();
  if(entries) for(const [index,entry] of entries.entries()) parents.set(entry.call_id || `unidentified-${index}`,entry);
  for(const [parentId,entry] of parents) {
    const observations=list(entry.tool_observations),admitted=list(entry.admission?.admitted);
    for(const child of list(entry.admission?.skipped)) {
      if(!child.reason || ['remaining_tool_budget_exhausted','decision_batch_limit'].includes(child.reason)) skipped++;
      else allocationSkipped++;
    }
    overlaps+=list(entry.admission?.allocation?.audit).filter(item=>item.action==='deferred_containing_context').length;
    readPlans+=entry.action==='read_plan';
    invalidPlans+=list(entry.admission?.feedback).length>0;
    const recorded=new Set();
    for(const child of observations) {
      const identity=child.child_id;
      if(!identity) {unknown++;continue;}
      recorded.add(identity);
      const key=parentId+'/'+identity;
      if(seen.has(key)) continue;
      seen.add(key);
      if(Number.isInteger(child.actual_tool_attempts) && child.actual_tool_attempts>=0) attempts+=child.actual_tool_attempts;
      else unknown++;
    }
    unknown+=admitted.filter(child=>!recorded.has(child.child_id)).length;
  }
  lines.push(`本次研究工具实际尝试：${replay ? '0 次（本次仅回放）' : entries==null ? '未知（未记录）' : unknown ? `未知（已记录 ${attempts} 次，另有 ${unknown} 项缺回执）` : `${attempts} 次`}。`);
  if(skipped) lines.push(`原轮 ${skipped} 项请求未获预算准入，未计为已执行。`);
  if(allocationSkipped) lines.push(`原轮 ${allocationSkipped} 项请求因已知字段不可读、已有原文或重叠选择而未执行；不代表问题已回答。`);
  if(overlaps) lines.push(`已调整 ${overlaps} 项相同任务的重叠段落选择；被暂缓的范围未计为已读。`);
  if(readPlans) lines.push(`按必答项安排了 ${readPlans} 次阅读计划；阅读意图不等于答案完整性。`);
  if(invalidPlans) lines.push(`${invalidPlans} 次阅读计划未通过引用或任务对应检查，该计划未执行读取。`);
  return lines;
}
// End P0 progress presentation.
function applyAgentGeneration(body) {
  if(['agent_legacy','agent_langchain','agent_workflow','agent_auto','agent_team'].includes(body.generation)) {
    body.agent_backend=body.generation.slice(6);
    body.generation='agent';
  }
  return body;
}
// End Agent selection mapping.
function renderPublishedEvidence(data) {
  const view=publishedEvidenceView(data),root=el('published-evidence');root.replaceChildren();
  el('published-evidence-date').textContent=view.available ? `冻结依据 · ${view.asOf}` : '依据未读取';
  for(const text of view.paragraphs) root.append(node('p',text));
  if(view.modes.length) {
    const wrap=node('div');wrap.className='evidence-table-wrap';wrap.tabIndex=0;wrap.setAttribute('role','region');wrap.setAttribute('aria-label','复杂跨文档小样本对照，可横向滚动');
    const table=node('table');table.append(node('caption','复杂跨文档小样本对照 · 与富化回归分别统计'));
    const header=node('tr');for(const text of ['策略','严格通过 / 题数','必答事实召回率','平均后端耗时']) {const th=node('th',text);th.scope='col';header.append(th);}table.append(header);
    for(const mode of view.modes) {const row=node('tr');for(const text of [mode.label,mode.strict,mode.recall,mode.elapsed])row.append(node('td',text));table.append(row);}
    wrap.append(table);root.append(wrap);
  }
  if(view.available && Array.isArray(data.sources) && data.sources.length) {
    const details=node('details');details.append(node('summary','随提交包核验原始评测依据'));
    for(const source of data.sources)details.append(node('p',`${source.file || '路径未记录'} · SHA-256 ${source.sha256 || '未记录'}`));
    root.append(details);
  }
}
async function refresh() {
  await updateMonitoring();
  const results = await Promise.allSettled([
    read('/api/v1/operations/status'), read('/api/v1/operations/evaluations?limit=1'),
    read('/api/v1/enrichment/evaluations?limit=1'), read('/api/v1/rag/status'),
    read('/api/v1/rag/evaluations?limit=5'), read('/api/v1/rag/human-review-status'),
    read('/api/v1/release/evidence')
  ]);
  const [ops, audits, enrichment, model, evaluation, human, published] = results;
  renderPublishedEvidence(published.status==='fulfilled' ? published.value : null);
  window.dispatchEvent(new CustomEvent('zhidu-system-state',{detail:{
    ops:ops.status==='fulfilled' ? ops.value : null,
    model:model.status==='fulfilled' ? model.value : null,
    audits:audits.status==='fulfilled' ? audits.value : null,
    enrichment:enrichment.status==='fulfilled' ? enrichment.value : null,
    evaluation:evaluation.status==='fulfilled' ? evaluation.value : null,
    monitoring:monitoringSnapshot.monitoring,operations:monitoringSnapshot.operations,
    read_at:new Date().toISOString()
  }}));
  if (ops.status === 'fulfilled') {
    const c = ops.value.collection;
    const stale = c.configured_targets - c.targets_fresh;
    notice('source-health', stale ? `来源超期：${stale}/${c.configured_targets} 个采集任务需刷新。` : '来源在最近两个周期内已更新。', stale ? 'attention' : '');
  } else notice('source-health', '来源状态暂不可读。', 'attention');
  const latest = audits.status === 'fulfilled' ? audits.value[0] : null;
  if (latest?.integrity?.failed) notice('evidence-health', `证据缺失或损坏：最近审计发现 ${latest.integrity.failed} 份异常原文。`, 'failed');
  else notice('evidence-health', latest ? `最近证据审计：${latest.run_at}。每次回答仍会复验引用。` : '尚无证据完整性审计，不能假定原文完整。', latest ? '' : 'attention');
  if (model.status === 'fulfilled') {
    const data = model.value;
    notice('model-health', data.status === 'ready' ? `本地 embedding 已就绪：${data.current_vectors}/${data.chunks} 个当前片段。` : data.status === 'index_incomplete' ? `语义索引待同步：${data.current_vectors}/${data.chunks} 个片段。` : '模型暂不可用：请先准备本地 embedding 模型；词项基线可独立使用。', data.status === 'ready' ? '' : 'attention');
    notice('rag-index-warning', data.status === 'ready' ? `当前语义索引 ${data.current_vectors}/${data.chunks} 就绪。` : '混合检索当前不可用：语义索引或模型待恢复。可在“检索策略”手动选择词项基线查询已保存证据。', data.status === 'ready' ? 'hint' : 'source-freshness attention');
    const generation = data.generation;
    if (!generation) notice('generation-health', '当前服务尚未加载大模型接口，请重启服务。', 'attention');
    else if (generation.provider === 'extractive') notice('generation-health', '默认使用本地原文摘录，可在回答方式中选择 DeepSeek。');
    else if (generation.status === 'configured') notice('generation-health', `DeepSeek 已配置：${generation.model}。实际连接结果将在回答后显示。`);
    else notice('generation-health', generation.status === 'missing_api_key' ? '生成模型密钥尚未配置，请按所选供应商配置后重启服务。' : 'DeepSeek 地址配置无效：请使用官方 API 地址。', 'attention');
  } else { notice('model-health', '模型状态暂不可读。', 'attention'); notice('rag-index-warning','模型与索引状态未验证，可手动选择词项基线。','source-freshness attention'); }
  if (enrichment.status === 'fulfilled' && enrichment.value.length) {
    const e = enrichment.value[0];
    notice('enrichment-eval', `富化回归 ${e.suite_version} · ${e.case_count} 例 · 字段断言准确率 ${e.assertion_accuracy}。固定回归不等于人工金标。`);
  } else notice('enrichment-eval', '尚无富化评测记录。');
  const root = el('rag-evaluations'); root.replaceChildren();
  if (human.status === 'fulfilled') {
    const h = human.value;
    root.append(node('p', h.tasks ? `历史双人复核任务：${h.completed}/${h.tasks} 已完成，${h.pending} 待审，${h.conflicts} 待裁决。此任务与上方项目采纳的 AI 审核金标分别记录。` : '本库未登记双人复核任务；项目采纳的审核方法见上方提交版评测依据。'));
  }
  if (evaluation.status !== 'fulfilled') { root.append(node('p','本库历史 RAG 对照记录暂不可读；已发布实验的范围与结果见上方提交版评测依据。')); return; }
  if (!evaluation.value.length) { root.append(node('p', '本库尚未保存历史 RAG 对照记录；已发布的跨策略实验见上方提交版评测依据。')); return; }
  const primary = evaluation.value.find(item => item.report.version === 'rag-benchmark-v2' && item.report.dataset_version === 'week6-frozen-v1');
  const report = (primary || evaluation.value[0]).report;
  if (report.version === 'rag-benchmark-v1') { root.append(node('p','历史报告的引用支持率口径有误，已停用该展示；请读取修正版评测。')); return; }
  root.append(node('p', '训练/开发表征回归 · 非正式留出测试；原文一致性与问题相关支持分别计量。'));
  root.append(node('p', `题集 ${report.dataset_version || report.dataset_sha256} · 独立问题划分 ${JSON.stringify(report.unique_case_counts_by_split || {})}`));
  const table = node('table'); const header = node('tr');
  for (const name of ['策略', '类别准确率', '拒答正确率', '原文一致性', '问题相关支持', 'Recall@5', 'P50 / P95 ms']) header.append(node('th', name));
  table.append(header);
  for (const [name, data] of Object.entries(report.modes)) {
    const row = node('tr');
    const metric = value => value == null ? '待测' : Number(value).toFixed(3);
    for (const value of [name, metric(data.class_accuracy), metric(data.refusal_correctness), metric(data.verbatim_consistency_rate), metric(data.citation_support_rate), metric(data.recall_at_5), `${Number(data.complete_answer_latency_ms.p50).toFixed(1)} / ${Number(data.complete_answer_latency_ms.p95).toFixed(1)}`]) row.append(node('td', value));
    table.append(row);
  }
  root.append(table, node('p', `数据规模 ${report.data_scale.events} 事件 / ${report.data_scale.search_chunks} 片段 · 并发 ${report.concurrency} · 本地抽取式回答 · 冷启动单独记录，无答案缓存。`));
  const strata = node('details'); strata.append(node('summary','按语言及数据划分查看'));
  const rows = Object.fromEntries(Object.entries(report.modes).map(([key,value])=>[key,value.strata]));
  strata.append(node('pre',JSON.stringify({cases:report.unique_case_counts_by_split,metrics:rows},null,2))); root.append(strata);
}
el('week6-refresh').onclick = refresh;
let pendingRequest = null;
let completedReceipt = null;
let retryReceipt = null;
let retryPending = false;
let sending = false;
let lastFailure = false;
async function post(path, body) {
  const response = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json','X-Admin-Key':el('rag-key').value},body:JSON.stringify(body)});
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(response.status === 401 ? '管理员密钥不匹配；这里不是 DeepSeek API Key。' : response.status === 409 ? `会话请求冲突：${data.detail}。原记录已保留。` : `请求失败 ${response.status}，请检查服务配置后重试。`);
    error.status = response.status; throw error;
  }
  return data;
}
async function conversations(selected = el('rag-conversation').value) {
  const rows = await read('/api/v1/conversations?limit=200');
  el('rag-conversation').replaceChildren(new Option('选择或新建会话', ''));
  for (const row of rows) el('rag-conversation').append(new Option(`${row.title} · ${row.message_count} 条`,row.id));
  // Opening a workspace must not silently inherit another saved task or asset.
  el('rag-conversation').value = rows.some(row=>row.id===selected) ? selected : '';
}
async function history() {
  const id = el('rag-conversation').value;
  const root = el('rag-history'); root.replaceChildren();
  if (!id) { notice('rag-conversation-status','首次提交时自动新建；追问在所选会话中继续。'); return; }
  const [data, validity] = await Promise.all([read(`/api/v1/conversations/${id}/replay`),read(`/api/v1/conversations/${id}/context-status`)]);
  notice('rag-conversation-status', `${data.conversation.title} · ${data.messages.length} 条消息 · 当前资产：${data.conversation.active_asset?.name || '未选择'}`);
  for (const citation of validity.citations.filter(c => !c.reusable_as_current)) {
    const warning = node('p',`历史引用 ${citation.event_id}：${citation.status}。历史答案保留；新一轮将重新获取当前资料。`); warning.className='attention'; root.append(warning);
  }
  const details = node('details'); details.open = true; details.append(node('summary','最近会话记录'));
  for (const message of data.messages.slice(-6)) {
    const card = node('article'); card.className='rag-history-message';
    card.append(node('strong', message.role === 'user' ? '我的问题' : `回答 · ${message.answer_status}`),node('pre',message.content));
    const run = message.hops.find(h => h.hop_type === 'rag_generation')?.output_data;
    if (run) card.append(node('p',`请求模型 ${run.requested_generation.model} · 实际 ${run.generation_model} · ${run.elapsed_ms} ms · usage ${run.generation.usage?.total_tokens ?? '未返回'} · ${run.generation.status}${run.generation.reason ? ' / '+run.generation.reason : ''}`));
    const refs=node('details'); refs.append(node('summary',`${message.citations.length} 条历史引用`),node('pre',JSON.stringify(message.citations,null,2))); if(message.citations.length) card.append(refs);
    details.append(card);
  }
  root.append(details);
}
function renderAnswer(data) {
  const root=el('rag-output');root.replaceChildren();
  const citations=Array.isArray(data.citations) ? data.citations : [];
  const generated=Array.isArray(data.generated_claims) ? data.generated_claims : [];
  const generation=data.generation || {};
  const statusNames={evidence:'引证回答',evidence_only:'原文摘录',partial:'部分回答',refused:'证据不足',clarification:'待明确上下文',unavailable:'服务暂不可用'};
  const summary=node('section');summary.className='run-summary';
  summary.append(node('h3',statusNames[data.answer_class] || data.answer_class || '本轮答复'));
  const metrics=node('div');metrics.className='run-summary-metrics';
  const elapsed=Number.isFinite(data.elapsed_ms) ? (data.elapsed_ms/1000).toFixed(2)+' s' : '未记录';
  const toolCount=data.agent?.attempted_tool_calls ?? data.tool_calls ?? data.tools?.length ?? '未记录';
  const replaySummary=data.deduplicated===true || data.local_receipt_display===true || data.historical_replay===true;
  for(const text of [`${replaySummary ? '原轮' : ''}后端耗时 ${elapsed}`,`${replaySummary ? '原轮 ' : ''}模型 token ${data.cost?.billed_tokens ?? '未完整返回'}`,`${replaySummary ? '原轮' : ''}工具尝试 ${toolCount}`,`引用 ${citations.length}`]) metrics.append(node('span',text));
  summary.append(metrics,node('p',`实际回答：${data.generation_model || '本地处理'}；${modelCostText(data)}。`));root.append(summary);
  const progress=p0ProgressLines(data);
  if(progress.length) {
    const card=node('section');card.className='claim-card p0-progress';card.append(node('h4','问题完整性与研究记录'));
    const items=node('ul');for(const line of progress) items.append(node('li',line));card.append(items);root.append(card);
  }
  if(data.local_receipt_display) root.append(node('p','本次仅重新显示页面已保存结果，没有提交模型请求。'));
  else if(data.deduplicated) root.append(node('p','本次重复请求已复用原结果，没有重新调用模型。'));
  if(generation.status==='fallback') {
    const reasons={missing_api_key:'尚未配置模型密钥',invalid_endpoint:'模型地址无效',authentication_failed:'模型密钥未通过验证',insufficient_balance:'模型余额不足',rate_limited:'模型请求被限流',timeout:'模型请求超时',network_error:'模型连接结果不明',upstream_error:'模型服务返回错误',incomplete_output:'模型输出被截断',invalid_citation:'模型引用未通过检查',invalid_claim_text:'模型结论格式未通过检查',unquoted_source_absence:'来源缺失说明缺少对应引用',model_request_outcome_unknown:'模型请求结果不明'};
    const warning=node('p',`模型回答未被采用：${reasons[generation.reason] || '生成未通过检查'}。以下保留本轮实际返回的原文与范围说明。`);warning.className='attention';root.append(warning);
  }
  if(generation.status==='completed' && generated.length) {
    for(const [index,claim] of generated.entries()) {
      const card=node('article');card.className='claim-card';
      const text=node('p',claim.text || '');text.className='answer-text';
      card.append(node('h4',`结论 ${index+1}`),text);
      const evidence=Array.isArray(claim.evidence) ? claim.evidence : [];
      const refs=node('details');refs.append(node('summary',`展开 ${evidence.length} 条对应原文`));
      for(const ref of evidence) {
        const citation=Number.isInteger(ref.citation) ? citations[ref.citation-1] : null;
        refs.append(node('p',citation ? `[${ref.citation}] ${citation.source_id || '来源'} · ${citation.external_id || ''} · ${citation.field || ''}` : '本条引用信息未完整返回'));
        const quote=node('blockquote',ref.quote || '');quote.className='answer-text';refs.append(quote);
      }
      card.append(refs);root.append(card);
    }
    const full=node('details');full.open=data.answer_class==='partial';
    const fullText=node('p',data.answer || '');fullText.className='answer-text';
    full.append(node('summary','完整答复与范围说明'),fullText);root.append(full);
  } else {
    const card=node('article');card.className='claim-card';
    const text=node('p',data.answer || '本轮未返回可显示的答复。');text.className='answer-text';
    card.append(node('h4','本轮答复'),text);root.append(card);
  }
  for(const item of sourceNotices(citations,monitoringSnapshot.monitoring,monitoringSnapshot.operations)) {
    const warning=node('p',item.text);warning.className='source-freshness'+(item.warning ? ' attention' : '');root.append(warning);
  }
  if(!citations.length) root.append(node('p','本轮没有可引用资料，不能把空结果解释为没有漏洞。'));
  if(citations.length) {
    root.append(node('h4',`本轮来源证据 · ${citations.length} 条`));
    for(const [index,citation] of citations.entries()) {
      const card=node('details');card.className='evidence-card';
      card.append(node('summary',`[${index+1}] ${citation.external_id || '来源记录'} · ${citation.field || '原文'}`));
      const quote=node('blockquote',citation.text || '本条未返回原文文本。');quote.className='answer-text';card.append(quote);
      card.append(node('p',`${citation.source_id || '来源'} · revision ${citation.revision ?? '未记录'} · ${citation.start ?? '?'}–${citation.end ?? '?'}`));
      if(citation.source_url) {
        try {
          const url=new URL(citation.source_url);
          if(['http:','https:'].includes(url.protocol) && !url.username && !url.password) {
            const link=node('a','打开来源页面');link.href=url.href;link.target='_blank';link.rel='noopener noreferrer';card.append(link);
          }
        } catch { /* A malformed source URL is displayed only in the audit. */ }
      }
      root.append(card);
    }
  }
  const check=data.agent?.final_citation_check;
  root.append(node('p',check ? `原文复验 ${check.verified ?? '未记录'}/${check.total ?? '未记录'}；引用一致性不替代结论的语义核查。` : '结论依据本轮所列来源，语义正确性仍须核查。'));
  if(data.routing?.gaps?.length) root.append(node('p',`初始待补证范围：${(data.routing.gap_descriptions || []).join('、')}`));
  const audit=node('details');audit.className='run-audit';
  audit.append(node('summary','查看完整执行审计 JSON'),node('pre',JSON.stringify({generation:data.generation,cost:data.cost,agent:data.agent,tools:data.tools,evidence_tasks:data.evidence_tasks,context:data.context,constraints:data.constraints,citations,generated_claims:generated,requirement_ledger:data.requirement_ledger,question_coverage:data.question_coverage,claim_support:data.claim_support,evidence_novelty:data.evidence_novelty,batch_tool_calls:data.batch_tool_calls},null,2)));root.append(audit);
  for(const item of (data.agent?.tool_results || []).filter(x=>x.tool==='asset_exposure' && x.status==='completed')) {
    const local=node('details');local.append(node('summary','本地资产条件结果（未发送给模型）'),node('pre',JSON.stringify(item.result,null,2)));root.append(local);
  }
  if(!data.historical_replay && data.reason==='model_unavailable') notice('model-health','模型暂不可用，本轮未执行混合回答。','attention');
  if(!data.historical_replay && data.reason==='evidence_missing') notice('evidence-health','证据缺失或损坏，本轮引用未通过复验。','failed');
  if(data.conversation_context) {
    for(const item of data.conversation_context.notices || []) root.prepend(node('p',item.rule));
    if(!data.historical_replay) {
      el('rag-event').replaceChildren(new Option('自动解析明确上下文',''));
      for(const candidate of data.conversation_context.candidates || []) el('rag-event').append(new Option(`${candidate.external_id} · ${candidate.source_id}`,candidate.event_id));
      const details=el('rag-event').closest('details');if(data.answer_class==='clarification' && details) details.open=true;
    }
  }
}
function emitRunState(phase,detail={}) {
  window.dispatchEvent(new CustomEvent('zhidu-run-state',{detail:{phase,...detail}}));
}
function unknownModelOutcome(data) {
  const reason=data.generation?.reason || data.reason || '';
  if(['model_request_outcome_unknown','checkpoint_model_outcome_unknown','timeout','network_error'].includes(reason)) return true;
  const calls=data.agent?.role_calls || data.agent?.model_calls || [];
  return Array.isArray(calls) && calls.some(call=>call.status==='uncertain' || (call.status==='running' && call.http_requests>0) || String(call.error || '').includes('outcome_unknown'));
}
function redisplayCompletedReceipt(receipt) {
  if(!receipt) return;
  const data={...receipt.data,deduplicated:true,local_receipt_display:true,
    cost:{...receipt.data.cost,current_attempt_external_requests:0,current_attempt_billed_tokens:0}};
  try {
    renderAnswer(data);
    el('rag-retry').hidden=data.generation?.status!=='fallback' && data.answer_class!=='unavailable';
    el('rag-retry').textContent='重新显示已保存结果';
    emitRunState('completed',{data,request_id:receipt.id,local_receipt_display:true,browser_elapsed_ms:0});
  } catch(error) {
    notice('rag-output','服务端结果已保存在页面，显示暂时失败。重新显示只读取本地回执，不会再次提交模型请求。','attention');
    el('rag-retry').hidden=false;el('rag-retry').textContent='重新显示已保存结果';
    emitRunState('completed',{data,request_id:receipt.id,local_receipt_display:true,display_error:true,message:error.message,browser_elapsed_ms:0});
  }
}
el('rag-form').onsubmit = async event => {
  event.preventDefault(); if (sending) return;
  sending=true; el('rag-submit').disabled=true; el('rag-new').disabled=true; el('rag-conversation').disabled=true;
  const clientStart=performance.now();
  const startedAt=new Date().toISOString();
  const reusePending=retryPending && pendingRequest?.body;
  retryPending=false;
  retryReceipt=null;
  let receivedReceipt=null;
  const selected=applyAgentGeneration({generation:el('rag-generation').value});
  emitRunState('running',{started_at:startedAt,generation:selected.generation,backend:selected.agent_backend,question:el('rag-question').value.trim()});
  try {
    if (!reusePending && !el('rag-conversation').value) {
      const created=await post('/api/v1/conversations',{title:el('rag-question').value.trim().slice(0,80) || '新的研究会话'});
      await conversations(created.id);
    }
    const body=reusePending ? {...reusePending} : {question:el('rag-question').value.trim(),mode:el('rag-mode').value,generation:el('rag-generation').value,conversation_id:el('rag-conversation').value};
    if(!reusePending) {
      applyAgentGeneration(body);
      if(el('rag-query').value.trim()) body.query=el('rag-query').value.trim();
      if(el('rag-event').value) body.event_id=el('rag-event').value;
      if(el('rag-asset').value==='__none__') body.clear_asset=true;
      else if(el('rag-asset').value) body.asset_id=el('rag-asset').value;
    }
    const signature=JSON.stringify(body);
    if (!pendingRequest || pendingRequest.signature!==signature) pendingRequest={signature,id:crypto.randomUUID(),body:{...body}};
    body.request_id=pendingRequest.id;
    emitRunState('running',{started_at:startedAt,request_id:body.request_id,generation:body.generation,backend:body.agent_backend,question:body.question});
    notice('rag-output','请求正在处理，等待服务返回真实执行记录…');
    const data=await post('/api/v1/rag/answers',body);
    // Commit the service receipt before any rendering, events or telemetry.
    // A display failure must never turn this paid call into a fresh request.
    completedReceipt={body:{...body},id:body.request_id,data:JSON.parse(JSON.stringify(data))};
    receivedReceipt=completedReceipt;retryReceipt=receivedReceipt;
    const outcomeUnknown=unknownModelOutcome(data);
    if(!outcomeUnknown) pendingRequest=null;
    emitRunState('completed',{data,request_id:body.request_id,started_at:startedAt,browser_elapsed_ms:performance.now()-clientStart,outcome_unknown:outcomeUnknown});
    renderAnswer(data);
    el('rag-output').append(node('p',`本次浏览器完整往返 ${(performance.now()-clientStart).toFixed(0)} ms${data.deduplicated ? ' · 已返回原轮次，未再次调用模型' : ''}。`));
    lastFailure=data.generation?.status==='fallback' || data.answer_class==='unavailable';
    el('rag-retry').hidden=!lastFailure;
    el('rag-retry').textContent=outcomeUnknown ? '读取原请求结果' : '重新显示已保存结果';
    if(outcomeUnknown) {
      const warning=node('p','模型连接结果不明，已保留原请求编号；读取原请求只检查既有记录，不会自动发起新的模型请求。');warning.className='attention';el('rag-output').append(warning);
    }
    // Each successful request confirms the asset in the session; subsequent turns inherit it.
    if(!outcomeUnknown) { el('rag-asset').value=''; el('rag-query').value=''; }
    await Promise.allSettled([updateMonitoring(),conversations(body.conversation_id).then(history)]);
    window.dispatchEvent(new CustomEvent('zhidu-conversation-updated',{detail:body.conversation_id}));
  } catch(error) {
    el('rag-retry').hidden=false;
    if(receivedReceipt) {
      retryReceipt=receivedReceipt;
      notice('rag-output','服务端结果已保存在页面，后续显示或状态刷新失败。可重新显示既有回执，不会因此创建新的模型请求。','attention');
      el('rag-retry').textContent=pendingRequest ? '读取原请求结果' : '重新显示已保存结果';
      emitRunState('completed',{data:receivedReceipt.data,request_id:receivedReceipt.id,display_error:true,message:error.message,browser_elapsed_ms:performance.now()-clientStart,outcome_unknown:!!pendingRequest});
    } else {
      notice('rag-output',error.message,'attention');
      el('rag-retry').textContent=pendingRequest ? '读取原请求结果' : '重新提交本轮';
      emitRunState('error',{message:error.message,status:error.status || null,request_id:pendingRequest?.id || null,browser_elapsed_ms:performance.now()-clientStart,outcome_unknown:!!pendingRequest && (error.status==null || error.status===409)});
    }
  }
  finally { sending=false; el('rag-key').value=''; el('rag-submit').disabled=false; el('rag-new').disabled=false; el('rag-conversation').disabled=false; }
};
el('rag-retry').onclick=()=>{if(!pendingRequest && retryReceipt) {redisplayCompletedReceipt(retryReceipt);return;}retryPending=!!pendingRequest;return el('rag-form').requestSubmit();};
el('rag-new').onclick=()=>{pendingRequest=null;completedReceipt=null;retryReceipt=null;el('rag-conversation').value='';el('rag-event').replaceChildren(new Option('自动解析明确上下文',''));el('rag-query').value='';el('rag-asset').value='';el('rag-output').replaceChildren();el('rag-retry').hidden=true;emitRunState('idle');history().catch(()=>notice('rag-conversation-status','会话读取失败，请重试。','attention'));el('rag-question').focus();};
el('rag-conversation').onchange=()=>{pendingRequest=null;completedReceipt=null;retryReceipt=null;el('rag-event').replaceChildren(new Option('自动解析明确上下文',''));el('rag-query').value='';el('rag-asset').value='';el('rag-output').replaceChildren();el('rag-retry').hidden=true;emitRunState('idle');history().catch(()=>notice('rag-conversation-status','会话读取失败，请重试。','attention'));if(el('rag-conversation').value)window.dispatchEvent(new CustomEvent('zhidu-conversation-updated',{detail:el('rag-conversation').value}));};
window.addEventListener('zhidu-conversation-selected', event => { if(!sending && el('rag-conversation').value !== event.detail) { el('rag-conversation').value=event.detail;pendingRequest=null;completedReceipt=null;retryReceipt=null;emitRunState('idle');history().catch(()=>notice('rag-conversation-status','会话读取失败，请重试。','attention')); } });
window.addEventListener('zhidu-receipt-replay',event=>{
  if(sending || pendingRequest || event.detail?.data?.historical_replay!==true) return;
  const original=event.detail.data;
  const data={...original,historical_replay:true,deduplicated:false,
    cost:{...original.cost,current_attempt_external_requests:0,current_attempt_billed_tokens:0}};
  try {
    renderAnswer(data);
    const banner=node('p','历史真实运行回放 · 非当前新生成 / 原实验语义仍有遗漏。');banner.className='history-replay-banner attention';el('rag-output').prepend(banner);
    el('rag-retry').hidden=true;
    emitRunState('completed',{data,historical_replay:true,browser_elapsed_ms:0});
  } catch(error) {
    notice('rag-output','历史回放显示失败，本次未提交模型请求；当前会话保持原状态。','attention');el('rag-retry').hidden=true;
    emitRunState('error',{message:error.message,historical_replay:true,data});
  }
});
Promise.all([conversations().then(history),read('/api/v1/assets?limit=200').then(data=>{
  for(const asset of (Array.isArray(data)?data:data.items || [])) el('rag-asset').append(new Option(`${asset.name} · ${asset.environment}`,asset.id));
})]).catch(()=>notice('rag-conversation-status','会话或资产列表暂不可用。','attention'));
refresh().catch(()=>notice('source-health','系统状态暂不可读，请刷新重试。','attention'));
