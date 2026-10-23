import {errorType, gapsFor, overview, overviewText, workerText} from './monitoring-ui.js';
const $ = id => document.getElementById(id);
const labels = {completed:'完成',partial:'未完成分页',failed:'失败',running:'运行中',interrupted:'已中断',not_started:'未启动',pending:'等待运行'};
let offset = 0, total = 0, selected = null;
const pageSize = 12;
function el(tag, text, cls) { const node=document.createElement(tag); if(text!==undefined) node.textContent=text; if(cls) node.className=cls; return node; }
function time(value) { return value ? new Date(value).toLocaleString('zh-CN',{hour12:false}) : '未知'; }
async function api(path) { const r=await fetch(path); if(!r.ok) throw new Error(`接口 ${r.status}：${path}`); return r.json(); }
function link(text, path) { const node=el('a',text); node.href=path; node.target='_blank'; node.rel='noopener noreferrer'; return node; }
function badge(value) {return el('span',value,`badge ${value}`);}
async function load() {
  $('message').textContent='';
  try {
    const params=new URLSearchParams({limit:pageSize,offset});
    if($('query').value.trim()) params.set('q',$('query').value.trim());
    if($('severity').value) params.set('severity',$('severity').value);
    if($('ai-label').value) params.set('ai_label',$('ai-label').value);
    const data=await api('/api/v1/events?'+params); total=data.total;
    $('total').textContent=`共 ${total} 条`; $('events').replaceChildren();
    if(!data.items.length) $('events').append(el('p','暂无情报。请运行 README 中的采集命令，或导入离线演示数据。','muted'));
    for(const event of data.items) {
      const item=el('button',undefined,'event'+(event.id===selected?' selected':''));
      item.append(el('strong',event.title),badge(event.severity),badge(event.source_id),el('small',event.external_id));
      if(event.withdrawn_at) item.append(badge('已撤回'));
      item.append(el('div',`来源更新 ${time(event.source_updated_at)} · 当前版本 ${event.revision}`,'muted'));
      item.onclick=()=>show(event.id).catch(error); $('events').append(item);
    }
    $('prev').disabled=offset===0; $('next').disabled=offset+pageSize>=total;
    $('page').textContent=total?`${offset+1}–${Math.min(offset+pageSize,total)}`:'0';
  } catch(e) { error(e); }
}
function error(e) {$('message').textContent=e.message;}
async function show(id) {
  selected=id;
  const [data,history]=await Promise.all([api(`/api/v1/events/${id}`),api(`/api/v1/events/${id}/history`)]);
  const revision=data.current_revision;
  const raw=await api(`/api/v1/raw-documents/${revision.raw_document_id}`);
  const box=$('detail'); box.replaceChildren(el('h3',data.title));
  box.append(badge(data.severity),badge(raw.origin==='live'?'联网采集':'离线回放'),badge(data.withdrawn_at?'已撤回':'来源声明'));
  const kv=el('dl',undefined,'kv');
  const pairs=[['来源',data.source_id],['资料类型',data.kind],['事件编号',data.external_id],['别名',data.aliases.join(' / ')],['发布时间',time(data.published_at)],['采集时间',time(data.first_seen_at)],['来源更新时间',time(data.source_updated_at)],['核验状态',data.review_status]];
  for(const [key,value] of pairs) kv.append(el('dt',key),el('dd',value)); box.append(kv);
  if(data.triage) box.append(el('p',`AI 相关性：${data.triage.label} · ${data.triage.category}（规则初筛）`));
  if(data.enrichment) {
    const enrichment=data.enrichment;
    box.append(el('h3','结构化富化（派生数据）'));
    const selected=enrichment.cvss&&enrichment.cvss.selected;
    if(selected) box.append(el('p',`CVSS ${selected.version} · ${selected.score} · ${selected.vector}`));
    if(enrichment.entities.length) box.append(el('p','实体：'+enrichment.entities.map(item=>item.ecosystem?`${item.ecosystem}/${item.value}`:item.value).join(' / ')));
    if(enrichment.quality_flags.length) box.append(el('p','待补资料：'+enrichment.quality_flags.join(' / '),'notice'));
    if(enrichment.cpe_matches.length) box.append(el('p',`CPE 影响条件：${enrichment.cpe_matches.length} 条（点击下方证据核对）`));
  }
  if(revision.normalized.metadata_only) box.append(el('p','论文元数据；未获取全文。发布日期精度：'+revision.normalized.publication_precision,'notice'));
  box.append(el('h3','影响组件（尚未执行资产匹配）'));
  for(const p of data.packages) box.append(el('p',`${p.ecosystem} / ${p.name} · 影响：${p.vulnerable_range} · 首个修复版本：${p.fixed_version||'未知'}`));
  box.append(el('h3','来源描述'),el('div',data.description,'description'));
  box.append(el('h3','原始证据'),link('查看完整原文 JSON ↗',raw.content_url),el('p',`SHA-256：${raw.sha256}`,'muted'));
  for(const evidence of revision.evidence) {
    const d=el('details');d.append(el('summary',`${evidence.field} · ${evidence.json_pointer}`),el('pre',JSON.stringify(evidence.value,null,2)));box.append(d);
  }
  box.append(el('h3',`历史记录（${history.length} 个版本）`));
  for(const rev of history) {
    const d=el('details'); d.append(el('summary',`v${rev.number} · ${rev.disposition} · ${time(rev.source_updated_at)}`),el('pre',JSON.stringify(rev.normalized,null,2)),link('该版本原文 ↗',`/api/v1/raw-documents/${rev.raw_document_id}/content`));box.append(d);
  }
  const related=await api(`/api/v1/events/${id}/related`);
  box.append(el('h3','相同标识的关联来源'));
  if(!related.items.length) box.append(el('p','暂未发现具有相同标识的其他来源记录。','muted'));
  for(const other of related.items) {
    const button=el('button',`${other.source_id} · ${other.external_id}`);
    button.onclick=()=>show(other.event_id).catch(error); box.append(button);
  }
  box.append(el('p','同标识关联不代表独立佐证；各来源的结论和证据分别保留。','muted'));
  await load();
}
async function status() {
  const [health,runs,enrichment]=await Promise.all([api('/health'),api('/api/v1/collection-runs'),api('/api/v1/enrichment/status')]);
  $('count').textContent=health.events; $('health').textContent=health.status==='ok'?'正常':'异常';
  const parts=health.version.split('.').map(Number);$('catalog-link').hidden=!(parts[0]>0||parts[1]>=12);
  $('enrichment-coverage').textContent=`${enrichment.enriched}/${enrichment.events}`;
  $('run-status').textContent=runs.length?(labels[runs[0].status]||runs[0].status):'尚无联网采集';
  $('runs').replaceChildren();
  if(!runs.length) $('runs').append(el('p','使用 CLI collect 启动联网采集。离线导入不计为联网采集记录。','muted'));
  for(const r of runs) $('runs').append(el('div',`${time(r.started_at)} · ${r.scope} · ${labels[r.status]||r.status} · ${JSON.stringify(r.stats)}${r.error?' · 错误类型 '+errorType(r.error):''}`,'run'));
}
$('search').onsubmit=e=>{e.preventDefault();offset=0;load();};
$('prev').onclick=()=>{offset=Math.max(0,offset-pageSize);load();};
$('next').onclick=()=>{offset+=pageSize;load();};
load();status().catch(error);

async function monitoring() {
  const snapshot=await overview();
  const data=snapshot.monitoring;
  $('monitor-counts').textContent=overviewText(snapshot);
  $('monitor-worker').textContent=workerText(snapshot);
  if(!data) { $('monitor-summary').textContent='来源最近成功时间未验证，请稍后刷新。'; return; }
  $('monitor-summary').textContent=`配置 ${data.configured_sources} 个来源、${data.configured_categories} 类来源；默认列表只展示命中规则的记录，待核验候选可切换查看。任务完成不代表采集进程常驻在线。`;
  $('monitor-targets').replaceChildren();
  for(const job of data.targets) {
    const row=el('div',undefined,'run');
    row.append(el('strong',`${job.id} · ${job.source_name}`),badge(labels[job.status]||job.status));
    row.append(el('div',`周期 ${job.interval_seconds/60} 分钟 · 上次成功 ${time(job.last_success_at)} · 下次计划 ${time(job.next_run_at)} · 连续失败 ${job.consecutive_failures}`));
    if(!job.config_current) row.append(el('div','配置尚未执行或已变更；等待下一轮同步。','muted'));
    if(job.has_pending_pages) row.append(el('div','已保存分页进度，下轮继续采集。','muted'));
    if(job.error) row.append(el('div','错误类型：'+errorType(job.error),'monitor-error'));
    $('monitor-targets').append(row);
  }
}
$('refresh-monitor').onclick=()=>Promise.all([monitoring(),status(),operations(),monitoringWindows()]).catch(error);
monitoring().catch(error);

async function monitoringWindows() {
  const root=$('monitor-windows');root.replaceChildren();
  for(const hours of [24,168]) {
    try {
      const report=await api(`/api/v1/monitoring/window?hours=${hours}`);
      const panel=el('details');
      const complete=report.targets.filter(t=>t.freshness_coverage===1).length;
      panel.append(el('summary',`${hours===24?'24 小时':'7 天'}：${report.status} · 完整覆盖 ${complete}/${report.targets.length}${report.status==='insufficient_coverage'?' · 仍有历史断档':''}`));
      panel.append(el('p',`${time(report.window_start)} 至 ${time(report.window_end)}；process_uptime_measured=${report.process_uptime_measured}；publication_latency_sla_proven=${report.publication_latency_sla_proven}`,'muted'));
      for(const target of report.targets) {
        const gaps=gapsFor(report,target);const row=el('details');
        row.append(el('summary',`${target.target_id} · 成功轮次覆盖 ${(target.freshness_coverage*100).toFixed(2)}% · ${gaps.length} 段未覆盖`));
        row.append(el('p',`成功 ${target.success_runs} 轮，失败/中断 ${target.failed_runs} 轮；新鲜度计算周期 ${target.freshness_horizon_seconds} 秒。`));
        for(const gap of gaps) row.append(el('p',`断档：${time(gap.from)} — ${time(gap.to)}`,'monitor-error'));
        panel.append(row);
      }
      root.append(panel);
    } catch { root.append(el('p',`${hours===24?'24 小时':'7 天'}窗口无法读取；覆盖状态未验证。`,'notice')); }
  }
}
monitoringWindows();

async function operations() {
  const [ops, evaluations, recovery, quality] = await Promise.all([
    api('/api/v1/operations/status'), api('/api/v1/operations/evaluations?limit=1'),
    api('/api/v1/operations/recovery-actions?limit=10'), api('/api/v1/enrichment/evaluations?limit=1')
  ]);
  const names = {passed:'通过', degraded:'需要处理', failed:'失败'};
  const checks = {raw_integrity:'原文完整性', enrichment_coverage:'富化覆盖', index_event_count:'检索索引对账', enrichment_state_count:'富化状态对账', monitor_configs_current:'监测配置', monitor_freshness:'来源新鲜度', no_failed_targets:'来源失败检查'};
  $('ops-summary').textContent = `${names[ops.status] || ops.status} · ${ops.collection.targets_fresh}/${ops.collection.configured_targets} 个任务在两个周期内同步成功 · 检查时间 ${time(ops.run_at)}`;
  $('ops-alerts').replaceChildren();
  for (const check of ops.checks.filter(c=>c.passed===false)) {
    const message = check.id==='monitor_freshness' ? '来源同步已超期，请查看采集进程或最近失败记录。' : '检查未通过，请查看运行报告。';
    $('ops-alerts').append(el('p', `${checks[check.id] || check.id}：${message}`, 'notice'));
  }
  const latest = evaluations[0];
  const suite = quality[0];
  $('ops-quality').textContent = `富化覆盖 ${ops.enrichment.enriched_events}/${ops.enrichment.events}；覆盖率不能作为准确率。` +
    (latest ? ` 最近原文审计 ${time(latest.run_at)}：${latest.integrity.verified}/${latest.integrity.raw_documents} 通过。` : ' 尚无原文审计快照。') +
    (suite ? ` 固定回归样本 ${suite.case_count} 个、${suite.assertion_count} 项断言，通过 ${(suite.assertion_accuracy*100).toFixed(1)}%；尚非独立盲测。` : ' 尚无富化评测。');
  $('ops-recovery').replaceChildren();
  if (!recovery.length) $('ops-recovery').append(el('p','暂无恢复记录。', 'muted'));
  for (const row of recovery) $('ops-recovery').append(el('p', `${time(row.occurred_at)} · ${row.action_type} · ${row.target_id||'全库派生数据'} · ${row.status}`));
}
operations().catch(error);
