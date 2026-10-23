const $ = id => document.getElementById(id);
const state = {offset: 0, limit: 10, listSeq: 0, detailSeq: 0, evidenceSeq: 0, selected: null, result: null};
const node = (tag, text, cls) => {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = text;
  if (cls) element.className = cls;
  return element;
};
const badgeLabels = {critical:'严重',high:'高危',medium:'中危',low:'低危',unknown:'未评级',live:'采集资料',replay:'回放资料',current:'当前版本',withdrawn:'已撤回',conflict:'严重性冲突'};
const badge = (text, cls = text) => node('span', badgeLabels[text] || text, `badge ${cls}`);
const date = value => value ? new Date(value).toLocaleString('zh-CN', {hour12: false}) : '未知';
const report = error => { $('message').textContent = error.message; };
async function api(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`接口请求失败（${response.status}），请检查服务后重试。`);
  return response.json();
}
function link(text, href) {
  const anchor = node('a', text);
  const url = new URL(href, location.origin);
  if (!['http:', 'https:'].includes(url.protocol)) return node('span', '来源地址不可打开');
  anchor.href = url.href; anchor.target = '_blank'; anchor.rel = 'noopener noreferrer';
  return anchor;
}
function download(name, payload) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(payload, null, 2)], {type: 'application/json'}));
  const anchor = node('a'); anchor.href = url; anchor.download = name;
  document.body.append(anchor); anchor.click(); anchor.remove();
  $('message').textContent = `已发起下载：${name}。请在浏览器下载列表中查看。`;
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function modeChanged() {
  const retrieval = $('mode').value === 'retrieval';
  $('origin-label').hidden = !retrieval; $('pool-label').hidden = !retrieval; $('alias-label').hidden = retrieval;
  for (const id of ['entity-type-label', 'entity-value-label', 'cpe-label', 'quality-label']) $(id).hidden = !retrieval;
  $('search-hint').textContent = retrieval
    ? '正式集合只含 relevant；needs_review 保持在候选集合。检索读取持久索引，分数表示词项匹配程度，不是置信度。'
    : '标题 / GHSA 为字面子串检索；CVE 与组件为精确过滤。查看详情可区分 live / replay。';
  state.offset = 0; load();
}
async function load() {
  const sequence = ++state.listSeq;
  state.result = null; $('export-results').hidden = true;
  $('message').textContent = ''; $('events').replaceChildren(node('p', '正在读取情报…', 'muted'));
  $('prev').disabled = true; $('next').disabled = true;
  const retrieval = $('mode').value === 'retrieval';
  const query = $('query').value.trim();
  $('results-title').textContent = retrieval ? '证据检索' : '情报列表';
  if (retrieval && !query) {
    $('events').replaceChildren(node('p', '输入关键词后开始检索，例如 vllm、denial of service 或 CVE 编号。', 'empty'));
    $('total').textContent = '待查询'; $('page').textContent = '—'; return;
  }
  const params = new URLSearchParams({limit: state.limit, offset: state.offset, include_withdrawn: $('withdrawn').checked});
  if (query) params.set('q', query);
  for (const key of ['package', 'severity']) if ($(key).value.trim()) params.set(key, $(key).value.trim());
  for (const key of ['source', 'kind']) if ($(key).value) params.set(key === 'source' ? 'source_id' : key, $(key).value);
  if (retrieval) {
    params.set('origin', $('origin').value);
    if ($('pool').value) params.set('pool', $('pool').value);
    if ($('entity-type').value && $('entity-value').value.trim()) {
      params.set('entity_type', $('entity-type').value);
      params.set('entity_value', $('entity-value').value.trim());
    }
    if ($('cpe').value.trim()) params.set('cpe', $('cpe').value.trim());
    if ($('quality').value) params.set('quality_flag', $('quality').value);
  }
  else if ($('alias').value.trim()) params.set('alias', $('alias').value.trim());
  try {
    const data = await api(`${retrieval ? '/api/v1/retrieval/search' : '/api/v1/events'}?${params}`);
    if (sequence !== state.listSeq) return;
    state.result = retrieval ? {saved_at: new Date().toISOString(), filters: Object.fromEntries(params), ...data} : null;
    $('export-results').hidden = !retrieval || !data.items.length;
    $('total').textContent = `${data.total} ${retrieval ? '片段' : '条'}`;
    $('events').replaceChildren();
    if (!data.items.length) $('events').append(node('p', retrieval ? '没有匹配的证据。可调整关键词、组件或 live / replay 资料范围；当前不进行语义推断。' : '没有匹配的情报，请调整筛选条件或先导入资料。', 'empty'));
    for (const item of data.items) {
      const id = retrieval ? item.citation.event_id : item.id;
      const row = node('button', undefined, `event${id === state.selected ? ' selected' : ''}`);
      row.dataset.id = id;
      row.append(node('strong', item.title));
      if (retrieval) {
        row.append(badge(item.citation.origin), badge(`v${item.citation.revision}`), badge(item.field));
        row.append(node('p', item.text, 'snippet'), node('small', `匹配词：${item.matched_terms.join(' / ')} · 分数 ${item.score}`));
      } else row.append(badge(item.severity), badge(`v${item.revision}`));
      if (item.withdrawn || item.withdrawn_at) row.append(badge('已撤回', 'withdrawn'));
      row.append(node('small', item.external_id));
      row.onclick = () => show(id, retrieval ? item.citation.revision : undefined);
      $('events').append(row);
    }
    $('prev').disabled = state.offset === 0; $('next').disabled = state.offset + state.limit >= data.total;
    $('page').textContent = data.total ? `${state.offset + 1}–${Math.min(state.offset + state.limit, data.total)}` : '0';
  } catch (error) {
    if (sequence !== state.listSeq) return;
    $('events').replaceChildren(node('p', '加载失败，请点击查询重试。', 'empty'));
    $('total').textContent = '—'; $('page').textContent = '—'; report(error);
  }
}

function flatten(value, prefix = '', output = {}) {
  if (value !== null && typeof value === 'object' && Object.keys(value).length) {
    for (const [key, item] of Object.entries(value)) flatten(item, prefix ? `${prefix}.${key}` : key, output);
  } else output[prefix] = JSON.stringify(value);
  return output;
}
function versionLabel(revision) { return `v${revision.number} · ${revision.disposition}`; }
function structuredSummary(enrichment) {
  const section = node('section'); section.append(node('h3', '结构化摘要'));
  if (!enrichment) {
    section.append(node('p', '尚无结构化富化结果。', 'notice')); return section;
  }
  const box = node('div', undefined, 'structured-summary');
  box.append(badge(enrichment.schema_version, 'derived'), node('p', '以下内容是可重建派生数据，事实引用仍须回到右侧原文。', 'muted'));
  box.append(node('h4', '实体'));
  const entities = node('div', undefined, 'quality-list');
  for (const item of enrichment.entities || []) entities.append(badge(`${item.type}: ${item.value}`, 'derived'));
  box.append(entities.childElementCount ? entities : node('p', '未提取到实体。', 'muted'));
  box.append(node('h4', 'CVSS 展示'));
  const selected = enrichment.cvss?.selected;
  box.append(node('p', selected ? `${selected.version} · ${selected.score} · ${selected.vector}` : '来源未提供可用 CVSS。', selected ? '' : 'muted'));
  if ((enrichment.cvss?.entries || []).length > 1) box.append(node('p', `来源共有 ${enrichment.cvss.entries.length} 个评分条目；展示项不是系统重新评分。`, 'notice'));
  box.append(node('h4', '版本表达式'));
  if (!(enrichment.version_ranges || []).length) box.append(node('p', '来源未提供结构化版本范围。', 'muted'));
  for (const item of enrichment.version_ranges || []) {
    if (item.source_kind === 'nvd_affected_data') {
      const identity = [item.vendor, item.product, item.packageName, item.packageURL].filter(Boolean).join(' · ') || 'NVD affectedData';
      box.append(node('p', `${identity} · 发布方 ${item.authority || '未说明'} · 默认状态 ${item.defaultStatus || 'unknown'} · 版本事实 ${JSON.stringify(item.version_status)} · 原文 ${item.json_pointer}`, 'muted'));
      continue;
    }
    const vulnerable = item.vulnerable ? `${item.vulnerable.raw || '未知'}（${item.vulnerable.status}）` : '未提供';
    const fixed = item.fixed ? `${item.fixed.raw || '未知'}（${item.fixed.status}）` : '未提供';
    box.append(node('p', `${item.ecosystem} / ${item.package} · 影响 ${vulnerable} · 修复 ${fixed}`, 'muted'));
  }
  box.append(node('h4', 'CPE 来源条件'));
  if (!(enrichment.cpe_matches || []).length) box.append(node('p', '来源未提供 CPE 条件。', 'muted'));
  for (const item of enrichment.cpe_matches || []) box.append(node('p', `${item.criteria} · vulnerable=${item.vulnerable}`, 'muted'));
  box.append(node('h4', '资料质量标记'));
  const flags = node('div', undefined, 'quality-list');
  for (const flag of enrichment.quality_flags || []) flags.append(badge(flag, 'quality'));
  box.append(flags.childElementCount ? flags : node('p', '当前规则未标记资料缺口。', 'muted'));
  section.append(box); return section;
}
function comparison(history, current) {
  const section = node('section'); section.append(node('h3', '版本对比'));
  if (history.length < 2) { section.append(node('p', '当前仅有一个版本，后续更新后可逐字段比较。', 'muted')); return section; }
  section.append(node('p', 'stale 为旧资料，conflict 为冲突资料；两者均不代表当前事实。', 'muted'));
  const controls = node('div', undefined, 'version-controls');
  const selects = ['对比版本', '基准版本'].map((text, i) => {
    const label = node('label', text); const select = node('select'); select.setAttribute('aria-label', text);
    for (const rev of history) { const option = node('option', versionLabel(rev)); option.value = rev.number; select.append(option); }
    const previous = history.find(rev => rev.number < current.number && rev.disposition === 'superseded') || history.find(rev => rev.number !== current.number);
    select.value = i ? current.number : previous.number; label.append(select); controls.append(label); return select;
  });
  const changes = node('div');
  function render() {
    const left = flatten(history.find(rev => rev.number === Number(selects[0].value)).normalized);
    const right = flatten(history.find(rev => rev.number === Number(selects[1].value)).normalized);
    const keys = [...new Set([...Object.keys(left), ...Object.keys(right)])].filter(key => left[key] !== right[key]).sort();
    changes.replaceChildren();
    if (!keys.length) { changes.append(node('p', '两个版本的归一化字段相同。', 'muted')); return; }
    const table = node('table'), head = node('tr');
    for (const text of ['变化字段', `v${selects[0].value}`, `v${selects[1].value}`]) head.append(node('th', text));
    const thead = node('thead'); thead.append(head); table.append(thead); const body = node('tbody');
    for (const key of keys) { const row = node('tr'); for (const text of [key, left[key] ?? '（不存在）', right[key] ?? '（不存在）']) row.append(node('td', text)); body.append(row); }
    table.append(body); changes.append(table);
  }
  selects.forEach(select => { select.onchange = render; }); render(); section.append(controls, changes); return section;
}

async function show(id, pinnedRevision) {
  const sequence = ++state.detailSeq; ++state.evidenceSeq; state.selected = id;
  document.querySelectorAll('.event').forEach(item => item.classList.toggle('selected', item.dataset.id === id));
  $('detail').className = ''; $('evidence').className = ''; $('message').textContent = '';
  $('detail').replaceChildren(node('p', '正在读取情报…', 'muted')); $('evidence').replaceChildren();
  $('reader-state').textContent = '加载中';
  try {
    // Read history first so the detail snapshot cannot precede the history's current version.
    const history = await api(`/api/v1/events/${id}/history`);
    if (sequence !== state.detailSeq) return;
    const data = await api(`/api/v1/events/${id}`);
    if (sequence !== state.detailSeq) return;
    const revisions = [...history.filter(rev => rev.number !== data.revision).map(rev => (
      rev.disposition === 'current' ? {...rev, disposition: 'superseded'} : rev
    )), data.current_revision].sort((left, right) => right.number - left.number);
    const viewed = pinnedRevision === undefined ? data.current_revision : revisions.find(rev => rev.number === pinnedRevision);
    if (!viewed) throw new Error('引用版本不存在，请重新检索。');
    const content = viewed.normalized;
    const box = $('detail'); box.replaceChildren(node('h3', content.title, 'title'));
    $('reader-state').textContent = `阅读 v${viewed.number} / 当前 v${data.revision}`;
    box.append(badge(content.severity), badge(versionLabel(viewed), viewed.disposition), badge('来源声明'));
    if (content.withdrawn_at) box.append(badge('已撤回', 'withdrawn'));
    if (viewed.number === data.revision && data.triage) box.append(badge(data.triage.label), badge(data.triage.category));
    if (viewed.number !== data.revision) box.append(node('p', '正在阅读检索时引用的历史版本；当前版本已变化，请对照历史核查。', 'notice'));
    box.append(node('p', `${content.external_id} · ${(content.aliases || []).join(' / ')}`, 'muted'));
    box.append(node('p', `来源更新 ${date(content.source_updated_at)} · 人工状态 ${data.review_status}`, 'muted'));
    if (viewed.number === data.revision) box.append(structuredSummary(data.enrichment));
    else box.append(node('p', '结构化摘要只对应当前版本；历史版本请直接核对来源字段。', 'notice'));
    box.append(node('h3', '影响组件'));
    for (const pkg of content.packages || []) {
      const card = node('div', undefined, 'package'); card.append(node('strong', `${pkg.ecosystem} / ${pkg.name}`), node('div', `影响范围：${pkg.vulnerable_range}`), node('div', `首个修复版本：${pkg.fixed_version || '未知'}`)); box.append(card);
    }
    if (!content.packages?.length) box.append(node('p', '来源未提供组件信息。', 'muted'));
    box.append(node('p', '版本范围来自公告；尚未执行资产匹配。修复版本未知不等于不存在修复。', 'muted'));
    box.append(node('h3', '来源描述'), node('div', content.description || '来源未提供描述。', 'description'));
    const actions = node('div', undefined, 'actions'); actions.append(link('查看来源公告 ↗', content.source_url));
    const exportInput = node('button', '导出当前版本检索输入');
    exportInput.onclick = async () => {
      exportInput.disabled = true;
      try { const chunks = await api(`/api/v1/retrieval/events/${id}`); download(`${content.external_id}-retrieval-input.json`, {saved_at: new Date().toISOString(), chunks}); }
      catch (error) { report(error); } finally { exportInput.disabled = false; }
    };
    actions.append(exportInput); box.append(actions, comparison(revisions, data.current_revision));
    const selector = node('select'); selector.setAttribute('aria-label', '引用版本');
    for (const rev of revisions) { const option = node('option', versionLabel(rev)); option.value = rev.number; selector.append(option); }
    selector.value = viewed.number;
    const evidenceBox = node('div'); $('evidence').append(node('label', '查看指定版本的证据'), selector, evidenceBox);
    selector.onchange = () => showEvidence(id, revisions.find(rev => rev.number === Number(selector.value)), evidenceBox, sequence);
    await showEvidence(id, viewed, evidenceBox, sequence);
  } catch (error) {
    if (sequence !== state.detailSeq) return;
    $('reader-state').textContent = '加载失败'; $('detail').replaceChildren(node('p', '读取失败，请重新选择情报。', 'empty')); report(error);
  }
}

async function showEvidence(id, revision, box, detailSequence) {
  const sequence = ++state.evidenceSeq;
  box.replaceChildren(node('p', '读取证据…', 'muted'));
  try {
    const raw = await api(`/api/v1/raw-documents/${revision.raw_document_id}`);
    if (detailSequence !== state.detailSeq || sequence !== state.evidenceSeq) return;
    box.replaceChildren(badge(raw.origin), badge(versionLabel(revision), revision.disposition));
    if (raw.origin === 'replay') box.append(node('p', '离线回放资料；演示样本不构成真实漏洞证据。', 'notice'));
    if (['conflict', 'stale', 'superseded'].includes(revision.disposition)) box.append(node('p', '此版本非当前有效事实，仅供追溯与比较。', 'notice'));
    const kv = node('dl', undefined, 'kv');
    for (const [key, value] of [['事件 ID', id], ['版本', revision.number], ['原文 ID', raw.id], ['获取时间', date(raw.first_fetched_at)], ['SHA-256', raw.sha256]]) kv.append(node('dt', key), node('dd', value));
    box.append(kv, link('查看该版本完整原文 JSON ↗', `/api/v1/raw-documents/${raw.id}/content`));
    const payload = {saved_at: new Date().toISOString(), event_id: id, revision: revision.number, raw_document_id: raw.id, sha256: raw.sha256, origin: raw.origin, disposition_at_export: revision.disposition, evidence: revision.evidence};
    const save = node('button', '保存此版本引用 JSON', 'primary'); save.onclick = () => download(`citation-v${revision.number}-${id}.json`, payload); box.append(save);
    for (const evidence of revision.evidence) {
      const item = node('details'), summary = node('summary', evidence.field);
      summary.append(node('span', evidence.json_pointer, 'pointer'));
      item.append(summary, node('pre', JSON.stringify(evidence.value, null, 2))); box.append(item);
    }
  } catch (error) {
    if (detailSequence !== state.detailSeq || sequence !== state.evidenceSeq) return;
    box.replaceChildren(node('p', '证据读取失败，请重新选择版本。', 'notice')); report(error);
  }
}
$('search').onsubmit = event => { event.preventDefault(); state.offset = 0; load(); };
$('mode').onchange = modeChanged;
$('prev').onclick = () => { state.offset = Math.max(0, state.offset - state.limit); load(); };
$('next').onclick = () => { state.offset += state.limit; load(); };
$('export-results').onclick = () => { if (state.result) download('zhidu-retrieval-results.json', state.result); };
async function loadReviewQueue() {
  $('review-queue').replaceChildren(node('p', '正在读取复核队列…', 'muted'));
  const params = new URLSearchParams({limit: 12});
  if ($('review-quality').value) params.set('quality_flag', $('review-quality').value);
  if ($('review-source').value) params.set('source_id', $('review-source').value);
  try {
    const data = await api(`/api/v1/review-queue?${params}`);
    $('review-total').textContent = `${data.total} 条待复核`;
    $('review-queue').replaceChildren();
    if (!data.items.length) $('review-queue').append(node('p', '当前筛选下没有待复核记录。', 'muted'));
    for (const item of data.items) {
      const card = node('button', undefined, 'review-card');
      card.append(node('strong', item.title), node('p', `${item.external_id} · ${item.source_id}`, 'muted'));
      card.append(badge(`priority ${item.priority}`, 'derived'), badge(item.review_status), badge(item.ai_label));
      const flags = node('div', undefined, 'quality-list');
      for (const flag of item.quality_flags) flags.append(badge(flag, 'quality'));
      card.append(flags); card.onclick = () => openSource(item.event_id); $('review-queue').append(card);
    }
  } catch (error) {
    $('review-total').textContent = '读取失败'; $('review-queue').replaceChildren(node('p', '复核队列加载失败。', 'notice'));
  }
}
$('review-refresh').onclick = loadReviewQueue;
$('review-quality').onchange = loadReviewQueue;
$('review-source').onchange = loadReviewQueue;
async function loadComparisons() {
  $('comparisons').replaceChildren(node('p', '正在读取跨来源比较…', 'muted'));
  const params = new URLSearchParams({limit: 50});
  if ($('comparison-id').value.trim()) params.set('identifier', $('comparison-id').value.trim());
  if ($('comparison-status').value) params.set('status', $('comparison-status').value);
  if ($('comparison-review').value) params.set('review_status', $('comparison-review').value);
  if ($('comparison-inactive').checked) params.set('include_inactive', 'true');
  try {
    const data = await api(`/api/v1/comparisons?${params}`);
    $('comparison-total').textContent = `${data.total} 项`;
    $('comparisons').replaceChildren();
    if (!data.items.length) $('comparisons').append(node('p', '当前筛选下没有跨来源比较。', 'muted'));
    for (const item of data.items) {
      const card = node('article', undefined, 'comparison-card');
      const meta = node('div', undefined, 'comparison-meta');
      meta.append(node('h3', `${item.identifier} · ${item.field}`), badge(item.status, item.status), badge(item.review_status));
      card.append(meta);
      if (!item.is_active) card.append(node('p', '已归档：仅用于历史追溯，不参与当前事实判断。', 'notice'));
      if (item.analyst_note) card.append(node('p', `人工备注：${item.analyst_note}`, 'notice'));
      if (item.status === 'conflict') {
        card.append(node('p', '严重性观察互相冲突；人工复核只记录状态与备注，不选择事实胜方。', 'muted'));
        const trace = node('button', '查看 trace 核验与复核版本'); trace.type = 'button';
        trace.onclick = () => loadConflictContext(item.id); card.append(trace);
      }
      const grid = node('div', undefined, 'observation-grid');
      for (const observation of item.observations) {
        const pane = node('section', undefined, 'observation');
        pane.append(node('strong', `${observation.source_id} · ${observation.external_id}`));
        pane.append(node('pre', JSON.stringify(observation.value, null, 2)));
        pane.append(node('p', `revision ${observation.revision_id} · ${observation.json_pointer || '字段集合'}`, 'pointer'));
        const actions = node('div', undefined, 'actions');
        const open = node('button', '进入情报阅读该来源'); open.type = 'button'; open.onclick = () => openSource(observation.event_id);
        actions.append(open);
        if (observation.raw_document_id) actions.append(link('查看原文 ↗', `/api/v1/raw-documents/${observation.raw_document_id}/content`));
        pane.append(actions); grid.append(pane);
      }
      card.append(grid); $('comparisons').append(card);
    }
  } catch (error) {
    $('comparison-total').textContent = '读取失败'; $('comparisons').replaceChildren(node('p', '跨来源比较加载失败。', 'notice'));
  }
}
async function loadConflictContext(comparisonId) {
  const root = $('conflict-review-context'); root.className = 'conflict-context';
  root.replaceChildren(node('p', '正在读取来源 trace…', 'muted'));
  try {
    const data = await api(`/api/v1/comparisons/${comparisonId}/review-context`);
    root.replaceChildren(node('strong', `${data.comparison.identifier} · ${data.comparison.field} · ${data.comparison.status}`));
    root.append(node('p', data.note, 'muted'));
    const grid = node('div', undefined, 'conflict-source-grid');
    for (const item of data.source_traces) {
      const pane = node('article', undefined, 'conflict-source');
      pane.append(node('strong', `${item.observation.source_id} · ${item.observation.external_id}`));
      pane.append(node('pre', JSON.stringify(item.observation.value, null, 2)));
      pane.append(node('p', `${item.trace.summary.revisions} 个 revision · 字段证据 ${item.trace.summary.field_evidence_verified}/${item.trace.summary.field_evidence_total} · ${item.evidence_refs.length} 个完整引用`, 'pointer'));
      grid.append(pane);
    }
    root.append(grid);
    const history = node('div', undefined, 'review-history');
    history.append(node('strong', '复核前后版本'));
    if (!data.review_transitions.length) history.append(node('p', '尚无人工复核变更；当前为 unreviewed v0。', 'muted'));
    for (const item of data.review_transitions) {
      history.append(node('p', `${item.change_kind || '历史人工记录'} · v${item.before.version} ${item.before.review_status} → v${item.after.version} ${item.after.review_status} · ${item.after.analyst_note || '无备注'}`, 'muted'));
      if (item.observations) { const details = node('details'); details.append(node('summary', '变更前来源观察（历史快照）'), node('pre', JSON.stringify(item.observations, null, 2))); history.append(details); }
    }
    root.append(history);
  } catch (error) { root.replaceChildren(node('p', '冲突 trace 加载失败。', 'notice')); }
}
$('comparison-refresh').onclick = loadComparisons;
$('comparison-id').addEventListener('keydown',event=>{if(event.key==='Enter'){event.preventDefault();loadComparisons();}});
$('comparison-example').onclick=()=>{$('comparison-id').value='CVE-2026-73557';$('comparison-status').value='';$('comparison-review').value='';$('comparison-inactive').checked=false;loadComparisons();};
$('comparison-status').onchange = loadComparisons;
$('comparison-review').onchange = loadComparisons;
$('comparison-inactive').onchange = loadComparisons;
let assetRows = [];
function openSource(eventId) {
  window.dispatchEvent(new CustomEvent('zhidu-open-view',{detail:{view:'intelligence'}}));
  return show(eventId);
}
window.addEventListener('zhidu-source-example',event=>{
  $('mode').value='events';
  for(const id of ['query','package','severity','source','kind'])$(id).value='';
  $('withdrawn').checked=false;$('alias').value=event.detail.identifier;
  modeChanged();
});
function showAssetSummary() {
  const asset = assetRows.find(item => item.id === $('asset-context').value);
  $('asset-report').disabled = !asset;
  if (!asset) { $('asset-summary').textContent = assetRows.length ? '请选择一项资产，才能展示组件、版本条件与来源判断。' : '当前没有导入资产。可通过资产管理页查看导入方法；未导入不表示不存在风险，也不能据公告推断你的资产已受影响。'; return; }
  $('asset-summary').textContent = `${asset.name} · ${asset.environment} · ${asset.component_count} 个组件 · affected ${asset.exposure_counts.affected} / not_affected ${asset.exposure_counts.not_affected} / unknown ${asset.exposure_counts.unknown} · SBOM ${asset.sbom_sha256}`;
}
async function loadAssets() {
  try {
    assetRows = await api('/api/v1/assets'); $('asset-total').textContent = `${assetRows.length} 个资产`;
    $('asset-context').disabled = assetRows.length===0;
    for (const asset of assetRows) { const option = node('option', `${asset.name} · ${asset.environment}`); option.value = asset.id; $('asset-context').append(option); }
    showAssetSummary();
  } catch (error) { $('asset-total').textContent = '读取失败'; $('asset-summary').textContent='资产清单读取失败，请稍后刷新；当前未验证资产状态。'; }
}
$('asset-context').onchange = showAssetSummary;
$('asset-report').onclick = async () => {
  const assetId = $('asset-context').value; if (!assetId) return;
  $('asset-report').disabled = true;
  try { const payload = await api(`/api/v1/assets/${assetId}/report`); download(`zhidu-asset-report-${assetId}.json`, payload); }
  catch (error) { report(error); } finally { $('asset-report').disabled = false; }
};
function renderConversation(data) {
  const conversation = data.conversation;
  $('conversation-summary').textContent = `${conversation.title} · ${conversation.message_count} 条消息 · ${conversation.pending_evidence_tasks} 个 pending 补证任务 · ${conversation.active_asset ? `显式资产 ${conversation.active_asset.name}` : '未选择资产'} · replay ${data.replay_sha256}`;
  $('conversation-messages').replaceChildren();
  const tasks = [];
  for (const message of data.messages) {
    if (message.role !== 'assistant') { const question=node('p', `问题：${message.content}`); $('conversation-messages').append(question); continue; }
    const card = node('article', undefined, 'conversation-message');
    card.append(node('h3', `第 ${message.sequence} 条 · ${message.answer_status} · 资产 ${message.effective_asset_id || '未选择'}`));
    card.append(node('pre', message.content));
    const hops = node('div', undefined, 'hop-list');
    for (const hop of message.hops) {
      const hopCard = node('section', undefined, 'hop-card');
      const details = node('details');
      details.append(node('summary', `${hop.hop_order}. ${hop.hop_type}`));
      if (hop.hop_type === 'rag_generation') {
        const run = hop.output_data;
        hopCard.append(node('p', `请求 ${run.requested_generation?.model || '未知'} · 实际 ${run.generation_model || '无'} · ${run.generation?.status || '未知'} · ${run.elapsed_ms ?? '未记录'} ms · token ${run.generation?.usage?.total_tokens ?? '未返回'}`, 'muted'));
      }
      details.append(node('pre', JSON.stringify(hop.output_data, null, 2)));
      const refs = (hop.evidence_refs || []).map(ref => `${ref.event_id} / ${ref.revision_id} / ${ref.raw_document_id} / ${ref.json_pointer}`).join('\n');
      details.append(node('p', refs || '本跳没有完整证据引用', 'hop-refs'));
      hopCard.prepend(details); hops.append(hopCard);
    }
    card.append(hops); $('conversation-messages').append(card); tasks.push(...message.evidence_tasks);
  }
  $('conversation-tasks').replaceChildren();
  if (!tasks.length) $('conversation-tasks').append(node('p', '该会话尚无动态补证任务。', 'muted'));
  for (const task of tasks) {
    const card = node('article', undefined, `task-card ${task.status}`);
    card.append(node('h4', `${task.task_type} · ${task.status} / ${task.network_verification_status}`));
    card.append(node('p', `缺少：${task.missing_fields.join('、')} · 目标来源：${task.target_sources.join('、')}`, 'muted'));
    card.append(node('p', `完成条件：${task.completion_conditions.join('；')}`)); $('conversation-tasks').append(card);
  }
}
async function loadConversationDetail() {
  const id = $('conversation-select').value;
  $('conversation-recommendations').replaceChildren();
  if (!id) { $('conversation-summary').textContent = '尚未选择会话。'; $('conversation-messages').replaceChildren(); $('conversation-tasks').replaceChildren(); return; }
  $('conversation-summary').textContent = '正在从数据库重放会话…';
  try {
    const data = await api(`/api/v1/conversations/${id}/replay`); renderConversation(data);
    const validity = await api(`/api/v1/conversations/${id}/context-status`);
    for (const item of validity.comparisons.filter(item => item.stale)) {
      $('conversation-messages').prepend(node('p', `${item.identifier} 的历史快照 v${item.snapshot_version}：${item.is_active ? '来源已更新，需重新复核' : '比较已归档，仅保留追溯'}。补证任务保持历史记录，不表示已核验。`, 'notice'));
    }
    if (!data.conversation.active_asset) { $('conversation-recommendations').append(node('p', '会话没有显式选择资产，因此不生成个性化建议。', 'muted')); return; }
    const recs = await api(`/api/v1/conversations/${id}/recommendations?limit=8`);
    if (!recs.recommendations.length) $('conversation-recommendations').append(node('p', '当前没有 affected/unknown 建议。', 'muted'));
    for (const item of recs.recommendations) {
      const card = node('article', undefined, 'recommendation-card');
      card.append(node('h4', `${item.priority} · ${item.action} · rule_score ${item.rule_score}`));
      card.append(node('p', `${item.component.name}@${item.component.version} · ${item.event.external_id} · ${item.exposure_status}`));
      card.append(node('p', item.advice, 'muted')); $('conversation-recommendations').append(card);
    }
  } catch (error) { $('conversation-summary').textContent = `会话重放失败：${error.message || '请重试'}`; }
}
async function loadConversations() {
  try {
    const rows = await api('/api/v1/conversations?limit=50');
    $('conversation-total').textContent = `${rows.length} 个会话`;
    const selected = $('conversation-select').value;
    const placeholder = node('option', '选择会话'); placeholder.value = '';
    $('conversation-select').replaceChildren(placeholder);
    for (const item of rows) { const option = node('option', `${item.title} · ${item.message_count} 条`); option.value = item.id; $('conversation-select').append(option); }
    if (rows.some(item => item.id === selected)) $('conversation-select').value = selected;
    else if (rows.length) $('conversation-select').value = rows[0].id;
    await loadConversationDetail();
  } catch (error) { $('conversation-total').textContent = '读取失败'; }
}
$('conversation-refresh').onclick = loadConversations;
$('conversation-select').onchange = async () => { await loadConversationDetail(); window.dispatchEvent(new CustomEvent('zhidu-conversation-selected', {detail: $('conversation-select').value})); };
load();
loadReviewQueue();
loadComparisons();
loadAssets();
loadConversations();
api('/health').then(data => { $('health').textContent = `${data.events} 条情报 · 服务正常`; }).catch(() => { $('health').textContent = '服务不可用'; });
api('/api/v1/retrieval/index').then(data => {
  $('index-health').textContent = `当前索引 · ${Number(data.chunks).toLocaleString('zh-CN')} 个片段`;
  $('index-health').title = data.schema_version || '';
}).catch(() => { $('index-health').textContent = '索引不可用'; });
api('/api/v1/sources').then(items => {
  for (const source of items) {
    const option=node('option',source.name); option.value=source.id; $('source').append(option);
    const reviewOption=node('option',source.name); reviewOption.value=source.id; $('review-source').append(reviewOption);
  }
}).catch(report);
api('/api/v1/answer-audits?limit=6').then(items => {
  $('audit-total').textContent = `最近 ${items.length} 条`; $('audits').replaceChildren();
  if (!items.length) $('audits').append(node('p','尚无审计记录。可通过问答审计 API 保存抽取式或外部模型回答。','muted'));
  for (const item of items) {
    const card=node('article',undefined,'audit-card');
    card.append(node('strong',item.question),node('p',`${item.model} · ${item.prompt_version} · ${item.pool}`,'muted'),node('p',item.answer,'audit-answer'),node('p',`${item.citations.length} 条引用 · ${date(item.created_at)}`,'muted'));
    $('audits').append(card);
  }
}).catch(() => { $('audit-total').textContent='读取失败'; });

window.addEventListener('zhidu-conversation-updated', async event => { await loadConversations(); $('conversation-select').value=event.detail; await loadConversationDetail(); });
