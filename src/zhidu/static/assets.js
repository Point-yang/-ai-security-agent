const $ = (id) => document.getElementById(id);
const node = (tag, text, cls) => {
  const item = document.createElement(tag);
  if (text !== undefined) item.textContent = text;
  if (cls) item.className = cls;
  return item;
};
const badge = (value) => node('span', value, `badge ${value}`);

async function api(path) {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`接口 ${response.status}：${path}`);
  return response.json();
}

function fail(error) {
  $('message').textContent = error.message;
}

function renderEventTrace(data) {
  const box = $('trace');
  box.replaceChildren();
  const summary = data.summary;
  box.append(
    node('h3', `${data.event.external_id} · ${summary.revisions} 个观察版本`),
    node(
      'p',
      `字段证据 ${summary.field_evidence_verified}/${summary.field_evidence_total} 已通过原文哈希与 JSON Pointer 复验。`,
      summary.field_evidence_failed ? 'notice' : 'verified-line',
    ),
  );
  for (const revision of [...data.timeline].reverse()) {
    const row = node('details');
    const title = node('summary');
    title.append(
      badge(revision.disposition),
      node('strong', `revision ${revision.number}`),
      node('span', ` · 变更 ${revision.delta_from_previous_observation.length} 个字段`, 'muted'),
    );
    const meta = revision.raw_document;
    row.append(
      title,
      node('p', `${meta.source_id} · ${meta.origin} · SHA-256 ${meta.sha256}`, 'muted'),
      node('pre', JSON.stringify(revision.delta_from_previous_observation, null, 2)),
    );
    box.append(row);
  }
}

async function showEventTrace(eventId) {
  $('trace').replaceChildren(node('p', '正在复验字段证据与历史版本…', 'muted'));
  renderEventTrace(await api(`/api/v1/events/${eventId}/trace`));
}

async function showAssetGraph(assetId) {
  const box = $('trace');
  box.replaceChildren(node('p', '正在构建资产 → 组件 → 事件 → 版本 → 原文证据链…', 'muted'));
  const data = await api(`/api/v1/assets/${assetId}/evidence-graph`);
  box.replaceChildren(
    node('h3', `${data.asset.name} · 证据图`),
    node(
      'p',
      `${data.summary.chains} 条链路；字段证据 ${data.summary.field_evidence_verified}/${data.summary.field_evidence_total} 可复验；来源指针 ${data.summary.source_pointers_verified}/${data.summary.source_pointers_total} 可定位。`,
      'verified-line',
    ),
    node('p', '证据完整性可复验不等于漏洞可复现。', 'notice'),
  );
  for (const chain of data.chains) {
    const row = node('details');
    const title = node('summary');
    title.append(
      badge(chain.status),
      node('strong', `${chain.component.name}@${chain.component.version}`),
      node('span', ` → ${chain.event.external_id}`, 'muted'),
    );
    row.append(
      title,
      node('p', chain.reason),
      node('p', `${chain.event.source_id} · revision ${chain.revision.number} · ${chain.raw_document.sha256}`, 'muted'),
    );
    const button = node('button', '查看该事件历史');
    button.addEventListener('click', () => showEventTrace(chain.event.id).catch(fail));
    row.append(button);
    box.append(row);
  }
}

async function showAsset(id) {
  const data = await api(`/api/v1/assets/${id}/exposures?limit=500`);
  const box = $('exposures');
  box.replaceChildren();
  const graphButton = node('button', '生成完整证据追溯图', 'primary-action');
  graphButton.addEventListener('click', () => showAssetGraph(id).catch(fail));
  box.append(graphButton);
  if (!data.items.length) {
    box.append(node('p', '没有组件与当前来源身份条件匹配。', 'muted'));
    return;
  }
  for (const item of data.items) {
    const row = node('details');
    const title = node('summary');
    title.append(
      badge(item.status),
      node('strong', `${item.component.ecosystem}/${item.component.name}@${item.component.version}`),
      node('span', ` · ${item.event.external_id}`, 'muted'),
    );
    const traceButton = node('button', '复验字段与历史');
    traceButton.addEventListener('click', () => showEventTrace(item.event.id).catch(fail));
    row.append(
      title,
      node('p', item.reason),
      node('p', `${item.event.source_id} · ${item.match_method} · revision ${item.revision_id}`, 'muted'),
      traceButton,
    );
    box.append(row);
  }
}

async function load() {
  const [assets, comparisons] = await Promise.all([
    api('/api/v1/assets'),
    api('/api/v1/comparisons?limit=500'),
  ]);
  $('asset-count').textContent = assets.length;
  $('affected-count').textContent = assets.reduce((n, a) => n + a.exposure_counts.affected, 0);
  $('unknown-count').textContent = assets.reduce((n, a) => n + a.exposure_counts.unknown, 0);
  $('conflict-count').textContent = comparisons.items.filter((item) => item.status === 'conflict').length;
  $('assets').replaceChildren();
  if (!assets.length) $('assets').append(node('p', '尚未导入资产。使用 zhidu asset-import 导入 CycloneDX JSON。', 'muted'));
  for (const asset of assets) {
    const button = node('button', undefined, 'event');
    button.append(
      node('strong', asset.name),
      badge(asset.criticality),
      node('small', `${asset.environment} · ${asset.component_count} 个组件 · affected ${asset.exposure_counts.affected}`),
    );
    button.addEventListener('click', () => showAsset(asset.id).catch(fail));
    $('assets').append(button);
  }
  $('comparisons').replaceChildren();
  if (!comparisons.items.length) $('comparisons').append(node('p', '当前没有满足跨来源比较条件的字段。', 'muted'));
  for (const item of comparisons.items) {
    const row = node('details');
    const title = node('summary');
    title.append(badge(item.status), node('strong', `${item.identifier} · ${item.field}`));
    row.append(title, node('pre', JSON.stringify(item.observations, null, 2)));
    $('comparisons').append(row);
  }
}

load().catch(fail);
