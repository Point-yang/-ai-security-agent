// Shared display policy: source freshness, API readiness and process pulse stay distinct.
export const formatTime = value => value ? new Date(value).toLocaleString('zh-CN', {hour12:false}) : '未知';
export function errorType(error) {
  if (!error) return '';
  const text = String(error);
  const transport = text.match(/\b(ConnectTimeout|ReadTimeout|WriteTimeout|PoolTimeout|ConnectError|ReadError|RemoteProtocolError|ProxyError)\b/);
  if (transport) return transport[1];
  const http = text.match(/HTTP\s+(\d{3})/i);
  if (http) return `HTTP ${http[1]}`;
  if (/network failure/i.test(text)) return '网络传输失败';
  if (/cursor|continuation invalidated/i.test(text)) return '分页游标失效';
  return '来源处理失败（详情已脱敏）';
}
export function summarize(monitoring, operations) {
  const jobs = (monitoring?.targets || []).filter(row => row.enabled);
  const progress = new Map((operations?.collection?.targets || []).map(row => [row.id, row]));
  return {
    total: jobs.length,
    successful: jobs.filter(row => row.status === 'completed').length,
    failed: jobs.filter(row => row.status === 'failed').length,
    stale: operations ? jobs.filter(row => progress.get(row.id)?.fresh_within_two_intervals !== true).length : null,
    progress,
  };
}
export function sourceNotices(citations, monitoring, operations) {
  const rows = [];
  const {progress} = summarize(monitoring, operations);
  for (const source of [...new Set(citations.map(c => `${c.origin || 'live'}:${c.source_id}`))]) {
    const [origin, sourceId] = source.split(':');
    const selected = citations.filter(c => c.source_id === sourceId && (c.origin || 'live') === origin);
    const versions = [...new Set(selected.map(c => c.revision ?? c.revision_id).filter(Boolean))].join(' / ');
    if (origin === 'replay') {
      rows.push({warning:true, text:`${sourceId} · replay 回放资料 · 引用版本 ${versions || '未知'}；不能作为当前采集状态。`});
      continue;
    }
    const jobs = (monitoring?.targets || []).filter(j => j.enabled && j.source_id === sourceId);
    if (!jobs.length || !operations) {
      rows.push({warning:true, text:`${sourceId} · 引用版本 ${versions || '未知'}；来源最新采集状态未验证。`});
      continue;
    }
    const stale = jobs.some(j => progress.get(j.id)?.fresh_within_two_intervals !== true);
    const stamps = jobs.map(j => `${j.id} 上次成功 ${formatTime(j.last_success_at)}`).join('；');
    rows.push({warning:stale, text:`${sourceId} · 引用版本 ${versions || '未知'} · ${stamps}。${stale ? '资料截至上次成功采集；最新状态未验证。仍可核对已保存原文。' : '来源最近成功在两个配置周期内；引用仅代表所示版本。'}`});
  }
  return rows;
}
export function gapsFor(report, target) {
  const gaps = [];
  let cursor = Date.parse(report.window_start);
  const end = Date.parse(report.window_end);
  for (const interval of target.intervals || []) {
    const start = Math.max(cursor, Date.parse(interval.from));
    if (start > cursor) gaps.push({from:new Date(cursor).toISOString(), to:new Date(start).toISOString()});
    cursor = Math.max(cursor, Date.parse(interval.to));
  }
  if (cursor < end) gaps.push({from:new Date(cursor).toISOString(), to:new Date(end).toISOString()});
  return gaps;
}
export async function overview() {
  const paths = ['/health/ready','/api/v1/monitoring/worker','/api/v1/monitoring','/api/v1/operations/status'];
  const values = await Promise.allSettled(paths.map(async path => {
    const response = await fetch(path);
    const data = await response.json();
    if (!response.ok && path !== '/health/ready') throw new Error(String(response.status));
    return data;
  }));
  const [api, worker, monitoring, operations] = values.map(value => value.status === 'fulfilled' ? value.value : null);
  return {api, worker, monitoring, operations};
}
export function overviewText(data) {
  const s = summarize(data.monitoring, data.operations);
  return data.monitoring ? `${s.total} 个目标：最近轮次成功 ${s.successful} · 失败 ${s.failed} · 当前超期 ${s.stale ?? '未验证'}` : '来源状态暂不可读，最新状态未验证';
}
export function workerText(data) {
  const names = {healthy:'健康', stale:'心跳超期', not_started:'尚无心跳', not_running:'进程未运行', unverified:'权限不足，无法核实', unavailable:'无法读取'};
  return `API ${data.api?.status === 'ready' ? '就绪' : '未就绪或无法读取'}；采集进程 ${names[data.worker?.status] || '未验证'}（独立进程心跳检查）。`;
}
