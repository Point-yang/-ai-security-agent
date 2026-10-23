// Public frozen evidence is separate from this installation's mutable audit tables.
const known = value => typeof value === 'number' && Number.isFinite(value) && value >= 0;
const count = value => Number.isInteger(value) && value >= 0 ? String(value) : '未知';
const percent = value => known(value) && value <= 1 ? `${(value * 100).toFixed(2)}%` : '未知';
export function publishedEvidenceView(data) {
  if (data?.status !== 'available' || data.schema_version !== 'submission-evidence-v1') {
    return {available:false, paragraphs:['已发布评测依据暂不可读，请查看提交包中的评测说明；未读取到的指标保持未知。'], modes:[]};
  }
  const paragraphs = [];
  const gold = data.gold;
  if (gold?.method === 'project_ai_review') {
    paragraphs.push(`项目采纳的 AI 审核金标：${count(gold.records)} 条。审核方式为 AI 来源核验，不标记为人工审核；${gold.independent === true ? '独立性按随附协议核验' : '属于已见数据回归，不是独立准确率证明'}。`);
  } else paragraphs.push('当前未读取到可识别的金标审核方法，不能推定人工审核或独立性。');
  const enrichment = data.enrichment;
  if (enrichment) paragraphs.push(`来源事实富化回归（${enrichment.evaluated_on || '日期未记录'}）：${count(enrichment.records)} 条记录 / ${count(enrichment.facts)} 项事实，精确率 ${percent(enrichment.precision)}，召回率 ${percent(enrichment.recall)}。${enrichment.independent === true ? '独立性以随附协议为准' : '冻结回归结果，不代表复杂问答准确率'}。`);
  const qa = data.complex_qa;
  if (qa) paragraphs.push(`复杂跨文档问答对照（${qa.evaluated_on || '日期未记录'}）：${count(qa.cases)} 题；${qa.agent_gain_proven === true ? '增益结论与适用范围见随附实验协议' : '当前实验尚未证明 Agent 稳定优于普通 RAG'}。历史实验版本与当前版本可能不同。`);
  const latest = data.latest_trial;
  if (latest) paragraphs.push(`最近开发试验（${latest.evaluated_on || '日期未记录'}）：${latest.status === 'planner_timeout' ? '规划调用超时' : '状态见随附记录'}；${count(latest.unknown_calls)} 次调用结果未核实，新增答案 ${count(latest.new_answers)} 条。${latest.total_tokens == null || latest.total_cost == null ? '总 token 与费用含未知项，不计作零。' : '用量与费用以随附记录为准。'}`);
  return {
    available:true, asOf:data.as_of || '日期未记录', paragraphs,
    modes:Array.isArray(qa?.modes) ? qa.modes.map(mode => ({
      label:mode.label || mode.key || '未标识策略',
      strict:`${count(mode.strict_passes)} / ${count(qa.cases)}（${percent(mode.strict_accuracy)}）`,
      recall:percent(mode.fact_recall),
      elapsed:known(mode.mean_elapsed_ms) ? `${(mode.mean_elapsed_ms / 1000).toFixed(1)} s` : '未记录',
    })) : [],
  };
}
