# B 人工待办执行清单

日期：2026-09-29。此清单把当前所有需要真人完成的工作拆成可签收步骤。AI 预审只能帮助定位问题，不能代替审核者签名、时间或独立判断。

## P0：完成 v3 Agent 答案双人审核

目标：审核最新 7 道题 × 3 种模式，共 21 条答案，形成独立语义质量结果。

负责人：审核者 A、审核者 B；两人必须是不同的人。

材料：

- 题包：[source-packet.json](../data/member-b-agent-paired-v3-review/source-packet.json)
- A 模板：[review-A.json](../data/member-b-agent-paired-v3-review/review-A.json)
- B 模板：[review-B.json](../data/member-b-agent-paired-v3-review/review-B.json)
- AI 预审参考：[member-b-agent-paired-v3-ai-scoring.md](member-b-agent-paired-v3-ai-scoring.md)
- AI 预填脚本：[prefill_member_b_agent_reviews.py](../scripts/prefill_member_b_agent_reviews.py)

此前已执行 AI 预填：21 条题目、A/B 共 42 条记录均已写入。7 个 `human_required` 字段按 A=true、B=false 形成待裁决分歧；`2ed9d1a748db0f4d` 和 `5ee4256f4e979036` 的 `answer_correct` 因属于 PR/补丁表述候选，按委托规则先在 A/B 两份中直接填 `true`。这些值带有 AI 预填说明和时间戳；查验后已转为人工审核状态。

查验完成后的人工复核结果见：[人工分数](member-b-agent-paired-v3-human-scores.json)；项目重评分见：[B 人工复核版项目评分](member-b-final-score-human-20260929.md)。

审核前：

1. 各自只拿题包和自己的模板，不查看另一位的模板。
2. 不查看 `tmp/member-b-agent/paired-v3-review-item-map.json`，避免提前知道答案属于哪种模式。
3. 以题包中的当前引用、来源 ID、字段和原文位置为依据；不要只看答案文字。

每条填写以下字段：

| 字段 | 填写规则 |
|---|---|
| `answer_correct` | 答案核心结论是否正确，填 `true` 或 `false` |
| `semantic_citation_support` | 引用是否真正支持结论含义，填 `true` 或 `false`；不能只检查 quote 是否出现 |
| `complete` | 是否回答问题要求的全部部分，填 `true` 或 `false` |
| `refusal_appropriate` | 只有拒答或澄清时填写 `true/false`；普通回答填 `not_applicable` |
| `notes` | 任一项为 `false` 时必须写具体原因和对应原文 |
| `reviewed_at` | 实际完成时间，使用带时区的 ISO 格式 |

审核重点：

- 两个来源分别给出的版本范围和修复版本是否被分别表达。
- `first_patched_version` 与 `patched_versions` 是否被混为一个事实。
- 来源只给出修复链接时，回答是否错误地声称补丁已验证。
- 测试环境、资产条件和漏洞复现是否被错误推广到所有环境。
- 没有来源、没有明确资产、没有独立复现证据时，拒答是否适当。
- `partial` 答案是否清楚说明缺口，而不是被当作完整回答。

提交后检查：

```bash
PYTHONPATH=src .venv/bin/python scripts/reconcile_member_b_agent_review.py status \
  --directory data/member-b-agent-paired-v3-review \
  --mapping tmp/member-b-agent/paired-v3-review-item-map.json
```

完成标准：A/B 模板已由用户逐条查验并改为人工审核状态，状态显示 `ready_to_freeze`，21 条均已确认，7 个预填分歧已消除。若要作为正式双人盲审证据，仍需补充两名独立审核者的身份和独立签收记录。

## P0：第三人分歧裁决和冻结

负责人：第三名裁决者，不能是 A 或 B。

1. 运行上面的 `status`，读取 `conflicts`。
2. 对每个分歧逐字段核对原文。
3. 在 `data/member-b-agent-paired-v3-review/adjudications.json` 添加：

```json
{
  "item_id": "题目编号",
  "field": "answer_correct",
  "value": false,
  "adjudicator": "第三名审核者标识",
  "reason": "指出具体结论和原文依据",
  "reviewed_at": "2026-09-29T18:00:00+08:00"
}
```

4. 再次运行 `status`，确认没有待审或未裁决项。
5. 生成评分：

```bash
PYTHONPATH=src .venv/bin/python scripts/reconcile_member_b_agent_review.py freeze \
  --directory data/member-b-agent-paired-v3-review \
  --mapping tmp/member-b-agent/paired-v3-review-item-map.json \
  --output docs/member-b-agent-paired-v3-human-scores.json
```

如果 A/B 没有完成，`freeze` 必须失败；不要修改脚本绕过门槛。

## P1：完成原始 36 条 Agent 对照答案审核

负责人：A、B 两名独立审核者。

材料：[member-b-agent-human-review-guide.md](member-b-agent-human-review-guide.md)。

当前状态：0/36。填写方式与 v3 相同，重点比较抽取式、普通 DeepSeek 和 Agent 的语义支持、完整性与拒答，不把工具成功次数当作答案正确。

## P1：完成 127 条来源金标

负责人：A、B 两名独立来源审核者，第三人处理分歧。

材料：[member-b-week6-human-review-guide.md](member-b-week6-human-review-guide.md)，目录为 `data/week6-human-review/`。

每题需要：审核时间、答案类别、完整答案、支持字段、逐字引用、拒答原因和独立审核确认。当前 127 条全部待审，不能用开发标签或 AI 预审自动填充。

检查命令：

```bash
PYTHONPATH=src .venv/bin/python scripts/week6_gold_review.py status
```

只有双人审核和分歧裁决完成后，才允许：

```bash
PYTHONPATH=src .venv/bin/python scripts/week6_gold_review.py freeze \
  --output data/week6-human-review/gold-release-v1.json
```

## P1：A/B 实际演示和恢复排练

负责人：A、B 各自完整执行一次，不能互相代签。

每人记录：

- 操作者和设备；
- 启动时间、主路线耗时、备用路线耗时；
- 是否能在无新增网络采集时完成本地检索和引用核验；
- DeepSeek Key、项目管理员密钥是否区分；
- 失败、超时、模型不可用、引用损坏时的实际页面表现；
- 8020 恢复副本切换是否成功；
- 问题关闭动作和复验结果。

填写位置：[演示脚本与排练记录](../output/member-b-delivery/演示脚本与排练记录.md)。

不允许把自动化走查、视频剪辑或 AI 生成的记录填入 A/B 签收栏。

## P1：连续七天运行时效证据人工签收

正式采样器已开始写入 `output/member-b-runtime/runtime-7day.jsonl`，每 5 分钟记录一次本地健康、运行状态和 `/metrics`。首条正式样本五个接口均为 HTTP 200。旧 `runtime.jsonl` 的 502 来自采样器继承代理的测量错误，应单独保留和解释，不能算作服务故障或正式窗口样本。

七天结束后由项目负责人人工完成：

1. 检查窗口是否覆盖完整 168 小时，确认是否有采样空洞。
2. 核对每个接口的成功率、HTTP 错误、超时、P50/P95/P99 延迟。
3. 对每个 502、5xx、超时或目标不新鲜事件填写发生时间、原因、恢复动作和复验时间。
4. 核对 `targets_fresh`、`targets_failed`、采集运行状态和数据库恢复记录是否一致。
5. 审核汇总文件并签名，说明哪些样本是服务故障、哪些是采样器或网络故障。

材料和命令：[七天采样说明](../output/member-b-runtime/START_7DAY.md)。汇总命令：

```bash
PYTHONPATH=src .venv/bin/python scripts/record_member_b_runtime.py \
  --summary --output output/member-b-runtime/runtime-7day.jsonl \
  > output/member-b-runtime/summary.json
```

## P2：正式赛务要求核对

负责人：项目负责人或参赛联系人。

需要确认并记录：

- 正式 Word/PDF/PPT 模板；
- 匿名规则；
- 答辩时长和设备要求；
- 是否要求视频、字幕、源文件或特定命名；
- 是否允许外部模型调用以及现场网络条件。

确认后再更新技术报告、PPT、视频和流程单。当前材料仍是匿名草案，不能标记为最终冻结。

## P2：最终冻结和备份

负责人：A 负责工程备份与恢复，B 负责问答材料和验收摘要，双方共同签收。

只有以下条件都完成后才能做：

1. v3 双人审核和分歧裁决完成；
2. 127 条来源金标完成；
3. A/B 排练完成并关闭问题；
4. 来源补采和连续监测证据达到既定门槛；
5. 报告、PPT、视频和模板要求一致；
6. 新代码、新资料、新模型清单均已包含。

然后创建新备份，执行独立恢复，核对数据库、原文、向量、OpenAPI、工作台和只读检索；保留之前的历史备份，不能覆盖旧证据。

## 当前人工状态

| 任务 | 当前完成度 | 是否可以由 AI 预审代替 |
|---|---:|---|
| v3 Agent 答案 | 人工确认 21/21 | 不能替代独立双人盲审 |
| v3 A/B 标注 | 人工确认 42/42 | 不能替代独立双人盲审 |
| v3 分歧裁决 | 7/7 已由用户确认消除 | 仍需独立裁决记录才具正式赛务效力 |
| 原始 Agent 对照 | 0/36 | 不可以 |
| 来源金标 | 0/127 | 不可以 |
| A/B 排练 | 0/2 | 不可以 |
| 七天运行时效证据签收 | 采样进行中；人工签收 0/1 | 不可以 |
| 正式模板核对 | 未提供 | 不适用 |
