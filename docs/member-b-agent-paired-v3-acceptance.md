# B：规划与引用修复后的新题集配对复验

事后修复补记：原始 v3 评测与冻结分数保持原样；2026-09-29 的已知题诊断、工具输出预算修复，以及第 15 条引用误判更正见 [Agent 两条失败样例修复与审计](member-b-agent-two-failure-repair-20260929.md)。

2026-09-29。对应 [独立审查门槛](member-b-agent-independent-review-20260929.md)与用户本轮要求。本报告区分冻结前实现、新题集真实配对和随后局部改进。**工程复验完成；Agent 相对普通 DeepSeek 的质量收益没有得到证明，双人语义审核尚未完成。**

最终代码全项目 **214 项测试通过**，[JUnit](member-b-agent-paired-v3-tests.xml)；Ruff、格式、前端 JS 语法和 Alembic 检查通过。主库 `integrity_check=ok`，模拟撤回在主库数量为 0。

## 修复与不变的约束

规划器现在只抽取 `decision_summary` 和 `calls`，容忍 JSON 字符串、规范 JSON 围栏和 `tool/args` 的常见等价写法；白名单、每步参数 Pydantic 严格校验、范围锁定及工具预算仍不变。规划格式或越界时最多给模型一次明确纠正机会，失败次数、用量与错误代码分别记入轨迹。没有自动采集、POC、shell 或无限循环。

生成提示增加服务端从当前已核验 `text` 逐字截取的短句候选，让模型容易复制准确引文。最终仍要求结论的每个 `quote` 连续出现在本轮编号来源原文中；不匹配就安全降级，不能为了提高通过率放松引用校验。

新 v2 配对揭示关键缺口：Agent 检索到编号后即使用跨来源派生观察回答版本问题，没有读取两份公告的 `packages` 和描述字段。现于生成前在**同一六次工具预算**内最多补取两份当前来源详情，并明确记为服务端证据门槛 `model_selected=false`，不能冒称是模型自主选择。使用已见过的 Mooncake 题做[单题事后诊断](member-b-agent-v2-mooncake-diagnostic.json)：两份 `packages` 原文进入引用，最终生成通过；全轮 7074 ms，不是时延达标证明，也不计入新留出。

v3 配对后又修正了明显的无答案成本：明确 GHSA/CVE 在当前有效事件及别名中不存在或已撤回时，本地直接拒答，避免先支付模型规划成本。这项修正发生在 v3 报告**之后**，没有回填或重跑冻结结果；其边界已有离线测试。

## 冻结协议和成对结果

[v3 题集协议](../config/member-b-agent-paired-v3.json)在模型运行前固定，并绑定独立评测库 SHA-256 `3052b80b76f82a80a21e6fb808a70f7b54acf6725ff9b3c86ce2b4552c718033`。7 题中，3 题考两份公开公告的版本/修复依据，4 题考不存在编号、缺明确资产、缺漏洞复现证据和**只在评测副本模拟**的来源撤回。正向目标事件与旧 12 题及 v2 题集没有重叠。[本地预检](member-b-agent-paired-v3-preflight.json)显示 3 题都能命中两来源、4 题安全拒答；该预检不包含模型答案质量判断。主库从未撤回模拟 GHSA。

[v3 原始逐题报告](member-b-agent-paired-v3-evaluation.json)保留 21 行三模式记录、当前引用、工具轨迹、失败、用量及完整本机耗时。表中的“成功生成”仅指格式与逐字引用通过，**不是语义正确率**。

| v3 指标 | 抽取式 | 普通 DeepSeek | 有界 Agent |
|---|---:|---:|---:|
| 正向题成功生成 | 不适用 | **3/3** | **2/3** |
| 正向题命中预设事件 | 3/3 | 3/3 | 3/3 |
| 四个边界题安全拒答 | 4/4 | 4/4 | 4/4 |
| 规划决策完成 | 不适用 | 不适用 | 100%（已执行的决策） |
| P95 完整本机请求 | 336 ms | 5325 ms | **27873 ms** |
| 外部请求 / 报告 token | 0 / 0 | 3 / 17622 | **13 / 23373** |

Agent 的修复版本题仍出现一次 `invalid_citation` 并降级，普通 DeepSeek 在三道正向题均生成成功。Agent 的尾部耗时主要来自无答案题在本地拒答前仍进行了两次云规划；该路径现已本地短路，但 v3 测量保留原值。请求上限 60，本轮实际报告 16 次。`api_usd=null` 意味提供商金额未计价，不能当作零费用。小样本 P95 只能描述此次运行，不能推断总体性能门槛。

结论是目前**不能**以此提高 Agent 质量评分或将 Agent 设为默认策略；普通 DeepSeek 保持现有默认。后续若继续优化，必须用另一套事前冻结、未见过的新题集配对，不能把 v2/v3 失败题调好后当成新留出。

## 双人审核准备与人工待办

已从 v3 原始报告准备 [21 条模式盲审题包](../data/member-b-agent-paired-v3-review/source-packet.json)、A/B 记录及分歧裁决文件。模式映射单独保存在 `tmp/member-b-agent/paired-v3-review-item-map.json`，审核前不向审核者展示。A/B 模板已完成用户逐条人工查验，21/21 条、42/42 份字段已确认，原先 7 个预填分歧已消除。自动 quote 匹配和字节校验不能替代人工判断。

已另生成[AI 预审报告](member-b-agent-paired-v3-ai-prereview.md)和机器可读明细。它核验了 21 条回答所引用原文的 SHA-256 与 JSON Pointer：失败数均为 0。AI 候选已先写入 A/B 模板，随后经用户逐条查验并转为人工审核状态；当前冻结结果见 [人工分数](member-b-agent-paired-v3-human-scores.json)。

人工需要：

1. 指定两名**不同**审核者 A、B，独立阅读每题回答和当前版本原文，分别判断结论正确、引用是否语义支持、回答是否完整、拒答是否适当；错误项记录具体断言和原文理由，填写审核时间。不要用程序批量填标签。
2. 两份标注完成后运行 `PYTHONPATH=src .venv/bin/python scripts/reconcile_member_b_agent_review.py status --directory data/member-b-agent-paired-v3-review --mapping tmp/member-b-agent/paired-v3-review-item-map.json`。若有分歧，由第三名人工裁决者逐字段写最终判断、理由和时间；未完成前脚本拒绝冻结成绩。
   全部完成后用 `PYTHONPATH=src .venv/bin/python scripts/reconcile_member_b_agent_review.py freeze --directory data/member-b-agent-paired-v3-review --mapping tmp/member-b-agent/paired-v3-review-item-map.json --output docs/member-b-agent-paired-v3-human-scores.json` 输出独立分模式评分。
3. 复核并推进此前 [36 条原始 Agent 对照盲审](member-b-agent-human-review-guide.md)（当前 0/36）及另一路 [127 条来源金标](member-b-week6-human-review-guide.md)（当前 0/127）。这三套对象不同，不可互相填充或合并分母。
4. 人工确认正式赛务的匿名模板和答辩时长，并由 A/B 各实际操作一次更新后的主路线、只读恢复路线，记录设备、耗时、失败与复验；这些不能由自动化代签。

上述人工工作完成后，再生成带分母、冲突裁决记录的质量报告，并由独立人员复验。来源新增 live 覆盖和持续监测证据仍由 A/B 按原交接并行推进；本轮模型实验不替代它们。
