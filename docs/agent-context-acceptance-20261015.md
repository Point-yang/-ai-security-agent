# 完整来源上下文与来源语义验收

日期：2026-10-15（北京时间）。本机 8010 已接入 `langgraph-source-team-v10` / `durable-agent-roles-v4`，共同回答合同保持 `source-answer-v10`。846 项 Python 测试、48 项前端测试、Ruff 与 JavaScript 语法检查通过。两道真实开发题均完成运行与引用校验；这不代表两题全部答对，也不更新独立评分。

## 本轮实现

`read_fields(context="section")` 按原文结构读取列表及其引导段、标题章节或完整字段，返回连续原文区间。超过 1200 字符时分页，保留完整结构范围、当前位置和续读游标；最后一页不单独冒充整个结构。旧 `excerpt` 行为保留。同一检索块内的重复关键词、跨空行或标题的游标、预算丢弃后继续读取均有回归覆盖。

新出处协议 `source-context-span-v1` 绑定原始文件、字段、版本、实际片段及定位参数，服务器重新读取来源复验。模型只能选择已有来源。完整结构证明纳入正文 ID，证明变化会使旧 ID 失效。

任务可声明 `coverage_scope="complete_context"`。检查只使用实际支持正文所引用的片段：缺页、不同来源的替代页、未引用或未获支持的内容都不能补足范围。缺少完整结构证据时保留 `partial` 和补查项，但不会因此删除已获支持的单项事实。工作台同步显示结构证据是否齐全。

GitHub packages 的版本范围及首次修复点，与 NVD 描述、affected data、CPE 适用条件分别解释。元数据只提示来源字段含义，不能凭“本轮未观察”宣称来源不存在某个事实。结构完整、逐字引用正确、语义支持和完整回答分别检查，前两项不能自动证明后两项。

代码：[结构定位](../src/zhidu/source_context.py)、[出处复验](../src/zhidu/source_spans.py)、[工具与分页](../src/zhidu/langchain_tools.py)、[来源合同](../src/zhidu/source_semantics.py)、[完整性检查](../src/zhidu/agent_requirements.py)。

## 冻结开发运行

沿用 Stage6 冻结的 core / ONNX 语料、问题、初始检索包、模型及金标，创建全新实验身份。先冻结代码，再生成。每题最多 8 次模型请求、6 次工具调用、60 秒软截止、每次最多 2400 输出 token，工具总输出上限 18000 字符；遇到未知结果或运行/格式失败立即停止。没有追加评审 API 或重发旧请求。

| 项目 | langchain-core | ONNX |
|---|---:|---:|
| 运行及结构合同 | 通过 | 通过 |
| 产品答案类别 | partial | partial |
| 模型请求 | 8 | 5 |
| 工具调用（含冻结初始检索） | 6 | 4 |
| 本轮耗时 | 31.68 秒 | 14.47 秒 |
| 总 token | 70128 | 40218 |
| 出处复验 | 5/5 | 4/4 |
| 实际引文逐字检查 | 7/7 | 9/9 |
| 新增原文字符（区间去重） | 838 | 2703 |

合计 13 次模型请求、110346 token。按冻结费率快照和实际回执核算为 USD 0.018429864；这是 token 费率核算，不是账户账单。新增字符也不等于质量增益。

core 正文已完整写出四项联合暴露条件，包括此前漏掉的“应用后来通过受影响 API 路径反序列化该运行数据”。但实际选取的是整字段的部分页，不能获得完整结构证明；影响的可能性限制、推荐信任与 allowlist 边界仍未补齐。内部核验仅 2/7 任务 covered。该结果仍是部分回答。

ONNX 的内部核验为 8/8 任务 covered，未列出原问题遗漏；正文区分了 GitHub 原始范围、NVD 原生措辞、触发路径、rank/索引、InferShapes 边界及 Release/ASan 表现。不过 composer 仍添加未要求字段的“证据边界”，最终保留 partial。内部标签不等于独立语义验收，逐项复核另存开发评审记录。

另行 [AI 开发复核](../output/agent-context-development-20261015/development-quote-review.json)认为两题都只部分完成：14 条最终结论均获得各自引文支持，但 core 仍缺影响限制及信任/allowlist 边界；ONNX 的“可能影响”漏掉 Release 下错误值传播到输出形状及潜在堆内存泄露。原问题明确要求可能影响，不能仅因内部任务标签全为 covered 就通过整题。堆布局等更细的 gold 限定单列为补充，不增加未问的必答项。该审阅不是人工审阅或新的留出评分。

core 的四项条件确实同时存在于正文和实际引文；结构证明未齐全不能推导出具体条件缺失。当前返回仍把该任务放入“尚缺证据”，容易让读者误以为四项没有答出。工作台已有结构状态说明，正文的缺口表述仍需进一步区分“语义漏答”和“结构证明不足”。

记录：[冻结协议](../output/agent-context-development-20261015/protocol.json)、[运行汇总](../output/agent-context-development-20261015/summary.json)、[core 实际返回](../output/agent-context-development-20261015/answers/stage6-langchain-core-team_hybrid.json)、[ONNX 实际返回](../output/agent-context-development-20261015/answers/stage6-onnx-team_hybrid.json)。旧 Stage6、五轮 Stage7、三轮 Stage8 及正文 ID 阶段的原始结果均保留，没有合并或改写为新成绩。

## 零模型诊断与实际边界

另在冻结数据库副本中恢复原初始范围，使用已知原文短语做固定工具诊断：条件列表 `[584,1050)` 共 466 字符、Guidance `[4497,5291)` 共 794 字符，均可完整读取并复验。总工具 4/6，输出 13587/18000 字符，新增模型/API 为 0，冻结原件哈希一致。这证明定点读取能力，不是 Agent 自主发现或完整答题成功。

裸 `allowed_objects` 在无标题开头和 Guidance 内均出现，最早匹配会选到整字段并分页。更具体的已知短语可以直达 Guidance；当前宽泛词仍可能浪费查询预算。真实 core 运行也出现整字段分页占用预算，故下一步应优化通用结构导航及研究角色的定位选择，不能把已知题目的答案或固定位置写入生产代码。

此外，需要处理“原问题已经覆盖，但无关字段缺失仍让答案停留 partial”的边界，并完成新的冻结对照实验后，才可讨论 Agent 相对普通 RAG 的质量或效率增益。

诊断：[报告](../output/agent-context-development-20261015/source-context-diagnostic.json)、[零模型复现程序](../output/agent-context-development-20261015/source-context-diagnostic.py)。测试及部署：[Python](../output/agent-context-development-20261015/tests.xml)、[前端](../output/agent-context-development-20261015/node-tests.txt)、[工程审计](../output/agent-context-development-20261015/engineering-audit.json)、[部署检查](../output/agent-context-development-20261015/deployment-audit.json)。默认后端仍为 workflow，团队模式继续保留实验标记。
