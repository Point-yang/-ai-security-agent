# Agent 技术栈与当前验收

核验日期：2026-10-13。七层技术栈均已接入产品。工程接通与问答质量分别验收；当前仍没有足够证据证明 Agent 在复杂问题上比普通 RAG 更准确或更高效。

| 层次 | 实际实现 | 当前证据及边界 |
|---|---|---|
| Agent | LangChain 1.4.4 `create_agent`；研究模型的结构化决策转换为框架 tool calls，由框架执行工具循环 | 模型根据工具观察选择读取或结束；不是仅导入依赖。原生 Agent 和团队研究节点均有实际 SDK 与工具验收 |
| 状态与分支 | LangGraph 1.2.14；planner → researcher → composer → verifier，具体缺口可返回 researcher | SQLite checkpoint、角色回执和工具快照支持恢复；已付费完成回复免费重放，未知云端结果不自动重发。单机实现，多节点需共享存储 |
| 模型 | `langchain-deepseek` 1.1.1 与统一模型适配层 | 真实 DeepSeek 规划、补查、依据证据生成和引用核验已经执行；OpenAI 兼容与 Ollama 接口有协议测试，其各自实际模型能力仍需烟测 |
| 领域工具 | `AgentToolRuntime`、`SourceRuntime` 与 LangChain `StructuredTool` | 检索、详情、字段定位与分页、来源比较、资产条件、原文核验。仅操作本轮发现的对象；资产详情仅在本地；不执行来源中的指令或 PoC |
| 检索 | 词项 + FastEmbed 0.7.4 / all-MiniLM-L6-v2 混合检索 | 对照使用同一 hybrid top-5 初始包。确切标识在融合前限定当前事件。字段补读不等于初始检索召回，中文复杂问答效果仍需独立验证 |
| 服务与存储 | FastAPI 0.141.1、SQLAlchemy 2.0.54、SQLite 与 Alembic | 接口、版本事件、原文、会话、评测及执行恢复已接通；重复已完成请求不追加调用，同请求不同内容拒绝复用 |
| 评测 | pytest、Node 边界测试、冻结 JSON、原文审计、匿名 AI 逐题复核与配对统计 | 来源金标在生成前冻结；语义支持与逐字一致性分开。AI 身份如实保留，不能表述为人工或主办方认证 |

## 本轮工程修复

最终代码通过 605 项 Python 测试、16 项前端费用与后端选择测试、ruff 与 JavaScript 语法检查，已加载本机 8010。证据见 [最终部署审计](../output/agent-stage7-final-runtime-20261013/deployment-audit.json)及 [完整测试记录](../output/agent-stage7-final-runtime-20261013/tests.xml)。

- 完整来源片段由服务器回填并复验，代码表达 `B_shape[1]` 不再被当作手写引用号。
- 字段读取优先覆盖每个请求字段，分页游标不能跳过预算丢弃的区间；不存在的字段返回本轮索引字段目录。
- 先打包模型实际收到的公开文本，再核算字符预算；完整出处与区间审计元数据留在本地。没有增大原实验预算。
- 参数错误和其他失败回复共用工具次数及字符预算；连错误包也放不下时停止。此停止状态持久化后仍不能借恢复继续发模型请求。
- 八次模型预算下，首轮研究为核验后的定点补查留出三次调用。二次补查最多一个研究调用，随后重新生成并核验；较小预算仍优先保留最终生成和核验。
- 来源片段里的 `source` 字段名与整个来源主语分开处理。这个守卫是范围模式检查，不能替代实际引文的语义核验。
- 页面分别显示确定计价、估算、已知小计、未知调用和历史重放，缺少 usage 不显示为零，不推测汇率或发票金额。
- 计划、核验和缺口中的任务标识统一支持 64 字符，保持数量、字符类型和身份校验；非法角色输出记录诊断类型和位置，不在审计中回显拒绝值。完成但格式无效的付费回复也不会自动重发。
- 明确形状赋值中的单元素数组，例如 `形状为 [28]`，与来源编号分开处理；同句其他手写编号仍拒绝。“原 Agent 对照”选项显式发送 `agent_backend="legacy"`，不随服务默认后端改变。

本机部署使用 `workflow` 默认后端，`team` 和 `auto` 保持实验选项。本机 `.env` 覆盖为最多 8 次模型、6 次工具、60 秒与每次 2400 输出 token；代码默认值仍为 5/6/30/1800。Stage7 实验使用独立的 18000 字符工具输出上限。

## 实验结论

Stage6 的六组新标识、46 项必答事实对照已经完成。严格通过为普通混合 RAG **0/6**、工作流 **2/6**、团队 **0/6**；必要事实召回分别为 **4.35%、30.43%、43.48%**。团队实际调用了额外工具，但质量、耗时和费用没有共同支持增益结论。见 [原冻结报告](../output/agent-stage6-release-20261013/report.json)。

Stage7 复用已见资料，始终属于开发回归。第一版首题误拦后停止，7 次请求保留；v2 前两题完成、第三题误拦后停止，23 次请求及后面三题未尝试状态保留。对 v2 两个已完成答案的 AI 引文复核发现 16 条结论中一条缺充分支持，不能把生成完成数当正确数。修复后原第三题候选可以零调用重放，7/7 来源引用复验通过；该检查只验证格式和来源，不证明语义正确。

对应记录：[第一版停止](../output/agent-stage7-development-20261013/stopped.json)、[v2 实跑审计](../output/agent-stage7-development-v2-20261013/execution-audit.json)、[开发引文复核](../output/agent-stage7-development-v2-20261013/development-quote-review.json)、[零调用格式重放](../output/agent-stage7-development-v2-20261013/zero-call-renderer-replay.json)。

v3 前两题各 5 次请求完成；第三题规划中的 25 字符标识超过旧 24 字符限制而停止，累计 11 次请求。两个完成答案经 AI 引文复核，13 条结论及 15 项必答事实均有引用支持。这是开发诊断，不能改写 Stage6 的成绩；原第三题计划在统一 64 字符合同下零调用验证通过，任务文本未修改。见 [v3 实跑记录](../output/agent-stage7-development-v3-20261013/execution-audit.json)、[引文复核](../output/agent-stage7-development-v3-20261013/development-quote-review.json)及 [计划格式重放](../output/agent-stage7-development-v3-20261013/zero-call-plan-validation.json)。

v4 使用新的请求身份及 [冻结协议](../output/agent-stage7-development-v4-20261013/protocol.json)，保存原语料、金标、初始包及旧成绩；144 份源码、测试、页面与依赖文件归档。最多 48 次生成请求、没有新增评分 API，首个失败即停止。完成开发验收后，再冻结至少达到项目预注册门槛的八组全新标识，分别检验严格正确率、耗时及原币费用的配对区间，才有条件讨论实际增益；此门槛是项目选择，不是主办方要求的固定样本数。

v4 四题完成、第五题 ONNX 的 `[28]` 形状误拦后停止，累计 30 次请求。四个完成答案的 26 条结论获得 AI 自引文支持；langchain-core 仍缺 NVD 修复对照、完整暴露条件、凭据/请求可能性及可信加载建议四项必答事实。两个二轮流程均有真实 `research:1 → compose:1 → verify:1` HTTP 回执，但 Gradio 重读已有证据、core 补查未命中，新增证据数为零。共享 8/6/60/18000 预算全部保持，流程闭环不等于有效补证。见 [实跑审计](../output/agent-stage7-development-v4-20261013/execution-audit.json)、[周期与预算审计](../output/agent-stage7-development-v4-20261013/cycle-budget-audit.json)、[引文复核](../output/agent-stage7-development-v4-20261013/development-quote-review.json)。ONNX 原候选在修复后原样零调用渲染通过，4/4 引用复验；旧失败仍保留。

v5-tail 在新调用前只冻结 ONNX、Keras 两题，预算为 16 次，前四题没有重发。ONNX 生成完成；Keras 的未限定本轮片段范围的 NVD 缺独立字段断言被拒绝，累计 9 次请求后停止，没有继续放宽守卫。旧问题、金标和统计保持；不能将不同版本的开发答案拼成“六题正确率”。见 [补验协议](../output/agent-stage7-development-v5-tail-20261013/protocol.json)与 [实跑审计](../output/agent-stage7-development-v5-tail-20261013/execution-audit.json)。

ONNX 单题的 8 条结论经 AI 自引文复核均有支持，但仍缺 `onnx-untrusted-model-scope`：引文包含不可信模型的适用条件，最终自然语言结论没有表达，不能由未转述的引用内容自动计作必答覆盖。PoC 数值和行号等附加信息有证据，也不能替代这个必答范围。见 [尾题开发复核](../output/agent-stage7-development-v5-tail-20261013/development-quote-review.json)。Keras 降级摘录未当作生成完成答案评分。

后续优先修正实际 statement 对必答事实的覆盖、无新证据的重复补查，以及 NVD 描述与 GitHub 结构化字段的不同来源边界。工程实现已接通，严格质量与实际增益验收仍未完成。
