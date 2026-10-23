# 成员 A 第二阶段：受限智能体工具验收

2026-09-28。对应 [两人后续安排](member-b-rag-conversation-independent-review.md)中的 A 任务：为未来模型自主工具选择提供安全的工具契约、参数校验、调用预算和失败返回。本周只完成 A 的工具层，**没有让 DeepSeek 自主选择或调用工具**。

## 工具契约

核心实现：[agent_tools.py](../src/zhidu/agent_tools.py)。工具一律只读，只操作当前资料；不执行 shell、POC、扫描、联网采集或其他任意函数。

| 工具 | 必要输入 | 输出和保护 |
|---|---|---|
| `retrieve` | 问题/检索词，词项或本地混合模式 | 当前池和来源范围内的至多 5 个片段，逐条复验原文哈希、JSON Pointer 和摘录位置；分数不是可信概率 |
| `event_details` | 显式 `event_id` | 当前事件版本的标题、版本字段、处置建议、描述及参考链接片段；最多 8 条、逐条复验，明确不是全文 |
| `compare_sources` | 精确 CVE 编号 | 当前有效比较、字段状态及各来源观察；验证可用原文指针、保留派生字段身份，不自动选定“正确来源” |
| `asset_exposure` | 显式 `asset_id` **及** `event_id` | 只返回这对资产/事件的当前版本比较；无记录不等于 not_affected，标记私有资产数据与来源条件边界 |
| `verify_evidence` | 当前 `chunk_id` | 重新验证原文字节哈希、字段定位和摘录区间；失效或旧版本不返回有效证据 |

使用同一个 `AgentToolRuntime` 实例承载一次问答的多次工具调用：最多 6 次、15 秒软截止、单次返回上限 9000 字符、累计 24000 字符。输入由 Pydantic 严格校验且拒绝额外字段；模型无法通过参数切换 formal/candidate 或 live/replay，范围在运行层创建时固定。全量请求可通过 `PreviewRequest` 固定范围并最多提交 6 个工具步骤。

失败使用稳定代码：`invalid_arguments`、`not_found`、`tool_not_allowed`、`model_unavailable`、`evidence_invalid`、`deadline_exceeded`、`output_budget_exceeded`、`tool_unavailable`。每步记录有效参数、状态、耗时和返回字符数；不返回底层异常或敏感密钥。混合模型不可用时显式失败，由调用方自行决定是否再调用词项工具；不静默用另一模式伪装成功。软截止可在工具执行前后拒绝结果，不代表能够中断任意数据库操作。

## 接口与实测

- `GET /api/v1/agent/tools/contracts`：输出五个工具的 JSON Schema 和边界。
- `POST /api/v1/agent/tools/preview`：使用显式步骤做**只读预览**，不调用 DeepSeek，不写 RagRun/会话，不对来源冲突自动裁决。两者都沿用 `X-Admin-Key`。
- [真实库演练](member-a-agent-tools-real-audit.json)：查询已收录公告、读取当前事件字段、重验原文、查询 CVE-2025-32444 三个比较字段均成功；缺失资产返回 not_found，非法工具 execute_poc 被拒绝，前后数据库计数一致。演练的工具调用总数 6、返回 12789 字符，属于一次工程样本，不是模型选择效果评分。
- 重启现有 launchctl 托管的 8010 服务后，[HTTP 验收](member-a-agent-tools-http.json)确认就绪、契约、检索、比较均返回 200，未授权预览返回 401；主服务原有页面继续可用。
- 全项目 **197 项测试通过**，[JUnit](member-a-agent-tools-tests.xml)。专项 9 项涵盖范围隔离、原文损坏、退役比较、旧版本资产、显式资产 ID、混合失败后明确词项重试、调用/输出/时间预算、非法参数与无写入。Ruff、格式、Alembic 检查通过；OpenAPI 已更新。

数据库迁移和真实库数据未更改。本次只读演练未调用生成模型，也未产生新的 AI 问答质量分。正式人工金标仍 0/127；截至本次检查的竞赛保守估分仍沿用 [上一轮](member-b-rag-conversation-independent-review.md)约初赛 61、决赛准备度 57，不能因为“有工具接口”就给 Agent 自主编排加分。

接下来交由 B 使用 [工具接入说明](member-b-agent-tools-handoff.md)实现有界模型规划和工具选择，并用固定留出集证明相对普通 RAG 的收益。
