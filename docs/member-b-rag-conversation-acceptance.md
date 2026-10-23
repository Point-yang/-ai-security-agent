# 成员 B 第一阶段：大模型多轮与当前证据接入验收

2026-09-28。依据 [B 交接](member-b-rag-conversation-handoff.md)实施。结论：工程功能与本机隔离副本联调完成；独立答案准确率和人工金标仍待审核。

## 交付行为

顶部问答现可选择或新建会话。每次提交将问题、实际回答、原始请求与解析后的请求、引用、约束、工具轨迹、请求模型与实际模型、模型失败原因、usage、费用状态和服务端全链路耗时关联到 `rag_runs`、会话消息及 `rag_generation` hop。`request_id` 绑定同一会话的同一请求：重复发送返回已保存结果，不再执行模型；改变请求却复用 ID 返回 409。模型限流、余额不足、超时及格式不合格时保存降级结果和失败审计；用户主动重试是新一轮，旧轮次保留。

“它 / 这条 / 首次修复版本”等追问从最近一轮已确认的事件 ID 或共同公告编号解析。同一公告的不同来源各自保留版本表达与引用；多个无共同编号的候选先澄清，并提供显式事件选择。模糊的“这个版本”要求写出版本号，资产切换也要求显式选择。历史问答只作为理解追问的参考，最近最多六条随 DeepSeek 请求传入；提示明确禁止把历史答案当证据。本轮引用仍来自当前检索索引，重新复验原文哈希和字段定位。

旧引用状态通过只读 `context-status` 覆盖层展示 current / superseded / withdrawn / missing。新答案使用当前 revision；旧消息、引用与 replay 哈希不改写。撤回来源的追问拒绝继续用旧来源；原文损坏时拒绝引用。首次修复版本的问题如果没有当前来源的非空结构化补丁字段，则不给模型凭先验猜具体版本。修复关键词候选、原文摘录和引用编号校验不等于语义正确性。

工作台将会话、问题与发送按钮置于前部；检索方式、模型、资产和事件选择收在可展开区域，运维状态与历史抽取式评测也收起。390 像素宽界面检查显示入口可见。项目管理员密钥与服务端配置的 DeepSeek API Key 有独立标签；页面清空本次管理员密钥输入。生成答案与旧抽取式对照分开呈现，未覆盖旧评测。

## 验证与实际联调

- 全项目 **188 项测试通过**，结果见 [JUnit](member-b-rag-conversation-tests.xml)。专项覆盖三轮追问、两来源差异、来源更新和撤回、原文损坏、修复信息缺失、资产切换、模糊指代、429/402/超时降级、重复及并发请求去重、只读上下文预览。
- Ruff、Python 格式、前端 JS 语法、Alembic 检查通过；已重新导出 OpenAPI。新迁移 `b928c1d740ae` 完成，主库 `integrity_check=ok`。迁移前 SQLite 备份：`data/backups/before-b-rag-conversation-20260928.sqlite`，SHA-256 `3778d699396b3991845b3417ea951952330f453675718333216e721b84b9286e`。
- 在主库的独立复制件执行真实界面问答：`GHSA-2pc9-4j83-qjmr 这条漏洞是什么？` → `影响哪些版本？` → `首次修复版本是什么？`。后两轮不重输编号，均请求当前两份来源并成功生成；首轮 DeepSeek 返回不合格格式，系统保留 usage 与 `invalid_response`，展示本地摘录。实际模型为 `deepseek-flash`。详细每轮耗时、usage、来源和状态见 [联调 JSON](member-b-rag-conversation-live-check.json)。三次只是连通和行为样本，不是 P95、准确率或人工审核结论。
- 真正的主库在备份后迁移到新 schema，并启动 8010 本机工作台；8031 是独立验收副本，不应与主库会话混用，验收后已停止。8010 当前由本机 `launchctl` 标签 `com.zhidu.rag.8010` 管理，仅绑定 `127.0.0.1`；标准输出和错误日志分别在 `/private/tmp/zhidu-main-20260928.log` 与 `/private/tmp/zhidu-main-20260928.err`。原有人工作业状态保持不变。

## 接口和使用

`POST /api/v1/rag/answers` 的 `RagRequest` 在选择会话时增加 `conversation_id` 和必填 `request_id`。可选 `asset_id`、`event_id`、`clear_asset=true`；`asset_id` 与 `clear_asset` 不能同时提供。`request_id` 由前端生成 UUID，长度 8–64；服务器对已保存的同 ID 同请求返回 `deduplicated=true`。上下文预览 `/api/v1/rag/context` 仍只读，也不使用会话 ID 自动保存轮次。

返回保留原 RAG 字段，另含 `conversation_context`（解析方式、候选与旧引用提示）、`requested_generation`、`resolved_request`、会话消息 ID、`state_version`、`elapsed_ms` 与 `timing_scope`。服务端 `elapsed_ms` 覆盖会话解析、检索、证据核验、模型调用和消息写入准备，不含事务提交后网络传输；页面同时显示浏览器本次完整往返耗时。`cost.api_usd=null` 表示未计价，不能误作零成本。模型概括的 `semantic_support_verified=false`，正式质量结果仍须独立审核。

示例：

```json
{
  "conversation_id": "已有会话 UUID",
  "request_id": "客户端每轮稳定生成的 UUID",
  "question": "首次修复版本是什么？",
  "mode": "hybrid",
  "generation": "deepseek"
}
```

先选中包含明确公告的会话；第一轮可在问题或 `query` 输入 GHSA / CVE。只有明确来源之后，省略编号的追问才会自动解析。若返回 `clarification`，选择页面“澄清公告对象”或在问题中输入明确编号。

## 仍需并行推进

人工盲标实际完成仍为 0/127；没有据本轮工程测试或三次模型联调推出答案准确率。缺失来源真实补采、持续监测证据与独立生成模型评测依原路线继续。异常中断若发生在云端已响应而数据库尚未提交之间，本地 `request_id` 无法向第三方保证严格一次计费；本系统不自动重试云端请求，需按审计确认后再由用户重试。
