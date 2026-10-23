# B 第二阶段交接：让模型有界选择工具

2026-09-28。A 已交付 [只读工具验收](member-a-agent-tools-acceptance.md)。B 的工作是让模型**按问题选择工具**，并用实测证明有收益；本交接文本不代表自主 Agent 已完成。

## 调用方式

在同一个用户请求事务或查询会话中实例化一次 `AgentToolRuntime(session, store, settings, encoder, pool=..., origin=...)`。模型得到的函数定义从 `contracts()["tools"]` 生成；每次提交 `runtime.execute(name, arguments)`。不要每轮重新创建 runtime，否则会重置 6 次调用和累计 24000 字符预算。若跨 HTTP 做展示，只读预览接口 `/api/v1/agent/tools/preview` 可一次提交最多六步；预览不会形成新的会话或 RagRun，不应当作正式 Agent 轨迹。

工具只有：`retrieve`、`event_details`、`compare_sources`、`asset_exposure`、`verify_evidence`。公开调用接口要求项目管理员密钥，DeepSeek API Key 始终保留在服务端。默认 formal/live；切换候选或回放必须来自用户选择而非模型参数。`asset_exposure` 必须提供显式资产 ID 和事件 ID，结果标有 `private_asset_data=true`，B 应在决定是否向云端继续发送资产详情前维持用户可见的授权范围。

工具返回 `completed` 或失败代码。输出中的来源陈述仅能作为待解释证据：比较结果是派生观察，`verification=not_available` 不能当成原文事实确认；参考链接并未自动读取网页；无 exposure 不能说资产安全。`verify_evidence` 只能证明字节与摘录一致，不证明模型概括在语义上成立。

## B 应完成的工作

1. 给模型一个小而固定的工具目录，限制最多 6 次调用；每个选择必须记录问题、候选工具、选中工具及简短的可审计决策摘要。不要保存隐藏思考内容或让模型执行任意代码。
2. 先用检索找目标，再按问题选择事件详情、跨源比较或显式资产工具；资料不足可补检索一次。工具失败时在预算内决定降级、换词项模式、澄清或拒答，不能静默忽略验证失败。
3. 输出最终答案前，使用 `verify_evidence` 或原有引用核验，确保事实句仍指向本轮当前版本原文。资产条件和来源争议分别提示，不用模型裁决事实冲突。
4. 将工具步骤及失败与会话和 RagRun 关联，记录总耗时、外部 token/费用和当前证据版本；幂等 request_id 仍适用，重复投递不能再次调用模型。
5. 固定留出题集，对比“现有抽取式基线 / 普通 DeepSeek RAG / 新 Agent RAG”；包括无答案、失效来源、两来源冲突、缺失资产、错误引用和限流。分别统计正确性、引用支持、工具成功率、拒答、多跳、P50/P95 与费用。若新 Agent 无质量收益或费用/延迟明显恶化，应如实保留反例。

可以使用 `GET /api/v1/agent/tools/contracts` 获取 schema，用 `POST /api/v1/agent/tools/preview` 离线确定工具行为。真实参考命令：

```bash
.venv/bin/python scripts/verify_member_a_agent_tools.py
```

该命令使用真实库但只读，不调用 DeepSeek，不含人工质量评分。正式生成模型测评仍需独立人工金标，不能以工具运行日志代替。
