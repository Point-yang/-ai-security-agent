# B 第一阶段交接：接通大模型多轮与当前证据

2026-09-28。A 已完成 [上下文验收](member-a-rag-context-acceptance.md)。B 负责将现有持久会话、顶部大模型问答与界面交互贯通。本文件的后续要求尚未实现。

## 可复用接口

`POST /api/v1/rag/context`：沿用 `RagRequest` 与 `X-Admin-Key`。只读预览，强制使用 expanded 上下文及本地摘录，无 DeepSeek 请求、无 RagRun 写入。返回 citations、constraints、context、tools 等现有结果字段。

```json
{
  "question": "这条公告影响哪些版本，如何修复？",
  "query": "GHSA-2pc9-4j83-qjmr",
  "mode": "lexical",
  "pool": "formal",
  "origin": "live"
}
```

`POST /api/v1/rag/answers`：默认 context_mode=expanded。generation 可为 configured / deepseek / extractive。`top_k` 限制种子事件数，扩展阶段最多增加两个直接关联事件，最终最多 24 条引用、18,000 字符；不能继续把 top_k 当最终引用数。显式 event_id 不扩展到其他事件。

`context.sources` 含 event_id、revision_id、source_id、source_url、字段清单、引用编号和字段块计数；结构化补丁字段存在与修复关键词候选只是状态提示，不是正确性评分。`context.relations` 记录 same_identifier / shared_cve 的直接关系，未裁决差异。预算裁剪会使回答标记 partial。

`GET /api/v1/conversations/{id}/context-status`：保留原 comparisons，新增 citations。每项含 event_id、snapshot_revision_id、current_revision、status、reusable_as_current。superseded / withdrawn / missing 均不应当作当前证据；历史 replay 保持原哈希。

## B 应实施的行为

1. 顶部问题区域加入会话选择/新建，将生成问题、答复、引用、请求模型、实际模型、失败与费用记录关联到持久会话。现有 RagRequest.conversation_id 目前只继承显式资产；不会自动传入历史问答，不能仅多传一个 ID 就宣称记忆完成。
2. 追问“它/这个版本”时，从该会话已确认的事件和资产中解析上下文；有多个候选时先澄清，不静默猜选。历史答案是待参考文字，不是新的证据来源。
3. 每一轮重新检查引用状态，并从当前版本重新获取 context。旧版撤回时明确提示；不得把新版本内容写回旧消息或改旧引用哈希。
4. 使用足够的当前原文片段调用生成模型；按编号展示结论与引文，保留明确拒答、降级和资料不足提示。不要通过只检查摘录存在就标记语义正确。
5. 问答输入框置于页面前部，将运维状态和历史评测折叠，减少窄窗口下寻找入口的成本。区分 DeepSeek API Key 与项目管理员密钥。
6. 保存实际生成答案的完整端到端耗时与 usage。旧抽取式评测必须与生成模型评测分开；只有独立审核可支持答案准确率结论。

## 联合验收案例

- 同会话：“这条漏洞是什么？”→“影响哪些版本？”→“首次修复版本是什么？”；第二、三轮不需手工重输公告 ID，但原文仍绑定当前版本。
- 两个来源使用不同版本表达：分别引用，解释字段含义，不无依据裁决哪一个正确。
- 来源更新：旧回答保留，提示依据已更新；新回答引用新 revision；旧 replay 哈希不变。
- 来源撤回、证据损坏或没有修复信息：显示限制或拒答，不能用模型先验编造补丁版本。
- 从一个明确资产切换到另一个资产：只使用用户选择的资产；无明确对象时澄清。
- 模型限流、余额不足、超时：保留会话中的失败或降级结果，允许用户重试但不重复写入同一轮。

人工盲标与持续监测按原路线并行推进；本阶段新增工程能力不自动改变竞赛质量评分。
