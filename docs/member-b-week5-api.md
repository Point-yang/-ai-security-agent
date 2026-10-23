# 成员 B 第五周多轮、多跳与补证接口

第五周把问答上下文、多跳证据、补证任务和资产建议保存到数据库。浏览器只负责读取和展示；刷新或换客户端后，`replay` 仍返回相同的审计快照。

## 持久会话

```http
GET  /api/v1/conversations
POST /api/v1/conversations
GET  /api/v1/conversations/{conversation_id}
GET  /api/v1/conversations/{conversation_id}/replay
POST /api/v1/conversations/{conversation_id}/turns
```

创建会话和提交轮次是写操作，需要 `X-Admin-Key`。创建时可以明确选择 `asset_id`：

```json
{
  "title": "生产推理集群核验",
  "asset_id": "asset-uuid"
}
```

提交轮次沿用抽取式问答的 `question`、`query`、`pool`、`origin`、`event_id` 和 `limit`，并可显式传入新的 `asset_id`。规则如下：

- 未传 `asset_id` 时，只能继承该会话此前明确选择的资产。
- 显式传入另一个 `asset_id` 才会切换会话资产。
- “另一个资产”“切换资产”等自然语言请求没有同时提交 `asset_id` 时返回 `asset_context_required`，不会按名称或指代猜测。
- 每轮保存 user/assistant 两条 message，并保存问题、请求参数、显式资产、有效资产、选中事件、引用、约束、答案状态和答案审计 ID。

`replay` 读取数据库中的 message、hop 和 evidence task，并返回 `replay_sha256`。它不依赖浏览器内存，也不重新调用模型或联网采集。

## 五跳证据轨迹

每个 assistant message 持久化以下确定性路径：

1. `event_selection`：问题和精确事件选择到 event。
2. `cross_source_comparison`：共享 CVE 到 agreement/variation/conflict observation。
3. `asset_exposure`：明确资产到该事件或比较来源对应的 exposure。
4. `event_trace`：event 到全部 revision、字段差异和完整性结果。
5. `raw_evidence`：revision 到 raw document、SHA-256 和 JSON Pointer。

每一跳分别保存 `input_data`、`output_data` 和 `evidence_refs`。完整引用至少包含 `event_id`、`revision_id`、`raw_document_id`、`json_pointer` 和 SHA-256；自然语言说明不能代替证据标识。

## 动态补证任务

```http
GET /api/v1/conversations/{conversation_id}/evidence-tasks?status=pending
```

系统对以下情况创建任务：

- `unknown_asset_condition`：来源版本条件无法安全确定。
- `source_quality_gap`：富化仍有缺失字段或不可解析表达式。
- `cross_source_conflict`：严重性来源观察互相冲突。

任务保存缺失字段、目标来源、完成条件和完整证据引用。新任务固定为 `status=pending`、`network_verification_status=not_started`；本接口不会启动采集器，也不会把待办显示为已验证。

## 冲突核验

```http
GET /api/v1/comparisons/{comparison_id}/review-context
```

响应包含每个 observation 对应的 event trace、完整证据引用，以及人工复核的 before/after 版本和分析备注。原有 `PATCH /api/v1/comparisons/{comparison_id}/review` 继续使用乐观锁。人工复核不会改写来源 observation，`automatic_resolution` 始终为 `false`。

## 资产规则建议

```http
GET /api/v1/assets/{asset_id}/recommendations
GET /api/v1/conversations/{conversation_id}/recommendations
```

建议只读取明确选择资产的 environment、criticality、component 和 exposure。输出类型为“优先复核”或“升级建议”；`rule_score` 仅表示工作流排序，`ranking_is_probability=false`。没有明确资产的会话返回 409。

## 固定评测

```bash
ZHIDU_DATABASE_URL=sqlite:///./data/member-b-week5-demo.db \
  .venv/bin/python -m zhidu conversation-eval \
  --config config/member-b-week5-conversation-eval.json \
  --output docs/member-b-week5-conversation-evaluation.json
```

评测覆盖上下文继承、显式切换、隐式资产拒绝、完整五跳、unknown 补证和 severity conflict 核验。指标只适用于固定案例，不表示自由生成推理准确率或联网验证率。

完整机器契约见 [openapi.json](openapi.json)。
