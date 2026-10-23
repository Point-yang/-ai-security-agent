# 成员 B 第四周接口与证据边界

第四周把资产上下文、固定题集、多来源对照和人工复核接入 B 的检索与回答链路。所有资产结论仍是“所选 SBOM 组件与来源条件的比较”，不是漏洞复现或独立验证。

## 资产上下文问答

`POST /api/v1/answers/extractive` 新增两个可选字段：

| 字段 | 语义 |
|---|---|
| `asset_id` | 用户明确选择的资产；只注入该资产与本次证据事件对应的 exposure |
| `event_id` | 将检索限制到一个明确事件，避免正文引用其他公告编号时选错事件 |

资产类问题未提供 `asset_id` 时返回 `status=asset_context_required`、零引用并拒绝给出资产结论。提供不存在的资产或事件返回 404。提供资产后，审计快照保存资产标识、SBOM SHA-256、选中事件和 exposure 的 event/revision/evidence；不会读取其他资产的 exposure。

```json
{
  "question": "我的资产是否受 GHSA-... 影响？",
  "query": "GHSA-...",
  "asset_id": "asset-uuid",
  "event_id": "event-uuid",
  "pool": "formal",
  "origin": "live",
  "limit": 1
}
```

约束版本升级为 `evidence-packet-v3` / `source-boundaries-v3`：

- `affected` 只说明身份与来源版本条件匹配，不代表漏洞已复现。
- `not_affected` 只适用于当前来源记录的范围，不能外推为资产安全。
- `unknown` 必须展示无法安全解析或条件矛盾的原因。
- 没有 exposure 时只能表述为“无身份匹配”，不能改写成“不受影响”。

CLI 对应参数为 `answer-extractive --asset-id ... --event-id ...`。

## 可复现资产报告与评测

`GET /api/v1/assets/{asset_id}/report` 返回报告版本、生成时间、SBOM SHA-256、富化 schema 列表、扫描时间、作用域、限制声明和完整 exposure 证据。CLI 可用：

```bash
.venv/bin/python -m zhidu asset-report ASSET_ID --output report.json
```

`GET /api/v1/asset-evaluations?limit=20` 返回已持久化的固定题集结果。`asset-eval` 从配置读取资产名及用例，验证状态、event/revision/原文指针证据和边界声明：

```bash
.venv/bin/python -m zhidu asset-eval \
  --config config/member-b-week4-asset-eval.json \
  --output docs/member-b-week4-asset-evaluation.json
```

固定题集覆盖 `affected`、`not_affected`、`unknown`、无身份匹配和严重性来源冲突。指标仅适用于该演示资产与固定来源条件，不能外推为完整资产安全评估。

## 跨来源比较与人工复核

`GET /api/v1/comparisons` 新增 `review_status` 过滤，支持：

- 自动比较状态：`agreement`、`variation`、`conflict`。
- 人工复核状态：`unreviewed`、`acknowledged`、`needs_evidence`。
- `identifier` 精确筛选共享 CVE。

工作台双栏显示每个来源的 event、revision、原文 SHA-256、JSON Pointer 与原文链接。`automatic_resolution` 始终为 `false`。

只有严重性 `conflict` 可使用管理员密钥写入人工状态和备注：

```http
PATCH /api/v1/comparisons/{comparison_id}/review
X-Admin-Key: ...
Content-Type: application/json

{
  "expected_version": 0,
  "review_status": "needs_evidence",
  "analyst_note": "需要核对不同来源的评分版本。"
}
```

`expected_version` 实现乐观并发控制，版本过期返回 409；非严重性冲突返回 422。复核不会修改自动比较状态、来源 observation 或选出胜方。`GET /api/v1/comparisons/{comparison_id}/reviews` 返回不可变更的复核历史。

完整机器契约见 [openapi.json](openapi.json)。
