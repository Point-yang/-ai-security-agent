# 成员 B 第三周接口与回答约束

第三周在第二周持久索引和不可变引用快照之上使用 `structured-v1` 富化结果。富化字段只参与过滤、摘要和回答边界，不替代来源证据；回答引用仍指向 `event_id`、`revision_id`、`raw_document_id`、JSON Pointer、字符区间和 SHA-256。

## 结构化检索

`GET /api/v1/retrieval/search` 的方法标识升级为 `lexical-v3-structured`，新增参数：

| 参数 | 语义 |
|---|---|
| `entity_type` | `cve`、`ghsa`、`doi`、`package`、`vendor` 或 `product` |
| `entity_value` | 与类型成对提供；忽略大小写精确匹配派生实体值 |
| `cpe` | 忽略大小写精确匹配完整 CPE criteria |
| `quality_flag` | 精确匹配资料质量标记 |

`entity_type` 和 `entity_value` 必须同时提供，否则返回 422。结构化条件只缩小候选事件集合，不增加词项分数，也不把复核 priority 混入排序。原有 pool、来源、类型、组件、严重程度、origin 和撤回过滤继续有效。

示例：

```http
GET /api/v1/retrieval/search?q=authentication&pool=formal&entity_type=cve&entity_value=CVE-2026-48746
GET /api/v1/retrieval/search?q=stop_token_ids&pool=formal&quality_flag=unparsed_version_range
GET /api/v1/retrieval/search?q=CVE-2026-48746&cpe=cpe%3A2.3%3Aa%3Avllm%3Avllm%3A*%3A*%3A*%3A*%3A*%3A*%3A*%3A*
```

## 结构化摘要与复核队列

`GET /api/v1/events/{event_id}` 和 `/enrichment` 返回实体、版本表达式、CVSS、CPE、质量标记、schema version 与 provenance。工作台只把这些字段标为派生摘要，并保留原文字段侧栏。

`GET /api/v1/review-queue` 支持 `quality_flag`、`source_id` 和 `limit`。返回的 priority 是工作流排序，不是风险概率。工作台可从队列直接打开记录，但人工备注仍使用带 `expected_version` 的原有 PATCH 接口。

## 回答前置约束

`GET /api/v1/answer-constraints/{event_id}` 现在同时返回：

- `enrichment_schema_version` 与 `quality_flags`。
- 来源语义规则。
- `derived_structured_data`：派生摘要不能替代原文引用。
- `selected_cvss_display_only`：展示项不是重新评分。
- `cvss_multiple_scores`：多个不同分数必须说明版本或来源差异。
- `cpe_condition_not_asset_match`：CPE 条件不是资产命中。
- 与每个质量标记同名的不确定性规则。

抽取式证据包升级为 `evidence-packet-v2` / `source-boundaries-v2`。命中带资料缺口的事件时，答案追加“不确定性说明”；没有证据时返回 `status=no_evidence`、零引用和 `insufficient_evidence`，拒绝给出事实性结论。每条审计引用同时快照富化 schema version 和当时的质量标记。

外部模型审计接口仍只验证引用存在、集合一致和保存约束，不自动证明自然语言回答中的每条主张已被充分支持。

## 第三周评测

评测配置 `config/member-b-week3-eval.json` 覆盖：

1. CVSS 多评分及展示项边界。
2. 不可解析版本表达式。
3. 无证据问题的拒答。
4. CPE 条件不能推导资产命中。

`retrieval_evaluations` 新增可空字段 `answerability_accuracy` 和 `constraint_pass_rate`，兼容第二周历史记录。Hit@K 只统计配置了期望外部编号的检索题；可回答性和约束命中分别计量。所有指标都只适用于固定题集和抽取式证据包。

## 后续混合检索边界

本周没有引入向量模型或向量数据库。若后续增加向量召回，每个候选仍须映射到当前索引的完整引用契约；派生实体或 embedding ID 不能单独作为事实引用。
