# 成员 B 第三周数据交接

交接日期：2026-09-20

> 完成状态（2026-09-20）：下列建议已落实为 lexical-v3 结构化过滤、质量约束问答、固定安全题集和第三周工作台。接口见 [member-b-week3-api.md](member-b-week3-api.md)，真实库结果见 [member-b-week3-acceptance.md](member-b-week3-acceptance.md)。本周没有引入向量模型；现有引用契约继续保留后续混合检索需要的完整溯源标识。

## 可使用的数据

每个当前事件现在可从以下接口获得结构化派生结果：

```http
GET /api/v1/events/{event_id}/enrichment
```

主要字段：

- `entities`：CVE、GHSA、DOI、package、vendor、product。
- `version_ranges`：原始版本表达式、解析状态和简单比较子句。
- `cvss.entries`：所有有效 CVSS 条目；`cvss.selected` 是透明展示选择。
- `cpe_matches`：NVD CPE criteria、vulnerable 和版本边界。
- `quality_flags`：当前资料缺口或来源语义限制。
- `provenance`：原文 ID、JSON Pointer 和验证状态。

这些字段是 `structured-v1` 派生数据，不是不可变来源事实。答案引用仍应指向成员 B 的检索片段或这里的 provenance 对应原文，不能只引用派生表。

## 展示和回答规则

- `cvss.selected` 可以表述为“系统从来源评分中选出的展示项”，不能称为系统重新评分。
- CPE `vulnerable=true` 表示来源配置中的条件，不能在没有资产清单和版本求值时断言某台资产受影响。
- 版本范围 `status=opaque` 时只能展示原始字符串，不进行比较、区间求交或修复版本推断。
- `missing_*` 表示当前资料缺失，不能翻译成“不受影响”“没有评分”或“没有修复”。
- `metadata_only` 的论文记录仍没有全文。
- `catalog_scope_only` 的 KEV 记录可支持“已列入目录”，不提供完整版本范围。

## 复核队列

```http
GET /api/v1/review-queue?quality_flag=missing_affected_scope&limit=50
```

队列默认只包含 `unreviewed` 或 `needs_evidence`，priority 用于安排工作顺序，不是风险概率。人工处理仍通过：

```http
PATCH /api/v1/events/{event_id}/annotation
X-Admin-Key: ...
```

客户端必须提交当前 `expected_version`；发生 409 时重新加载，不能覆盖其他分析人员的备注。

## B 的下一步建议

1. 在工作台增加结构化摘要、质量标记和复核队列视图。
2. 检索排序可把 CVE/CPE/package 实体作为结构化过滤条件，但不要把工作流 priority 混入风险分数。
3. 答案生成前检查 `quality_flags`，对缺失范围或无法解析版本的事件强制输出不确定性说明。
4. 为 CVSS 冲突、复杂版本表达式、无答案问题和 CPE 资产不命中增加评测用例。
5. 引入向量检索时继续保存 event、revision、raw document、JSON Pointer 和派生 schema version。
