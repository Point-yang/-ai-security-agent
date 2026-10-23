# 成员 B 第二周交接说明

交接日期：2026-09-20

> 完成状态（2026-09-20）：下列六项建议均已实现并通过验收。实现接口与边界见 [member-b-week2-api.md](member-b-week2-api.md)，真实库结果与验证记录见 [member-b-week2-acceptance.md](member-b-week2-acceptance.md)。

## 可以直接使用的新增数据

成员 A 已把多源结果写入原有事件、版本、原文与字段证据模型，没有改动成员 B 第一周依赖的事件 ID、版本 ID、内容哈希和 JSON Pointer 语义。

新增记录类型包括：

- `vulnerability`：漏洞与厂商安全公告。
- `exploitation_alert`：CISA KEV 已知在野利用目录记录。
- `paper`：Crossref 论文元数据。

未知字段代表当前来源没有提供或尚未标准化，不能据此推断产品不受影响、没有修复版本或没有风险。

## 检索与索引建议

事件列表和 B 的检索接口均可按 AI 相关性标签筛选：

```http
GET /api/v1/events?ai_label=relevant
GET /api/v1/retrieval/search?q=prompt%20injection&ai_label=relevant
```

为保持第一周兼容，省略 `ai_label` 时仍会检索全部记录。生成式问答、正式检索评测和默认索引应显式使用 `ai_label=relevant`；`needs_review` 建议作为独立候选池，避免把宽泛 AI 论文直接当作已确认的安全情报。

`event_triage` 是可重算的派生判断，不属于不可变来源证据。当前规则版本见 `src/zhidu/classification.py` 的 `RULE_VERSION`；引用答案时应引用来源字段和原文，不应把规则命中词当作外部事实。

## 各来源字段的使用边界

### vLLM 官方安全公告

- 上游部分公告没有标准包名，规范化层会使用 `unknown` 占位；这不是合法产品名。
- 修复版本范围保存在 `vendor_patched_ranges`，不要把范围的第一个边界直接描述为唯一修复版本。
- 原始公告仍可通过字段证据与原文定位核对。

### NVD

- 当前保留 CVE 标识、描述和原始 metrics。
- CPE、受影响版本和 CVSS 尚未完成统一推理，生成答案时不要自行补齐缺失范围。

### CISA KEV

- `dateAdded` 是加入 KEV 目录的日期，不是漏洞首次披露日期。
- catalog release 是目录版本时间，不是每条漏洞各自的最后修改时间。
- 这类记录可以支持“已被 CISA 列入已知在野利用目录”的陈述，但仍应附具体来源引用。

### Crossref

- 只有元数据，没有论文全文。
- `published_at` 带有日期精度信息，可能只有年份或年月；展示时不要虚构具体日期。
- 摘要可能是 JATS 字符串。如需清洗后分块，应同时保存清洗映射或原文定位，确保引用仍可复验。

## 关联接口

```http
GET /api/v1/events/{event_id}/related
```

该接口只表示记录共享 CVE/GHSA 标识，并保留每个来源的独立版本和证据。它不自动证明多个来源相互独立，也不解决字段冲突。展示时适合称为“同标识来源记录”，不要直接标记为“多源交叉验证通过”。

## 监测状态接口

```http
GET /api/v1/monitoring
```

它返回各采集目标的配置状态、最近执行、错误、退避和待续分页信息。它不是采集守护进程的心跳，因此目标状态正常不等于当前一定有后台进程在运行。

## B 的下一步建议

1. 为 509 条来源记录建立持久化索引，并保存 `event_id`、`version_id`、字段路径和哈希。
2. 以 `ai_label=relevant` 建立正式检索集合，以 `needs_review` 建立候选集合。
3. 实现按版本增量重建与删除/撤回同步；当前系统没有消息队列或可靠 outbox，不要只依赖并发条件下的 `updated_since` 游标。
4. 把答案、引用选择、检索分数、模型与提示版本写入服务端审计记录。
5. 先用固定问题集评测检索命中、引用可复验率和幻觉率，再引入多智能体编排。
6. 对漏洞版本范围、论文日期精度和 CISA 日期含义编写专门的答案约束。

接口定义见 [openapi.json](openapi.json)，本轮集成检查见 [member-a-week2-citation-check.json](member-a-week2-citation-check.json)。
