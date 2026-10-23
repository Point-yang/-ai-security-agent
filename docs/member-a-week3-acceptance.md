# 成员 A 第三周交付与验收

验收日期：2026-09-20

## 本周范围

第三周完成当前来源记录的结构化实体抽取、版本表达式保守解析、CVSS 汇总、NVD CPE 条件抽取、资料缺口标记和人工复核队列。所有结果保存在独立派生表，可以从当前来源版本与原文重新构建，不修改原文、来源指纹、事件版本或成员 B 的引用片段。

## 实现结果

| 能力 | 实现 |
| --- | --- |
| 实体抽取 | CVE、GHSA、DOI、软件包、CISA 厂商/产品、CPE 厂商/产品 |
| 版本范围 | 解析简单比较符列表并保留原始字符串；复杂表达式标记 `opaque`，不猜测语义 |
| CVSS | 兼容 GitHub/vLLM 与 NVD metrics，保留所有有效条目及路径，并透明选择一个展示项 |
| CPE | 从 NVD 原始 configurations 递归抽取 criteria、vulnerable 和版本边界，保留精确 JSON Pointer |
| 质量标记 | 区分元数据、目录范围、缺少 CVSS、缺少影响范围、缺少 CPE、未知包名和无法解析的版本表达式 |
| 人工复核 | 新增按 AI 相关性、严重度、在野利用类型和资料缺口排序的复核队列；原有乐观锁备注接口继续使用 |
| 自动维护 | 新采集的 current 版本在同一事务更新富化；`zhidu enrich` 可全量对账并清理孤儿派生记录 |

## 真实库结果

对 509 条当前事件完成富化：

- 覆盖率：509/509，100%。
- 实体：812 个。
- 有可用 CVSS：167 条。
- 有版本范围：146 条。
- 有 CPE 影响条件：7 条。
- 质量标记：329 条论文元数据、7 条 KEV 目录范围、20 条缺少影响范围、20 条 NVD 缺少 CPE、6 条缺少 CVSS、2 条未知包身份、8 条复杂版本表达式。

第二次执行 `zhidu enrich` 时 509 条全部 unchanged，证明同一状态下对账幂等。机器可读结果见 [member-a-week3-enrichment-report.json](member-a-week3-enrichment-report.json)。

## 新接口

- `GET /api/v1/enrichment/status`：覆盖率、结构化字段数量和资料缺口分布。
- `GET /api/v1/events/{event_id}/enrichment`：单条事件结构化结果和来源路径。
- `GET /api/v1/review-queue`：待复核事件，可按 `source_id` 或 `quality_flag` 筛选。
- `GET /api/v1/events/{event_id}`：兼容原响应并新增可选 `enrichment`。

复核队列的 priority 仅用于安排人工工作，不是漏洞风险概率。CVSS `selected` 是按照 Primary、版本与分数的透明排序结果，不是本系统重新评分。

## 验证

- 全量测试：64 项通过。
- Ruff 检查和格式检查：通过。
- Alembic：无待生成迁移；升级、降级、再升级测试通过。
- 前端 JavaScript 语法检查：通过。
- 成员 B 兼容检查：509 个事件、2498 个索引片段和 28 份原文全部复验通过，见 [member-a-week3-citation-check.json](member-a-week3-citation-check.json)。
- 迁移前 SQLite 完整性检查为 `ok`，备份位于 `data/backups/before-member-a-week3.sqlite`。

## 边界

- 没有根据 CPE 判断任何本地资产是否受影响；资产清单/SBOM 尚未接入。
- 版本解析只接受明确比较符列表，尚未实现各生态完整版本语义与区间求交。
- CVSS、CPE 和受影响范围仍是来源声明；多来源冲突尚未自动裁决。
- 本轮衡量的是字段覆盖与可追溯性，没有建立实体抽取准确率或版本判断准确率的人工金标准。
- 人工复核接口仍是本地管理员模式，没有账号、角色和租户隔离。

下一阶段适合由成员 B 使用结构化实体和资料缺口增强检索、答案约束与展示；成员 A 后续可接入 SBOM/资产清单、生态版本求值和多来源冲突检测。

