# 成员 B 第三周交付与验收

验收日期：2026-09-20。范围依据 `member-b-week3-handoff.md` 的五项建议。

## 完成情况

| 交接任务 | 交付 | 状态 |
|---|---|---|
| 结构化摘要与复核队列 | 工作台展示实体、CVSS、版本表达式、CPE、质量标记，并提供按缺口/来源筛选的复核队列 | 完成 |
| 结构化检索 | lexical-v3 支持实体、完整 CPE 和质量标记精确过滤，不使用工作流 priority 排序 | 完成 |
| 资料缺口回答约束 | evidence-packet-v2 强制输出不确定性；审计快照保存 schema version 与质量标记 | 完成 |
| 四类安全评测 | CVSS 多评分、复杂版本、无答案、CPE 非资产命中进入固定题集 | 完成 |
| 后续向量引用契约 | 未引入向量服务；文档明确后续召回必须继续保存完整原文引用 | 完成 |

## 真实库结果

升级前 SQLite 完整性检查为 `ok`，备份位于 `data/backups/before-member-b-week3.sqlite`，包含 509 个事件。数据库迁移至 `f3a91c024b17`。

索引升级为 `lexical-v3`：509 个事件、2498 个片段，其中 formal 1676、candidate 822。升级后的首次对账为 509 个事件全部 unchanged，未重写引用片段，说明本周只扩展结构化过滤语义。

固定四题评测见 `member-b-week3-evaluation.json`：

- Hit@K：1.0。
- 引用可复验率：1.0。
- 抽取式不支持行比例：0.0。
- 可回答性准确率：1.0。
- 约束通过率：1.0。

真实库已保存两个关键审计示例：不可解析版本事件会附加“不确定性说明”；不存在记录的问题返回 `no_evidence`、零引用和 `insufficient_evidence`。

全库引用一致性见 `member-b-week3-live-check.json`：2498 个片段全部通过 SHA-256、JSON Pointer 和字符区间复验，覆盖 28 份原始文档。

## 自动验证

- `pytest -q`：69 项通过。
- `ruff check .` 与 `ruff format --check .`：通过。
- `node --check src/zhidu/static/workspace.js`：通过。
- `alembic check`：模型与迁移一致。
- SQLite 升级、降级、再升级测试：通过。
- OpenAPI 已重新导出。

## 工作台

`/workspace` 标题升级为成员 B 第三周。检索模式显示结构化实体、CPE 和资料缺口过滤；当前版本详情显示 `structured-v1` 派生摘要；复核队列可按资料缺口和来源筛选并打开记录；最近问答审计继续只读展示。外部文本仍以 `textContent` 呈现。

浏览器验收已验证 GHSA + 质量标记组合过滤、完整 CPE 精确过滤、结构化详情和复核队列联动，浏览器控制台无错误。

## 限制

- 实体、CPE、CVSS 和质量标记来自确定性派生规则，不是新的来源事实。
- CPE 过滤只匹配来源 criteria，没有资产清单和生态版本求值。
- 版本范围 `opaque` 时不进行比较或修复版本推断。
- 四题固定评测不能外推为通用检索、自由生成问答或事实正确率。
- 本周未引入向量检索、外部模型、多智能体或身份权限系统。
