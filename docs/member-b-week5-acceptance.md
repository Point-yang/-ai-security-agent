# 成员 B 第五周交付与验收

验收日期：2026-09-22。范围依据 `member-b-week5-handoff.md` 的必做项和验收门槛。

## 完成情况

| 要求 | 交付 | 状态 |
|---|---|---|
| 持久多轮会话 | conversation/message 数据模型保存每轮输入、显式/有效资产、事件、答案、引用和约束 | 完成 |
| 上下文边界 | 只继承会话内曾显式选择的资产；显式 ID 才能切换；拒绝自然语言猜资产 | 完成 |
| 可视化多跳轨迹 | 固定五跳路径，每跳保存输入、输出及 event/revision/raw document/JSON Pointer | 完成 |
| 动态补证 | unknown、资料缺口和 conflict 生成 pending/not_started 任务，保存目标来源和完成条件 | 完成 |
| 冲突核验 | 多来源 trace 双栏、复核 before/after 版本和备注；不自动裁决 | 完成 |
| 个性化推荐 | 只用显式资产环境、重要度、组件与 exposure，输出优先复核/升级建议 | 完成 |

## 固定六用例

独立演示库 `data/member-b-week5-demo.db` 包含两个明确标注的虚构资产，用于验证上下文继承和资产切换。评测结果见 [member-b-week5-conversation-evaluation.json](member-b-week5-conversation-evaluation.json)：

- 多轮：上下文继承、显式切换资产、拒绝隐式资产，共 3 组。
- 多跳：完整五跳链、unknown 动态补证、severity conflict 人工核验，共 3 组。
- 会话通过率：1.0。
- 多跳证据率：1.0。
- 重放确定率：1.0。
- 补证边界通过率：1.0。
- 推荐边界通过率：1.0。

演示库产生 5 个会话、10 条消息和 25 个持久 hop。补证任务包括 3 个 conflict、1 个资料缺口和 1 个 unknown；全部保持 `pending/not_started`，没有执行联网采集。

## 真实库结果

升级前 SQLite 完整性检查为 `ok`，备份位于 `data/backups/before-member-b-week5.sqlite`。数据库迁移至 `d4f86b29a5c0`。

真实库保持 509 个事件、2498 个索引片段和 175 个跨来源比较；索引与比较对账全部 unchanged。真实资产数、会话数均为 0，虚构资产和固定评测会话没有进入真实库。

全库引用复验见 [member-b-week5-live-check.json](member-b-week5-live-check.json)：2498 个片段和 28 份原文通过 SHA-256、JSON Pointer 与字符区间核验。

## 自动验证

- `pytest -q`：86 项通过。
- `ruff check .` 与 `ruff format --check .`：通过。
- 三个前端脚本 `node --check`：通过。
- `alembic check`：模型和迁移一致，当前为 `d4f86b29a5c0 (head)`。
- OpenAPI 已导出，API 版本为 0.8.0。

## 浏览器验收

真实库 `/workspace` 显示第五周标题、0 个资产和 0 个会话，确认演示数据未混入。独立演示库可从数据库重放 5 个会话；完整链显示 5 张 hop 卡，每张均列出 event/revision/raw document/JSON Pointer。

unknown 会话同时显示 `unknown_asset_condition` 与 `source_quality_gap`，状态均为 `pending/not_started`。资产建议显示 P1/P2、`rule_score` 和“升级建议/优先复核”，页面明确说明分数不是概率。severity conflict 的 trace 核验并排展示 3 个来源及字段证据计数，并显示 `v0 unreviewed → v1 needs_evidence` 和分析备注。浏览器控制台无警告或错误。

## 边界

- 多跳是确定性证据导航，不是自由生成式推理，也不引入新的来源事实。
- `replay_sha256` 证明保存快照稳定，不证明上游来源内容真实。
- 补证任务是待办描述，与采集器和外部验证执行严格分开。
- 规则建议只用于人工工作流排序，不能表述为风险概率或自动处置结论。
- 资产 exposure 仍是 SBOM 组件与来源条件的比较，不是漏洞复现。
