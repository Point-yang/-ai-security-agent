# 成员 B 第四周交付与验收

验收日期：2026-09-21。范围依据 `member-b-week4-handoff.md` 的五项任务。

## 完成情况

| 交接任务 | 交付 | 状态 |
|---|---|---|
| 显式资产问答 | `asset_id` 只注入所选资产 exposure；`event_id` 可精确绑定证据事件；无资产上下文拒答 | 完成 |
| 资产影响固定题集 | 覆盖 affected、not_affected、unknown、无身份匹配和严重性来源冲突，逐项复验 event/revision/原文证据 | 完成 |
| 跨来源研究工作台 | 支持 CVE、自动状态和复核状态筛选，双栏展示来源 observation 与原文证据 | 完成 |
| 严重性冲突人工复核 | 支持状态、备注、乐观锁和不可变历史；重建比较时保留人工信息 | 完成 |
| 可复现资产报告 | 包含 SBOM SHA-256、富化 schema、扫描时间、完整 exposure 和限制声明 | 完成 |

## 真实库结果

升级前备份位于 `data/backups/before-member-b-week4.sqlite`，数据库迁移至 `b7c94e6a0d31`。SQLite 完整性检查为 `ok`。

真实库仍为 509 个事件、2498 个索引片段，索引对账 509 个事件全部 unchanged。跨来源比较共 175 项：agreement 96、variation 75、conflict 4；重建结果全部 unchanged，`automatic_resolution=false`。真实资产数为 0，虚构样本没有进入真实库。

全库引用一致性见 [member-b-week4-live-check.json](member-b-week4-live-check.json)：2498 个片段和 28 份原始文档通过 SHA-256、JSON Pointer 与字符区间复验。

## 独立演示库

虚构 CycloneDX 样本仅导入 `data/member-b-week4-demo.db`。资产 `week4-vllm-demo` 的 SBOM SHA-256 为 `369dfa8bf3f2e8a77d8da0dd572a25b5a404caaef7c17b3e0727bdb0e5636bbf`，包含 1 个组件和 136 项来源条件比较：affected 75、not_affected 60、unknown 1。

五类固定题集见 [member-b-week4-asset-evaluation.json](member-b-week4-asset-evaluation.json)：

- 状态准确率：1.0。
- 证据可复验率：1.0。
- 边界通过率：1.0。

可复现导出见 [member-b-week4-asset-report.json](member-b-week4-asset-report.json)。精确事件问答已用真实来源公告验证：引用与 `affected` exposure 绑定同一个 event/revision，答案同时声明“来源条件匹配不代表漏洞已复现”。

## 自动验证

- `pytest -q`：78 项通过。
- `ruff check .` 与 `ruff format --check .`：通过。
- `node --check src/zhidu/static/workspace.js`：通过。
- `alembic check`：模型与迁移一致；当前版本为 `b7c94e6a0d31 (head)`。
- OpenAPI 已重新导出。

## 浏览器验收

真实库 `/workspace` 可筛出 4 个 severity conflict；每项并排展示来源值、event/revision、JSON Pointer 和原文入口，并明确提示不自动选择事实胜方。真实库资产选择器显示 0 个资产。

独立演示库 `/workspace` 显示 1 个资产、1 个组件及 affected 75 / not_affected 60 / unknown 1，SBOM SHA-256 与导出报告一致，选择资产后报告按钮可用。最新问答审计展示精确事件引用、对应 affected exposure 和限制声明。两个页面的浏览器控制台均无警告或错误。

## 限制

- 资产状态来自来源条件与 SBOM 组件版本的确定性比较，没有执行漏洞复现。
- 无身份匹配不是 `not_affected`；报告也不等于完整资产安全证明。
- 多源 `variation`/`conflict` 是人工复核信号，系统不自动选择最高严重性或可信来源。
- 人工复核使用本地管理员密钥，没有独立用户身份和租户隔离。
- 固定题集和演示 SBOM 是受控验收资料，不能外推为通用准确率。
