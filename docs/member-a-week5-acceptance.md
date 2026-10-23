# 成员 A 第五周交付与验收

验收日期：2026-09-21。范围对应八周排期中的“字段证据、历史变更、资产页面”。

## 完成情况

| 任务 | 交付 | 状态 |
|---|---|---|
| 字段证据 | 原文字节 SHA-256、JSON Pointer、捕获字段值三重复验 | 完成 |
| 历史变更 | 按观察顺序展示 revision、disposition、字段 before/after 与审计事件 | 完成 |
| 资产页面 | 资产→组件→exposure→事件→revision→原文证据图 | 完成 |
| 真实库审计 | 全历史字段证据批量命令和机器报告 | 完成 |
| 演示边界 | 明确区分证据完整性、来源声明和漏洞独立验证 | 完成 |

## 核心创新演示

`GET /api/v1/events/{event_id}/trace` 对每个历史版本重新读取内容寻址原文，校验文件 SHA-256，解析 JSON Pointer，并比较解析值与当时保存的字段值。响应同时给出当前有效版本、stale/conflict/superseded 状态、与前一观察的字段差异及人工审计时间线。

`GET /api/v1/assets/{asset_id}/evidence-graph` 将资产、SBOM 组件、来源条件判断、事件、revision 和原始文档组成可审计链路，并分别统计来源指针可定位率和字段证据可复验率。页面 `/assets` 可从任意 exposure 打开事件历史，也可生成整项资产证据图。

这条链解决比赛演示中的关键问题：系统不只给出 affected/not_affected，而是可以现场回答“依据哪份来源、哪一版记录、哪个原文字段、数据是否被篡改、后来发生了什么变化”。

## 真实库结果

`zhidu evidence-audit` 对真实库 509 个事件、509 个 revision、28 份原始文档进行复验。3370 个字段证据全部通过，失败为 0，机器结果见 [member-a-week5-evidence-audit.json](member-a-week5-evidence-audit.json)。

真实库当前所有事件都只有一个 current revision，因此没有人为伪造历史变化。独立演示库保留一条两版本事件，1 个 superseded、1 个 current，24 个字段证据全部通过，见 [member-a-week5-demo-audit.json](member-a-week5-demo-audit.json)。

## 自动验证

- `pytest -q`：82 项通过。
- A 第五周新增 4 项测试，覆盖原文复验、两版本字段差异、资产证据图和 API/页面。
- `ruff check .`、`ruff format --check .`、`alembic check` 通过。
- 三个前端脚本语法和 Compose 配置通过。
- OpenAPI 已导出，API 版本为 0.7.0。

## 限制

- 历史差异按观察到达顺序比较；stale/conflict 只显示，不自动成为当前事实。
- 证据通过表示保存的原文字节、指针和字段值一致，不代表上游声明真实，也不代表漏洞可以复现。
- 真实库尚未产生来源更新版本，历史变化演示使用明确标注的虚构演示库。
- 大型资产的证据图当前一次返回全部 exposure；第六周需要增加分页、性能指标和监控。
