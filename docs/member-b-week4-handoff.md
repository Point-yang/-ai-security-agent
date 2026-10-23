# 成员 B 第四周数据与界面交接

交接日期：2026-09-20。成员 A 已完成 CycloneDX 资产接入、三态版本判断和跨来源差异复核；B 可以在保持证据边界的前提下扩展检索、回答和展示。

## 新接口

```http
GET  /api/v1/assets
GET  /api/v1/assets/{asset_id}
GET  /api/v1/assets/{asset_id}/exposures?status=affected
POST /api/v1/assets/import-cyclonedx
POST /api/v1/assets/{asset_id}/scan
GET  /api/v1/comparisons?identifier=CVE-...&status=conflict
POST /api/v1/comparisons/rebuild
```

三个写接口需要管理员密钥。`/assets` 已提供可直接验收的只读页面。完整字段见 [openapi.json](openapi.json)。

## 必须保留的语义

- `affected` 只能表述为“当前 SBOM 组件匹配来源声明的身份与版本条件”，不能表述为漏洞已复现。
- `not_affected` 只针对当前来源记录的范围，不能外推为资产安全。
- `unknown` 必须保留原因，不能降级成否定结果。
- 比较项中的 `conflict`/`variation` 是复核信号；`automatic_resolution` 恒为 false。
- 回答引用应落到 exposure 的 event/revision/evidence，或 comparison 的 observation，而不是只引用聚合状态。

## 建议 B 的第四周任务

1. 为问答请求增加可选 `asset_id`，仅在用户明确选择资产时注入该资产的 exposure；无资产上下文时继续禁止回答“我的资产是否受影响”。
2. 建立资产影响固定题集，覆盖 affected、not_affected、unknown、无身份匹配和来源条件互相矛盾，并验证每个结论都有 event/revision 证据。
3. 在研究工作台增加跨来源比较筛选与双栏证据查看，明确区分 agreement、variation、conflict。
4. 为严重性冲突提供人工复核状态与备注，不自动选取“最高严重性”作为事实答案。
5. 导出资产报告时加入 SBOM SHA-256、富化 schema、扫描时间和限制声明，确保比赛演示结果可复现。

真实数据库当前没有资产，B 开发应使用临时数据库或独立演示库导入 [cyclonedx-vllm-demo.json](../examples/cyclonedx-vllm-demo.json)，不要把虚构样本混入真实库。

## 完成记录

成员 B 已于 2026-09-21 完成上述五项任务。接口与证据边界见 [成员 B 第四周 API](member-b-week4-api.md)，实现与真实库/独立演示库验收见 [成员 B 第四周验收](member-b-week4-acceptance.md)。虚构样本只存在于 `data/member-b-week4-demo.db`，真实库资产数保持为 0。
