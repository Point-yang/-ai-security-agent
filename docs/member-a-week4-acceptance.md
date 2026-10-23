# 成员 A 第四周交付与验收

验收日期：2026-09-20。目标是把第三周的来源版本范围推进到可审计的资产组件比较，并建立多来源差异复核入口。

## 完成情况

| 任务 | 交付 | 状态 |
|---|---|---|
| SBOM/资产接入 | CycloneDX JSON、purl/CPE 组件身份、资产环境与重要度 | 完成 |
| 版本判断 | package 与 CPE 两条保守求值路径，三态结果 | 完成 |
| 证据链 | 每项判断绑定 event、revision、来源、富化版本和原始结构项 | 完成 |
| 多来源差异 | 按共享 CVE 比较严重性、CVSS 展示项和影响范围 | 完成 |
| 展示与接口 | `/assets` 只读页面、查询接口、受控导入/重扫接口和 CLI | 完成 |

## 判断规则

- `affected`：组件身份一致，且所有可支持的来源版本条件均命中。
- `not_affected`：组件身份一致，但版本落在该来源记录范围之外，或匹配的 CPE 条件明确标为 non-vulnerable。
- `unknown`：来源表达式不透明、版本不可比较、比较符不支持，或 package/CPE 条件互相矛盾。
- 没有身份匹配的事件不创建资产影响项，避免把“未匹配”误写成“不受影响”。

所有状态都是 `source_asserted_component_version_comparison`，接口明确返回 `independent_verification=false`。系统没有执行漏洞复现，也没有把来源范围视为完整世界知识。

## 真实库结果

升级前 SQLite 完整性检查为 `ok`，备份位于 `data/backups/before-member-a-week4.sqlite`；数据库迁移至 `a41c27d0e944`。真实库没有导入虚构资产，因此资产扫描为 0 个组件和 0 项判断。

跨来源对照覆盖 62 个至少由两个来源共同声明的 CVE，生成 175 个字段比较：96 个 agreement、75 个 variation、4 个 severity conflict。第二次执行 175 项全部 unchanged，证明对账幂等；系统没有自动裁决。机器结果见 [member-a-week4-comparison-report.json](member-a-week4-comparison-report.json)。

兼容复验继续通过：509 个事件、2498 个检索片段、28 份原文均可按 SHA-256、JSON Pointer 和字符区间还原，见 [member-a-week4-citation-check.json](member-a-week4-citation-check.json)。

## 自动验证

- `pytest -q`：74 项通过。
- `ruff check .` 与 `ruff format --check .`：通过。
- `alembic check`：模型与迁移一致。
- `node --check`：三个前端脚本通过。
- API 内联验收：健康检查 200、版本 0.5.0、资产接口 200、175 项比较可读、`/assets` 页面 200。
- OpenAPI 已重新导出。

## 限制

- 当前版本比较使用 PEP 440 可解析语义；生态特有的复杂表达式仍返回 `unknown`。
- CycloneDX 当前只接收 JSON，限制 10 MiB 和 10000 个组件；同名资产重新导入会替换旧组件清单。
- 跨来源对照依赖共享 CVE，不能发现没有共同标识的同一问题。
- CVSS 数值或影响范围不同标为 `variation`，因为差异可能来自版本、评分体系或范围，而非某一来源错误。
- 示例 SBOM 是虚构资料，未导入真实库。
