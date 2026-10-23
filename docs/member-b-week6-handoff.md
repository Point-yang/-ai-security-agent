# 成员 B 第六周交接

2026-09-22。A 已交付监控、运维、恢复审计、容器实测与富化评测基础。真实库当前 574 条情报，2724 个引用片段，包含 53 个 superseded 历史版本，可用于真实更新案例演示。

## B 本周任务

1. 问答金标与对照：冻结测试集；按 CVE/同义实体分组，避免相同问题不同来源跨训练/测试泄漏。区分正确答案、部分证据和应拒答案例；不要把六用例通过率当成通用准确率。
2. 语义检索：在现有词项检索基础上增加 embedding 召回与重排序；对照词项、混合检索、Agentic RAG。所有命中保留 event、revision、raw document、JSON Pointer、字符区间；旧片段作废时新索引必须同步失效。
3. 受限 Agent 工具编排：在确定性五跳基础上增加可配置路由、工具预算、超时、补证分支和引用检查。每个分支应有可重复实验；不因包装成多个角色就宣称多 Agent 性能提升。
4. 响应评测：测完整回答的 P50/P95 与首字时延（如采用流式），同时报告数据规模、硬件、并发、模型与缓存状态；接入 `/metrics` 的 HTTP 时延仅是接口耗时，不能替代答案质量评测。
5. 页面整合：接入运行 status 和富化评测接口；“来源超期”“证据缺失”“模型暂不可用”要有不同提示。保留原有显式资产和会话边界。

## A 提供的材料

- [第六周验收](member-a-week6-acceptance.md)、[运行手册](member-a-week6-runbook.md)。
- [127 例待标注原文包](member-a-week6-annotation-pack.json)：开发 99、留出 28；全部尚未标注。
- [真实历史字段审计](member-a-week6-evidence-audit.json)、[引用复验](member-a-week6-citation-check.json)。
- `/api/v1/operations/status`、`/api/v1/operations/evaluations`、`/api/v1/enrichment/evaluations`、`/metrics`，接口详情见 [OpenAPI](openapi.json)。

## 共同验收门槛

记录准确率、拒答正确率、引用支持率、Recall@K、P50/P95、请求成本及版本。训练/开发/测试集分组冻结后再调参。正式得分中的总体准确率/召回率和连续监测 SLA 仍需人工金标和持续运行证据，不以当前 characterization 回归集替代。

## 仍需补齐的冲奖扩展

来源目前仍为 4 类；博客、标准法规、POC 元数据需独立数据契约和采集验证。Memory 要有来源版本失效与资产隔离；微调与 KV Cache 只在检索基线和模型部署确定后用消融实验决定，不能挤占本周准确率/性能评测。

## 2026-09-24 执行记录

工程交付、冻结数据和真实对照结果见 [B 第六周工程验收](member-b-week6-acceptance.md) 与 [API/运行说明](member-b-week6-api.md)。独立人工标注尚未取得，正式得分仍为 null。英文 embedding 基线已实测，中文召回与部分拒答案例未通过质量门槛；没有把工程功能完成等同于整体质量验收通过。
