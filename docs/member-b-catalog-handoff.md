# 扩展元数据目录交接给 B

交接日期：2026-09-25。目录能力随 A 第七周范围扩展落库，但暂不改变 B 的正式/候选漏洞检索集合。

```http
GET /api/v1/catalog/items?source_id=nuclei-cves&limit=100
GET /api/v1/catalog/items/{item_id}/history
GET /api/v1/raw-documents/{raw_document_id}/content
```

响应的 `origin` 为 live/replay；本轮真实库中的 37 条目录记录均标为 replay。JSON 来源的 `evidence_locator` 是 JSON Pointer，POC NDJSON 目录使用 `byte:start:end`，不能当成 JSON Pointer。每项均有 `raw_sha256` 和原文 ID。

使用建议：把 `blog`、`standard_metadata`、`policy_metadata`、`poc_template_metadata` 放在独立资料视图；通过 CVE 号可以提出关联候选，但不能自动将模板严重性、政策索引或指南摘要当作漏洞事实。论文和指南都只有元数据时回答需要明确资料范围；POC 应显示“模板未执行”。

在实现多跳关联前，增加测试：同 CVE 的候选关联、不相关博客标题拒入漏洞事实、零政策结果、NDJSON 字节定位、旧版本引用有效、资料撤回或改版后上下文失效。新目录当前无 live 验收，不应进入正式问答质量的金标或来源覆盖统计。

接口契约见 [OpenAPI](openapi.json)，A 的边界和验收见[目录验收](member-a-catalog-acceptance.md)。
