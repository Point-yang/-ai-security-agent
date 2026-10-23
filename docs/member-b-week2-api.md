# 成员 B 第二周接口与数据契约

> 第三周已增加实体、CPE 和资料质量过滤，并把富化约束写入问答审计；当前增量说明见 [member-b-week3-api.md](member-b-week3-api.md)。本文件继续定义第二周持久索引与审计基线。

## 持久索引

`search_chunks` 保存当前版本的检索片段。每条包含 `event_id`、不可变的 `revision_id`、版本号、`raw_document_id`、JSON Pointer、SHA-256、字符偏移、来源、记录类型、相关性标签、集合和撤回状态。它是可重建派生数据，来源事实仍以事件版本和原文为准。

集合映射固定为：

| ai_label | pool | 用途 |
|---|---|---|
| relevant | formal | 正式检索和默认抽取式问答 |
| needs_review | candidate | 独立候选池，待人工复核 |
| unrelated | excluded | 兼容全部记录检索，不进入正式集合 |

采集新增或产生新 current 版本时，在同一数据库事务替换该事件索引。`zhidu reclassify` 会重算标签后对账索引。`zhidu index-sync` 扫描数据库当前状态，删除不再有当前版本/分类的索引行，更新版本、标签、集合与撤回状态，不依赖并发条件下可能漏数的时间游标。

```http
GET /api/v1/retrieval/index
```

返回索引版本、同步时间、事件数、片段数和各集合片段数。

## 检索接口

```http
GET /api/v1/retrieval/search?q=prompt%20injection&pool=formal&origin=live
```

第二周新增 `pool`、`source_id`、`kind`，保留第一周的 `ai_label`、`origin`、`package`、`severity`、`include_withdrawn`、`limit` 和 `offset`。同时给出互相矛盾的 pool 与 ai_label 返回 422。省略 pool 和 ai_label 时仍检索全部集合，保持第一周兼容；正式检索必须显式使用 `pool=formal` 或 `ai_label=relevant`。

搜索只读取 `search_chunks`，不在请求时重新扫描事件 JSON。算法版本为 `lexical-v2-persistent`：正文词项是主分，标题词项提供较小加分，正文或标题包含完整查询字符串再加分。分数只用于排序，不是置信度。当前仍是词项检索，不提供向量相似度或跨语言语义召回。

`GET /api/v1/retrieval/events/{event_id}` 返回该事件当前持久索引片段。引用新增 `revision_id`，并继续保留版本号、原文 ID、JSON Pointer、哈希和 origin。

## 来源回答约束

```http
GET /api/v1/answer-constraints/{event_id}
```

返回当前版本应遵守的回答规则：

- 所有来源：只能称为来源声明，不能称为独立验证。
- vLLM 官方公告：`vendor_patched_ranges` 是范围，不能把首个边界说成唯一修复版本。
- NVD：统一 CPE、影响版本和 CVSS 未解析时不能自行补齐。
- CISA KEV：`dateAdded` 是加入目录日期；catalog release 不是单条记录修改时间。
- Crossref：只有元数据；按 `publication_precision` 展示日期，不虚构日/月。
- 含组件范围的记录：不能据此断言具体资产受影响。

约束是本系统的回答政策，不属于不可变外部证据。

## 问答审计

HTTP 写入默认关闭。配置 `ZHIDU_ADMIN_KEY` 后，写接口使用 `X-Admin-Key`；未配置返回 503，错误 key 返回 401。

```http
POST /api/v1/answers/extractive
Content-Type: application/json
X-Admin-Key: ...

{
  "question": "vLLM 是否有认证绕过相关公告？",
  "query": "vllm auth bypass",
  "pool": "formal",
  "origin": "live",
  "limit": 5
}
```

该接口生成抽取式证据包并写入 `answer_audits`。它逐事件去重，不调用外部模型，不综合形成新的漏洞事实。无命中时以 `no_evidence` 保存拒答记录。

外部模型或其他客户端使用 `POST /api/v1/answer-audits` 保存已有回答，必须提交 question、answer、retrieval_query、pool、model、prompt_version，以及实际选用的 chunk_id、检索分数和顺序。服务端验证片段存在且集合一致，再复制不可变引用快照。索引后来替换旧版本时，历史审计仍保留当时的版本和原文信息。不存在的旧片段返回 409，应重新检索。

`GET /api/v1/answer-audits?limit=20` 返回最近审计。当前仅面向本地开发，没有用户账户或租户隔离，不应直接暴露公网。

CLI 可直接生成并审计抽取式证据包：

```bash
.venv/bin/python -m zhidu answer-extractive '问题' --query '检索词' --pool formal --limit 5
```

## 固定评测

问题集位于 `config/member-b-retrieval-eval.json`：

```bash
.venv/bin/python -m zhidu retrieval-eval --output docs/member-b-week2-evaluation.json
```

每题先对片段按事件去重，再计算期望来源记录是否进入 Top-K；每条入选引用重新读取原文、校验 SHA-256、解析 JSON Pointer 并核对字符片段。所谓“幻觉率”仅为抽取式证据包中无法复验的输出行占比，不能外推到自由生成模型。评测结果写入 `retrieval_evaluations` 并可从 `GET /api/v1/retrieval/evaluations` 查询。

当前三题是功能基线，不是统计充分的正式质量证明。后续应扩展由人工标注的正负样本、同义表达、无答案问题、候选池误收和来源日期/版本约束测试。
