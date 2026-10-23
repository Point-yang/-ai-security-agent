# 成员 B 第一周检索接口

> 这是第一周基线说明。第二周已将请求时内存扫描升级为持久化索引，并新增 formal/candidate 集合、问答审计和固定题集评测；当前接口以 [member-b-week2-api.md](member-b-week2-api.md) 为准。本文件保留用于说明兼容字段与第一周设计背景。

研究工作台：`GET /workspace`。新增接口与成员 A API 在同一 FastAPI 服务中运行，共用已有数据库和原文存储，不需要新增迁移、外部模型或依赖。原有 `/` 工作台及 A 的接口保留。

## 关键词检索

`GET /api/v1/retrieval/search`

| 参数 | 默认值 | 语义 |
|---|---|---|
| q | 必填 | 1—200 字符，不能全为空白 |
| package | 不筛选 | 当前影响组件名称，精确匹配 |
| severity | 不筛选 | unknown / low / medium / high / critical |
| origin | live | live 或 replay；按当前有效版本所引用原文的 origin 筛选 |
| include_withdrawn | false | 是否包含撤回情报 |
| limit | 20 | 1—100 个片段 |
| offset | 0 | 非负片段偏移量 |

示例：

```bash
curl 'http://127.0.0.1:8000/api/v1/retrieval/search?q=decompression&package=vllm&origin=live&limit=10'
```

响应包含 `query`、`method=lexical-v1`、`total`、`scanned_events`、`items`。`total` 是命中片段数，不是事件数；`scanned_events` 是应用 origin、组件、严重程度及撤回过滤后的事件数。空结果返回 200 和空 items，空白查询/无效参数返回 422。

items 中每条包含：

- `chunk_id`：事件、版本、字段及偏移生成的确定性标识。
- `external_id`、`title`、`field`、`withdrawn`：来源情报和片段所属字段。
- `text`、`start`、`end`：片段原文以及字段内的 Python Unicode 字符偏移，左闭右开；不是字节或 JavaScript UTF-16 偏移。
- `score`、`matched_terms`：排序分数与命中词，分数不代表概率或核验可信度。
- `citation`：`event_id`、`revision`、`raw_document_id`、`json_pointer`、`sha256`、`origin`、`verification=source_asserted`。

## 分片与排序规则

从当前有效版本的字段证据提取 title、description、packages、external_id 和 cve_id。文本字段使用原文字符串；packages 使用**原始 vulnerabilities 值**，以 Python `json.dumps(value, ensure_ascii=False, sort_keys=True)` 序列化，保留默认分隔空格。引用指向原始字段，未将归一化组件对象冒充原文。

每个片段最多 900 个字符，步长 780，相邻长文本片段重叠 120 个字符。短字段仅产生一片；空值不产生片段。只连接 `event.revision` 且 `disposition=current` 的版本，superseded、stale、conflict 不参与默认检索。

英文与数字按词项匹配、忽略大小写。文档中的连字符、下划线和点分隔词同时索引完整词与组成词，例如 `decompression-bomb` 可以被 `decompression` 命中；查询中的完整 GHSA/CVE/组件标识仍按完整词处理。中文按相邻双字分词；仅输入单个汉字不能可靠命中连续中文，建议输入至少两个汉字。当前不提供词干还原、同义词扩展、翻译、布尔查询或向量相似度。

至少一个查询词命中才返回。分数为“命中查询词数 / 去重查询词数”，再对包含完整查询字符串的片段加 1；同分按事件 ID、字段、偏移稳定排序。多词查询是 OR 召回，命中全部词的结果获得更高基础分。排序不使用标题元数据给描述片段额外加分。

目前每次请求扫描筛选后的当前版本，在内存中分片和排序，适用于第一周的小规模资料。offset 分页无冻结快照，采集更新时可能位移，应重新查询并按 chunk_id 去重。尚未声明生产规模性能或召回率指标。

## 导出检索输入

`GET /api/v1/retrieval/events/{event_id}` 返回当前有效版本的全部 `RetrievalChunk`，无 score / matched_terms。事件不存在返回 404。此接口按指定事件导出，**包含撤回和 replay 事件**，由 `withdrawn` 和 `citation.origin` 明确标识；调用方需自行决定是否纳入知识库。

工作台的“导出当前版本检索输入”在点击时重新请求此接口，因此导出的是请求时的当前版本。保存历史证据请使用引用侧栏的“保存此版本引用 JSON”。后续建立向量索引时，可复用事件 / 版本 / 原文标识做失效和追溯，但当前没有持久向量索引。

## 引用与原文核对

1. 读取 `GET /api/v1/events/{event_id}/history`，按 revision 找到引用版本，不直接使用最新版本替代。
2. 用 `GET /api/v1/raw-documents/{raw_document_id}/content` 取完整 JSON。A 的接口校验存储内容哈希；缺失或损坏返回 503。
3. 校验响应 ETag / 内容 SHA-256 与 citation.sha256 一致。
4. 按 JSON Pointer 定位字段；字符串直接截取，非字符串按上述规则序列化后截取 `[start:end]`，应与 text 完全一致。

JSON Pointer 指向完整字段，start/end 才定义片段范围。引用用于追溯来源声明，并不证明公告内容已被独立核验。版本状态可能在检索后变化，保存的引用仍可还原当时版本。

## 数据隔离与后续接入

真实采集和虚构演示分别使用 `data/zhidu.db` 与 `data/demo.db`；origin 筛选是额外保护，不替代数据库隔离。A 的同 GHSA 幂等规则不会把 live / replay 当作两个独立事件命名空间。

当前只返回检索片段，不生成回答。浏览器可下载引用或本页结果 JSON，尚未保存服务端问答记录。后续接入 RAG 时必须持久保存每次回答实际使用的引用，并将公告内容作为不可信资料处理，不能执行其中的指令。
