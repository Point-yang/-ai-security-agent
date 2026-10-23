# 成员 B 第六周：检索、编排与评测接口

后续修订启用 `bounded-rag-v2`：通过可审计领域词汇做中文检索改写，并加入实体/主题相关性过滤。原始 v1 配置保留以便复验。原报告的支持率错误见 [口径修正](member-b-week6-metric-correction.md)，人工双人审核流程见 [审核指南](member-b-week6-human-review-guide.md)。

API 版本 `0.10.0`，迁移 `f6b104e37a92`。原有词项检索、会话、显式资产和不可变引用接口保持兼容。

## 检索与回答

```http
GET  /api/v1/rag/search?q=audio%20decompression&mode=hybrid
GET  /api/v1/rag/status
POST /api/v1/rag/answers
GET  /api/v1/rag/runs?limit=10
GET  /api/v1/rag/evaluations?limit=5
```

检索支持 `mode=lexical|hybrid`、`pool=formal|candidate`、`origin=live|replay`、精确 `event_id` 和 `limit`。每个命中包含 event、revision、raw document、JSON Pointer、字符起止位置及 SHA-256。分数用于排序，不能作为概率。

回答写接口需要 `X-Admin-Key`：

```json
{
  "question": "音频解压导致内存耗尽的来源证据是什么？",
  "query": "audio decompression bomb",
  "mode": "agentic",
  "pool": "formal",
  "origin": "live",
  "top_k": 5
}
```

`mode` 支持 `lexical`、`hybrid`、`agentic`。可选 `asset_id`、`event_id` 和 `conversation_id`：资产仅来自请求显式 ID 或所选会话已明确选择的资产，文本不会用于猜测资产。RAG 请求中的资产覆盖只作用于本轮，不修改原会话。每轮输入、回答、工具记录和引用保存到 `rag_runs`。

回答类别为 `evidence`、`partial`、`refused`、`unavailable`。来源原文缺失时返回 `reason=evidence_missing`；模型暂不可用时返回 `model_unavailable`；工具预算和时限分别返回 `tool_budget_exceeded` 与 `timeout`。模型失败不会暗中切换为词项基线。事实输出是原文摘录，未接入自由生成式模型。

## 模型与失效机制

当前实际基线为 FastEmbed 0.7.4 / `sentence-transformers/all-MiniLM-L6-v2`，384 维，CPU ONNX 推理。多语言模型下载未完成，因而本轮不宣称多语言语义能力已达标。原始中英文固定问题均保留，用于暴露这一限制。

模型文件逐项计算 SHA-256，形成 `data/models/manifest.json`；向量行保存模型摘要和片段内容摘要。更新来源版本、重分类或撤回导致片段替换时，外键 `ON DELETE CASCADE` 在同一事务删除旧向量。新版本未补齐向量时，混合查询明确报告索引不完整。检索还会连接事件当前版本并排除撤回记录，防止旧片段被召回。

查询不下载模型、不上传语料。只有显式运行模型准备脚本才联网。模型文件准备方式基于 [FastEmbed 官方文档](https://qdrant.github.io/fastembed/Getting%20Started/)；实际运行依赖固定在 `requirements-semantic.lock`。

## 受限编排

当前默认路由配置位于 `config/member-b-week6-router-v2.json`，原 `member-b-week6-router.json` 保留用于旧基线复验。默认最多6次工具调用、15秒、40个候选。允许的工具固定为检索、按来源编号补证、同版本正文上下文、引用复验和五跳证据路径；来源正文不能提供工具名或执行命令。编号命中会扩展为同一事件/版本的正文片段，避免仅返回公告ID。

存在资料缺口或明确要求来源比较时触发补证分支；可分别禁用 `supplement` 和 `trace` 做实验。embedding 运行于单独进程，等待或推理超时会结束该进程；其余本地数据库/证据工具在边界处检查剩余时间，最终答复也检查截止时间。数据库 I/O 是协作式超时，不承诺任意系统阻塞下精确在 15 秒终止。

补证输出仍为 `pending/not_started`。本周未调用联网采集或 POC，不宣称多 Agent 性能提升。所有超时与预算耗尽分支都停止输出事实引用。

## 冻结集与人工标注

`config/member-b-week6-frozen-qa.json` 保存全库的 CVE/公告别名/规范化标题传递分组、train/development/test 划分、语料摘要、20 个来源支持的开发回归问题及 A 提供的 127 个待人工标注记录。`split` 是本轮权威划分，A 原有 `suggested_split` 仅保留作历史参考。未进行训练或按测试集调参。

正式人工金标尚未取得，`official_human_gold_scores=null`。人工审核应以冻结版本为准，另存标注侧文件，包含问题 ID、答案类别、完整答案、引用字段和原文摘录；测试组需两名独立审核者。不得直接修改冻结清单或将本轮自动开发标签当成人工结果。

## 重现命令

```bash
.venv/bin/pip install -r requirements-semantic.lock
.venv/bin/python -m zhidu init-db
.venv/bin/python scripts/prepare_week6_model.py
.venv/bin/python -m zhidu.rag_cli semantic-sync --output semantic-index.json

# 仅在独立数据库运行评测，报告中的语料摘要必须与冻结清单一致。
ZHIDU_DATABASE_URL=sqlite:///./data/member-b-week6-eval.db \
  .venv/bin/python -m zhidu.rag_cli benchmark --repeats 2 --concurrency 1 \
  --output docs/member-b-week6-rag-evaluation.json
```

本机已准备官方备用站模型，离线复用：

```bash
.venv/bin/python scripts/prepare_week6_model.py \
  --model-path data/models/minilm-official/fast-all-MiniLM-L6-v2
```

评测覆盖完整后端回答、引用核验、数据库提交和 JSON 序列化，记录 P50/P95、冷启动、并发、硬件、模型与缓存状态；不包含 HTTP 传输。未采用流式，首字时延为 null。API 费用为 0；本地 CPU/电力费用未计价，不能称为零总成本。

开发报告中的“准确率”仅指回答类别匹配；引用支持率要求原文摘录一致且事件属于冻结期望集合，不能代替人工蕴含判断；Recall@5 按期望事件集合计算。正式总体答案准确率仍等待独立人工金标。
