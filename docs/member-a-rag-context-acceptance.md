# 成员 A 第一阶段：RAG 上下文与会话证据准备验收

2026-09-28。对应 [两人完善路线](competition-score-roadmap-20260928.md)第一阶段 A：补齐版本、修复与关联证据，检查分块、去重和历史版本失效。本阶段 A 工程项通过；大模型多轮会话的产品接入仍由 B 完成，不把本次底层准备称为完整连续对话。

## 已完成

- 增加 `references` 与 `required_action` 原文字段索引，索引版本为 `lexical-v4-context`。词项排序算法仍保留原 `lexical-v3-structured` 方法标识；新增索引字段不等于新增来源覆盖。
- 扩展 RAG 上下文：一个事件不再只交给模型一个命中片段。补取同版本标题、包版本/修复字段、修复相关描述段落、邻接片段和参考链接，按来源分组保留证据。
- 只通过相同公告编号或共同 CVE 增加最多两个直接关联事件；不按标题相似度猜关联。显式 `event_id` 严格限定该事件；正式/候选、live/replay 和撤回状态继续隔离。
- 保留现有 900 字符分块及 120 字符重叠；不重写原文或丢失字符位置。修复关键词候选优先补入，并取一个候选的邻接块以降低边界断句影响。去除重复证据区间，不跨来源合并结论。
- 上下文最多 24 个片段、18,000 字符；按事件轮流选片段，避免单个长文占满预算。到达总预算时标记 partial 并保留约束；每个来源报告可用/已选字段块数，明确不是全文。
- 模型提示版本为 `deepseek-grounded-context-v2`，引用包含来源、版本、字段、标题和链接。明确区分 first_patched_version 与 patched_versions，不把参考链接当作已读全文。
- 索引对账检查实际文本、来源指针、哈希和分类等字段，不仅比对 chunk ID；同 ID 内容损坏也会重建并清理旧向量。检索增加当前事件/版本对应检查。
- 会话新增引用有效性覆盖层：current / superseded / withdrawn / missing，不修改历史消息和 replay 哈希。
- 新增只读上下文预览接口，供 B 在接入大模型多轮前查看实际材料；即使请求 generation=deepseek，也不会调用云端或保存 RAG 运行记录。
- 工作台回答新增上下文概览、来源详情和编号对应的字段引用。

## 真实库更新

先在线备份 SQLite 至 `data/backups/before-rag-context-20260928.sqlite`，完整性为 ok；摘要见 [备份记录](member-a-rag-context-backup.json)。原文未改变；本次备份是库级升级保护，不代替含源码和模型的最终交付包。

索引同步影响 77 个事件，595 个保持不变；重建 704 个片段、替换 620 个，净增 84 个（77 个 references、7 个 required_action）。片段及有效向量从 3130/3130 变为 **3214/3214**，本地模型和维数未变。详见 [索引记录](member-a-rag-context-index.json)、[向量记录](member-a-rag-context-vectors.json)。

两条真实来源工程样本对比：

| 公告 | 原上下文 | 扩展上下文 | 实际送入的资料 |
|---|---|---|---|
| GHSA-2pc9-4j83-qjmr | 2 个 description 片段 | 12 个片段，5076 字符 | 标题、描述、packages、references、标识 |
| GHSA-6pr9-rp53-2pmc | 2 个 description 片段 | 11 个片段，4474 字符 | 标题、描述、packages、references、标识 |

这不是随机抽样准确率实验。两例原文复验和版本字段上下文检查通过，全库字段证据审计通过，当前向量一致性通过。[真实上下文审计](member-a-rag-context-real-audit.json)包含字段数量及来源定位。

## DeepSeek 与 HTTP 验证

真实请求：“GHSA-2pc9-4j83-qjmr 影响哪些版本，首次修复版本是什么？请分别说明来源依据。”模型引用厂商的 patched_versions 和 GitHub 的 first_patched_version，给出来源声明的 `>=0.10.1,<0.14.0` 与 `0.14.0`。回答也包含描述文字与包字段的不同表述，未自动消解来源内容。

请求状态 completed，引用检查通过；模型阶段 3282.406 ms、全流程 4518.968 ms，输入 3392 / 输出 883 / 合计 4275 token。此次仅一条付费连通与上下文使用样本，不是 P95 或独立准确率证明。生成结果仍有冗余解释，`semantic_support_verified=false`；B 应继续做答案相关性、简洁性和语义支持评测。[真实调用记录](member-a-rag-context-deepseek-live.json)。

8010 服务已重启。真实 HTTP 上下文预览返回 200、12 个片段、云端请求数 0，embedding 为 ready、3214/3214。[HTTP 验证](member-a-rag-context-http.json)。

## 回归与边界

- 全项目 **177 项测试通过**，新增 9 项专项测试：[JUnit](member-a-rag-context-tests.xml)。
- 专项覆盖长文末尾修复、包字段和参考链接原文核验、关联来源差异、显式事件限定、旧版本向量清理、同 ID 索引修复、撤回过滤、无云端预览、原文损坏拒引、预算/live-replay 隔离、会话历史哈希稳定。
- 旧 DeepSeek 模拟集成测试更新为按实际传入引用编号返回结果，避免硬编码编号；旧工具路由测试显式使用 baseline。没有弱化原文一致性检查。
- Ruff、格式（83 个 Python 文件）、前端 JS 语法、Alembic 检查通过，OpenAPI 已更新。
- 旧抽取式 benchmark 固定 context_mode=baseline、generation=extractive；原历史报告不覆盖，新增数据字段后的实验需记录新快照。
- 修复关键词只是候选，不是独立补丁确认；参考链接没有自动联网下载。NVD 若缺结构化版本字段，只能引用其已有描述。
- 不新增长期记忆、自由工具执行或自主 Agent。当前多轮对话仍需 B 将会话状态与生成调用接通。

下一步见 [B 第一阶段接入说明](member-b-rag-conversation-handoff.md)。
