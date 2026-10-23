# 扩展来源真实采集验收

日期：2026-09-30。四个先前仅回放的目录来源已完成官方入口只读探测、相关性过滤、主库备份和持续采集首轮入库。它们保留为独立的**来源元数据目录**，尚未采集博客正文、标准/PDF 全文或 POC YAML，也未把模板执行结果、法律效力或论文与具体漏洞的语义关系当成事实。

| 来源 | 真实单页响应 | 严格过滤后 live 目录记录 | 采集范围 |
|---|---:|---:|---|
| Hugging Face 博客 API | 37,733 字节 | 1 | 标题、日期、文章链接；非安全博客被排除，正文未采集 |
| NIST AI RMF DOI 元数据 | 3,619 字节 | 1 | Crossref 的 DOI、发布方和日期精度；非 NIST 全文 |
| Federal Register API | 218,028 字节 | 2 | 100 条最新搜索结果中有安全/风险/准确性主题的政策索引；一般 AI 问卷通知被排除 |
| ProjectDiscovery `cves.json` | 2,217,099 字节 | 22 | CVE、模板标题、描述和路径；未下载或执行 YAML |
| **合计** | — | **26** | 四类真实来源元数据 |

原有 14 条 HF 回放行仍标为 `replay`，没有改写历史。主库目录现为 40 条当前行：26 条 `live`、14 条 `replay`。目录共有 **63 份版本**，原文字节、哈希、JSON Pointer/NDJSON 字节定位及元数据指纹审计 **63/63 通过**。新目标首轮均 `completed`；旧 CISA 与 vLLM 厂商目标曾因网络失败暂时超期，自动重试后恢复。当前运行快照为 **10/10 目标新鲜、0 失败、状态 `passed`**。

实施中修复了两个会影响计分可信度的问题：博客只保留标题明确涉及安全、隐私或证据核验的文章；政策索引还需标题包含风险、安全、漏洞、准确性等主题词。目录相同内容由 `replay` 再次以 `live` 抓到时，现在会形成新的 live 来源版本；后续 replay 不能覆盖已有 live 当前版本。相关回归验证了这两条 provenance 规则。

证据：[首次探测](member-a-catalog-live-probe-20260930.json)、[扩大政策页探测](member-a-catalog-live-probe-page100-20260930.json)、[最终过滤探测](member-a-catalog-live-probe-filtered-20260930.json)、[全目录审计](member-a-catalog-live-audit-20260930.json)。入库前 SQLite 在线备份为 `data/backups/before-live-catalog-20260930.sqlite`，SHA-256 `5545740c957710b863467dfa09db207307cbe6f62bdb0ce96b5d77c0576554a9`，完整性 `ok`。全项目 **219 项测试通过**，Ruff 检查通过。

四个新增目标已加入 [持续采集配置](../config/sources.json)，由现有 `com.zhidu.collector.continuous` 进程轮询。来源接口与字段仍以各自提供者为准：[Hugging Face 博客 API](https://huggingface.co/api/blog)、[NIST AI RMF DOI](https://doi.org/10.6028/NIST.AI.100-1)、[Federal Register API 文档](https://www.federalregister.gov/developers/documentation/api/v1)、[ProjectDiscovery 模板目录](https://github.com/projectdiscovery/nuclei-templates)。FederalRegister.gov 的 XML/HTML 展示不是官方法律版本，不将索引文本解释为生效法规。

新增只读关联接口 `GET /api/v1/catalog/items/{item_id}/associations`，并生成[目录到漏洞候选关联报告](member-a-catalog-association-report-20260930.json)。当前 26 条 live 目录中有 7 条 POC 模板通过精确 CVE 标识找到 11 条事件候选；每条保留目录原文定位、事件版本和来源，状态为 `candidate_requires_human_review`。系统不自动合并事件、不判断漏洞有效性、不把模板执行或标题命中解释为资产受影响。

该接口代码和测试已完成，但主 8010 进程尚未重启加载这次改动。部署后执行 `launchctl kickstart -k gui/501/com.zhidu.rag.8010`，再请求任一目录项的 `/associations` 路由核对；当前主进程重启受本机自动审批额度限制，不能把测试环境结果当成已上线结果。

当前可以主张“四类扩展元数据来源已真实采集并可追溯，POC 元数据已生成待人工复核的 CVE 候选关联”，不能主张“七类完整情报来源已具备正文与漏洞关联”。后续要提高监测/富化完整性评分，需补博客正文或官方可引用摘要、标准和政策正文状态，并由人工确认候选关联；再用持续窗口证明增量更新和失败恢复。
