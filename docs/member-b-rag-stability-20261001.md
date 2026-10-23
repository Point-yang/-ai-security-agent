# RAG 索引恢复与持续维护

日期：2026-10-01。主库在新增来源持续采集后有 3759 个当前检索片段、2755 个有效向量，`/api/v1/rag/status=index_incomplete`；当时混合检索返回 `model_unavailable`，词项检索仍可返回来源证据。原因是原采集进程未启用已有的 `--sync-semantic` 维护选项，新片段没有自动补齐向量。

恢复前用 SQLite 在线备份主库至 `data/backups/before-rag-semantic-sync-20261001.sqlite`，SHA-256 `d5216c54f07995fda473faa952c66109389a980d2748ad718c5a21b7f2e80c41`，完整性为 `ok`。随后运行本地 `semantic-sync`，一次补齐 **1004** 个向量；[对账报告](member-b-rag-semantic-sync-20261001.json)绑定本地 `sentence-transformers/all-MiniLM-L6-v2` 模型摘要与 384 维向量。没有下载模型或调用外部生成 API。

原 `com.zhidu.collector.continuous` 已替换为 `com.zhidu.collector.semantic`，启动命令为 `python -m zhidu monitor --config config/sources.json --sync-semantic`。新进程持有唯一采集心跳，每轮采集后或至少每五分钟尝试对账；首次持久化 `semantic_reconcile` 动作状态为 `completed`、扫描 3759 个片段、后续变化 0。切换时新旧进程曾短暂竞争采集锁并产生四条启动错误，旧任务移除后新进程持续运行；不把这些启动错误隐藏为成功轮次。

验证范围：

- 主库 `PRAGMA integrity_check=ok`，3759/3759 当前向量就绪。
- 项目内只读 [混合检索验证脚本](../scripts/verify_rag_ready.py) 对 `CVE-2025-30202` 返回 `evidence` 和 13 条引用，完整调用约 1.35 秒。
- 实际 8010 进程的 `/api/v1/rag/status` 返回 `ready`、3759/3759；`/api/v1/rag/search` 混合模式返回 HTTP 200、两个当前来源结果。
- 8010 重启加载当前代码后，首次通过系统代理访问混合检索时客户端超时；绕过代理直连同一接口返回 HTTP 200、两份当前来源。服务日志中的请求状态为 200，故该次客户端代理超时不计作 RAG 服务错误。
- [端到端公开题实测](member-b-rag-live-generation-20261001.json)：本机 `/api/v1/rag/answers` 返回 HTTP 200，DeepSeek `completed`，两个来源共 13 条引用，逐字引用检查通过，服务端耗时 3800.026 ms，1 次外部生成请求、5521 token。运行 ID 为 `a98f2384-6aed-42b8-8d0d-98be3887263d`，结果保存在主库问答审计表。
- 采集更新后向量补齐与错误模型拒答的两条针对性回归测试通过；Ruff 检查通过。

本轮证明当前检索、向量、原文引用和一次 DeepSeek 生成链路可用；单题成功不能推断总体语义正确率、P95 或七天无故障。历史完成记录和 v4 对照仍按各自冻结数据范围解释。若后续模型文件损坏或本地推理失败，对账会记录失败，混合检索显式拒绝使用不完整向量；词项模式仍可用于只读证据查看。
