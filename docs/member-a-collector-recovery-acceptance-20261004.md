# A：持续采集恢复验收

日期：2026-10-04（北京时间）。本次目标是恢复已有十个采集目标的实际运行，并让下一次传输故障有可诊断、较快的重试路径。**单轮恢复通过；连续窗口与发布后发现时延仍未通过验收。**

## 故障定位

恢复前十个目标中九个状态为 `failed`，多数持久化错误为 `network failure after 3 attempts`；常驻 `com.zhidu.collector.semantic` 进程实际仍在运行，不是简单的“忘记启动”。原调度在多次失败后对网络故障也退避到最长六小时，外网恢复后仍可能继续等待。恢复前 [24 小时窗口](member-a-collector-recovery-before-window-20261004.json)为 `insufficient_coverage`，不能用于证明 ≤6 小时发现 SLA。

对 GitHub、NVD 和 Hugging Face 官方公开入口进行了不带项目凭据的最小连通性检查：前两者本轮成功；Hugging Face 有一次直连超时，但另一轮请求成功。此前具体网络故障的外部根因无法仅凭这些检查确定，未将其归因于单一来源或代码解析器。

操作前使用 SQLite Online Backup API 创建 [独立备份](member-a-collector-recovery-backup-20261004.json)，完整性 `ok`，原主库未清空或覆盖；文件位于 `data/backups/before-collector-recovery-20261004.sqlite`。

## 本轮恢复

在已有数据库写锁下分别强制重试目标，没有同时运行第二个常驻采集器，也没有重置水位。十个目标均完成一轮：

| 目标组 | 结果 |
|---|---|
| HF 博客索引 | `completed`，1 条现有记录，无新建；[记录](member-a-collector-recovery-hf-probe-20261004.json) |
| CISA、Federal Register、Nuclei、NIST | 四个目标均 `completed`；CISA 7 条更新，其他保持/修订详见[单页结果](member-a-collector-recovery-one-page-20261004.json) |
| 两个 GHSA、NVD、vLLM 厂商、Crossref | 五个目标均 `completed`；NVD 4 条更新，Crossref 24 条新建和 45 条更新；详见[主目标结果](member-a-collector-recovery-primary-20261004.json) |

之后对账本地 MiniLM 向量，[对账结果](member-a-collector-recovery-semantic-20261004.json)保存了实际处理数。最终 [全库复验](member-a-collector-recovery-postcheck-20261004.json)：10/10 目标当前新鲜、0 个失败，981 个事件，4278/4278 个当前片段/向量，字段证据 7898/7898、目录版本证据 68/68 通过。8010 服务实际返回 `ready`；采集进程心跳健康、监测状态 10 个 `completed`，见 [重启后 HTTP/心跳记录](member-a-collector-recovery-runtime-20261004.json)。

## 工程修复

- `SourceHTTP` 与 GitHub 采集器仅记录传输异常**类型**（例如 `ConnectTimeout`），不保存异常全文、请求头、token 或原始 URL。
- `failure_retry_seconds` 对连续传输故障改为 120、240、480、960 秒等指数退避，最多 1800 秒；HTTP 429 和其他来源错误仍保留原有较长退避。对长网络断档既避免高频轰炸，又不再每次等待六小时才能复测。
- 新增只读 `GET /api/v1/monitoring/window?hours=24`，接受 1–168 小时，返回成功轮次计算的覆盖和断档；明确 `publication_latency_sla_proven=false`。它既不是进程在线率，也不是发布到采集延迟。
- 按原有 `launchctl` 标签重启采集和 8010 服务加载修复；水位、原文及问答数据仍保留。

全量 **249 项测试通过**，新专项覆盖传输错误脱敏、失败后水位不前进且成功后清零、网络/429 两种不同退避、监测窗口 API。Ruff 全库检查、修改文件格式、迁移检查和所有前端 JS 语法通过。全库格式检查另外发现 17 个未在本次修改的文件仍需统一格式整理；本次没有扩大编辑范围。

## 当前不能领取的成绩

恢复后的瞬时状态是 10/10 新鲜，但恢复前已经发生断档；恢复后 24 小时窗口仍为 `insufficient_coverage`，完整覆盖目标数为 0。过去的失败不能通过重启进程“抹去”。本轮没有证明七天连续稳定、漏洞发布到首次发现 ≤24/12/6 小时，也没有测得来源信息真值准确率。下一步让常驻采集器自然运行，按同一报告口径持续记录成功、失败、断档和增量公告时延；出现新失败时优先按异常类型分类排障。B 的展示与验收要求见 [交接报告](member-b-collector-recovery-requirements-20261004.md)。
