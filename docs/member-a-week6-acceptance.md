# 成员 A 第六周工程主线验收

日期：2026-09-22。本轮对应八周排期的容器化、监控、自愈、采集与富化评测。工程主线通过；连续运行 SLA、独立人工金标及新增来源仍列为未完成项。

收尾日期：2026-09-23。本地 8000 已启动 0.9.0，并完成浏览器验收：运行检查、新鲜度告警、回归评测和恢复记录正常展示，控制台无警告或错误。隔离验收容器已停止，数据卷保留。

最新运行快照见 [收尾检查](member-a-week6-current-check.json)：状态 degraded，1/6 个来源仍在两个周期内新鲜，63/63 份原文完整性正常。这是未常驻采集导致的真实超期，不改变 9 月 22 日有限轮采集和故障实验通过的历史结果，也不表示当前运行健康全部通过。

## 实现与证据

| 工作 | 实现 | 验证 |
|---|---|---|
| 容器化 | 非 root、只读根文件系统、tmpfs、数据库持久卷、就绪检查、退出重启、日志轮转 | API + PostgreSQL 在独立 Compose 项目实际运行 |
| 运行监控 | live/ready 分离、Prometheus 指标、HTTP 延迟直方图、来源新鲜度、质量覆盖、运行快照 | 新首页显示通过/降级和具体失败检查 |
| 恢复 | DB/锁临时失败后重新轮询，断点续传，重启中断任务审计，doctor 派生重建 | 容器进程崩溃自动重启、PostgreSQL 重启持久化、缺失索引恢复通过 |
| 采集评测 | 运行耗时分布、发布至首次观察延迟、配置/新鲜度检查 | 历史回填延迟明确不能证明实时 SLA |
| 富化评测 | 持久化固定断言评测、缺失样本保留分母、证据可复验检查 | 8 个回归样本、80 项断言通过；非人工盲测 |
| 人工评测准备 | 原文候选包、空白标注栏、按 CVE 分组建议切分 | 127 例，开发 99、留出 28，尚未标注 |
| 持续集成 | GitHub Actions 测试、格式、迁移、前端语法与容器就绪任务 | 已写入 workflow；尚未推送并触发远端 CI |

## 真实库变化

迁移前备份：`data/backups/before-member-a-week6.sqlite`，完整性为 `ok`。迁移版本 `e82a91c640d7`，API 版本 `0.9.0`。

首次运行快照发现六个来源均超出同步周期，状态为 degraded。随后按原配置运行一轮真实采集，六项全部 completed，总计 18 页，新增 65 条、更新 53 条；没有通过修改时间或水位伪造新鲜度。快照重新评估时六项均新鲜，状态 passed。

- 当前 574 个事件、627 个 revision，其中 current 574、superseded 53。
- 2724 个当前检索片段可复验，使用 40 份原文。
- 全历史 3939 项字段证据全部通过，使用 41 份原文。
- 63 份全部保存原文均通过哈希与字节大小检查；不同原文计数的范围如上，不应混用。
- doctor 修复执行时索引与富化各 574 项 unchanged，175 项跨来源比较 unchanged。真实库仍无虚构资产。

机器报告：[采集结果](member-a-week6-live-collection.json)、[运行评测](member-a-week6-operations-evaluation.json)、[恢复对账](member-a-week6-doctor-repair.json)、[引用复验](member-a-week6-citation-check.json)、[字段复验](member-a-week6-evidence-audit.json)、[富化回归](member-a-week6-enrichment-evaluation.json)。

## 容器与故障实测

独立项目 `zhidu-week6-check` 绑定本机 18000/15432，使用专用卷和虚构回放资料。Docker Hub 拉取超时后，通过 Docker Official Images 的 ECR 分发构建 Python 镜像，未更改全局 Docker 镜像源。

1. PostgreSQL 容器 + 宿主机 Python：迁移一致、导入幂等、丢失索引检测/重建、重复恢复不变、评测入库和 HTTP 接口通过。
2. 重启 PostgreSQL 容器后：虚构数据仍在，同组检查再次通过。
3. API 容器 + PostgreSQL 容器：非 root、只读根目录、就绪接口、指标和首页通过。
4. 对隔离 API 主服务发送 SIGKILL：Docker restart count 增长，就绪接口恢复，数据库记录仍在。

报告：[PostgreSQL](member-a-week6-postgres-check.json)、[数据库重启](member-a-week6-postgres-restart-check.json)、[完整容器与 API 崩溃恢复](member-a-week6-container-check.json)。前两个报告的 `api_container_build_verified=false` 表示那两个实验仅使用宿主机 API；第三份报告验证了完整容器。

## 回归与限制

94 项测试通过；ruff、格式、Alembic 模型一致性、三份前端脚本语法检查通过。保留两个依赖库弃用提示。OpenAPI 已更新。

- 本轮只完成有限轮采集和故障注入，没有连续 24/72 小时运行证据，不能宣称 ≤6 小时监测 SLA。
- 固定回归集依据当前输出检查建立，属于 characterization，不是独立人工金标。127 例候选包未填标签，不能计算总体准确率/召回率。
- 容器退出可自动重启；Docker 健康检查本身不会重启仅处于 unhealthy 的活进程。`doctor --repair` 由运维显式执行并持有写锁；损坏原文会阻止派生重建并记录 blocked，不自动修改原文。
- worker pulse 表示进程存活；来源是否取得进展由数据库 heartbeat、新鲜度和失败次数判断。
- Prometheus 抓取/告警配置已提供，外部 Prometheus、Alertmanager 和通知接收端尚未部署。首页即时告警已实现。
- 仍为 5 个适配器、4 类来源。博客、标准法规、POC 元数据以及 Agentic RAG/Memory 等增强没有在本轮冒充完成；单列在后续路线中。
