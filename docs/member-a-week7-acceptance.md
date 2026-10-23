# A 第七周：数据修复与冻结前验证

2026-09-24。已完成本轮工程修复、实验归档和持续监测启动；本周整体仍在进行中，正式功能冻结条件尚未全部满足。

## 已修复问题

| 问题 | 新行为 | 验证 |
|---|---|---|
| 来源撤回删除比较、丢失人工历史，并可能被补证任务外键阻止 | 比较改为 inactive，保留原 ID、观察值、复核历史和补证关联 | 撤回/再出现、默认查询过滤、拒绝编辑 inactive 回归通过 |
| 来源更新后旧复核仍显示已确认 | 标记 needs_evidence、递增 annotation_version、保存旧观察快照 | 旧版本编辑不再覆盖新来源判断 |
| 同组件多个版本区间被误判为矛盾 | 包版本区间按并集；未知分支不能支持“不受影响” | 命中一段、全部不命中、包含未知的回归通过 |
| 生态与 CPE 语义过度推断 | 非 pip 生态保留 unknown；CPE 环境条件、AND/negate、额外平台限定及复杂版本保守处理 | 叶子条件与完整配置适用性分开 |
| 非法或版本冲突 SBOM | 检查根类型、数组、字段类型/长度、purl 与 version 一致性 | 非法输入被明确拒绝 |
| 并发监测进程覆盖心跳 | 独立进程租约与原子心跳写入 | 第二进程被拒绝，退出后可重新启动 |
| 更新来源后语义索引缺少补齐 | `monitor --sync-semantic` 在采集周期后对账 | 新向量补齐、重复对账和模型故障隔离通过 |

富化 schema 为 `structured-v2`，资产证据新增 `conservative-match-v2`。CPE 语义参考 [NVD 官方说明](https://nvd.nist.gov/general/faq-sections/cpe-faqs)，Python 版本规则参考 [Python Packaging 规范](https://packaging.python.org/en/latest/specifications/version-specifiers/)。这些仍是来源条件比较，不是漏洞复现。

## 真实库与服务

迁移前在线备份：`data/backups/before-member-a-week7.sqlite`，完整性 ok。迁移版本 `a730cf924be1`，API 0.11.0。旧复核记录原本没有保存的 observations 保持 null，不伪造历史。

常驻采集启动于 2026-09-24 15:53 左右（Asia/Shanghai），命令为 `zhidu monitor --sync-semantic`，日志在 `data/member-a-week7-monitor.log`。首轮六个来源均 completed，新增 95、更新 76，648 个变更片段完成向量对账。

- 快照含 669 个事件、798 个历史版本：current 669、superseded 129。
- 3120 个片段、3120 个有效向量，175 个 active 比较。
- 83/83 份全部保存原文通过哈希与大小检查。
- 4789/4789 项历史字段证据可复验，覆盖 57 份历史引用原文。
- 真实库暂无 inactive 样本，归档场景在隔离测试库验证；没有导入虚构测试资产/会话。

A 独立验收页面为 http://127.0.0.1:8002/ 。已有 B 的 8000 服务未被替换。本次采集为当前主机进程，不是开机服务；关机、睡眠或进程退出可能中断，不能宣称已运行 24/72 小时。

停止采集前，读取 `data/collector.heartbeat` 的 PID，用 `ps -p PID -o command=` 核对是本项目 monitor，再发 SIGINT；不要未经核对终止旧 PID。需要重启时执行 `.venv/bin/python -m zhidu monitor --sync-semantic`。

## 实验材料

| 材料 | 结果 |
|---|---|
| [首轮采集](member-a-week7-live-cycle.json) | 六来源完成，648 个向量更新 |
| [派生重算](member-a-week7-enrichment-report.json)及[doctor 对账](member-a-week7-doctor-report.json) | 原文不改写，派生数据升级 |
| [HTTP 实测](member-a-week7-live-check.json) | 0.11.0、就绪、语义完整、生命周期字段通过 |
| [冻结前证据包](member-a-week7-release-check.json) | 工程检查通过，release_ready=false |
| [JUnit](member-a-week7-test-results.xml) | 全工作区 132 项通过，包含 A 本周 13 项专项及同时更新的 B 用例 |
| [监测启动前](member-a-week7-monitoring-before.json)/[启动后窗口](member-a-week7-monitoring-after.json) | 如实保留未覆盖时间，不把启动成功当成长期 SLA |

ruff、格式、Alembic 一致性通过。`monitoring-window --hours 24` 基于当前配置指纹下成功采集后的新鲜度区间并集，保留断档；它不是进程在线率，也不能证明发布后 ≤6h。

## 冻结门槛

1. 持续积累运行窗口，报告断档、覆盖率和发布时间含义。
2. 独立人工标注/复核并计算真实富化与问答指标，固定回归不能代替金标。
3. B 修复后的中文检索、拒答和评测口径需单独验收。
4. 博客、标准法规、POC 元数据仍缺，本轮未虚增来源类别。

当前工程检查通过不等于满足正式冻结和竞赛评分门槛。本次不改写 B 的历史评测 JSON 或冻结清单；真实库增长后旧 corpus hash 失配属预期，B 应使用独立冻结评测库或新版本协议。
