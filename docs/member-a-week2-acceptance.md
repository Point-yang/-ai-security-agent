# 成员 A 第二周验收说明

验收日期：2026-09-20

## 本周目标与结论

成员 A 已完成第二周的多源安全情报采集、增量监测、可解释初筛和跨来源关联基础能力，并保持成员 B 第一周的检索、引用、导出和版本对比契约兼容。

本轮属于功能与集成验收。它证明采集链路、持久化、恢复机制和前后端联调可运行，不代表已经达到生产级实时 SLA，也不把规则标签当作人工确认结论。

## 已完成能力

| 能力 | 实现与验收口径 |
| --- | --- |
| 多源接入 | 接入 GitHub Advisory、vLLM 官方安全公告、NVD、CISA KEV、Crossref，共 5 个来源、4 类来源类型。 |
| 定时监测 | `zhidu monitor` 支持按目标周期调度；`--once` 执行有限轮次；失败目标独立退避，不阻断其他目标。 |
| 增量与恢复 | 水位、分页 continuation、失败次数和下次调度时间持久化；每页与 continuation 在同一事务提交；未完成或失败时不推进水位。 |
| 并发保护 | SQLite 使用文件锁，PostgreSQL 使用 advisory lock，避免多个采集写进程同时运行。 |
| 可解释初筛 | 独立 `event_triage` 派生表提供 `relevant`、`needs_review`、`unrelated` 三种标签，并记录命中词、分类和规则版本。重分类不生成虚假的来源版本。 |
| 跨源关联 | `/api/v1/events/{id}/related` 按共享 CVE/GHSA 标识返回关联记录，保留各来源独立事实、原文和版本，不做破坏性合并。 |
| 证据链 | 原始响应、原始记录定位、字段 JSON Pointer、内容哈希、版本和来源身份继续保留。 |
| 展示 | 首页加入来源状态、类型与关联记录展示，默认显示 AI 安全相关记录，并提供候选池与全部记录筛选。 |

## 实际数据快照

本次有限轮次采集后，数据库共有 509 条来源记录、509 个来源版本：

| 来源 | 记录数 |
| --- | ---: |
| GitHub Advisory | 70 |
| vLLM 官方安全公告 | 76 |
| NVD | 27 |
| CISA KEV | 7 |
| Crossref | 329 |
| 合计 | 509 |

规则重分类结果为 `relevant` 241 条、`needs_review` 268 条。这里的数量是来源记录数量，不是去重后的漏洞数量；`needs_review` 必须进入候选池或人工复核，不能在答案中直接表述为已经确认的 AI 安全事件。

Crossref 只采集元数据，当前目标限制为 2024 年以来的论文，并按最近 7 天索引窗口增量查询。Crossref 是动态索引，分页期间总量可能变化，因此本轮不宣称静态快照的绝对全量召回。

六个监测目标在验收快照中均完成最近一轮，配置指纹一致且没有待续分页。快照见 [member-a-week2-live-check.json](member-a-week2-live-check.json)。本轮没有启动后台常驻采集进程。

## 验证结果

- 项目测试：51 项通过。
- 代码规范：Ruff 检查与格式检查通过。
- 数据库迁移：Alembic 无待生成升级操作。
- 前端脚本：成员 A 与成员 B 的 JavaScript 语法检查通过。
- Compose 配置：`monitoring` profile 配置解析通过；本机 Docker daemon 未运行，因此没有完成容器实跑。
- 成员 B 引用兼容检查：509 个事件可读、2498 个字段块通过定位与哈希校验、28 份原始文档被验收脚本验证，结果见 [member-a-week2-citation-check.json](member-a-week2-citation-check.json)。

迁移前数据库备份位于 `data/backups/before-week2.sqlite`。两项新增迁移只增加监测与派生分类结构，旧事件 ID、来源版本和原文证据保持不变。

## 运行方式

```bash
.venv/bin/python -m zhidu init-db
.venv/bin/python -m zhidu monitor --once
.venv/bin/python -m zhidu serve --port 8000
```

连续调度使用：

```bash
.venv/bin/python -m zhidu monitor
```

只强制刷新单个目标使用：

```bash
.venv/bin/python -m zhidu monitor --once --force --target vllm-official
```

容器方式可选：

```bash
docker compose --profile monitoring up --build -d
```

正常完成后按目标配置间隔调度；分页未完成时约 30 秒后续跑；失败时指数退避，最长 6 小时。Crossref continuation 若被上游判定无效，会从同一固定时间窗口重新开始，不推进水位。这些是程序调度行为，不构成采集时延 SLA。

## API 增量

- `GET /api/v1/events`：新增 `source_id`、`kind`、`ai_label` 筛选。
- `GET /api/v1/events/{id}/related`：查询共享标识的跨来源记录。
- `GET /api/v1/monitoring`：查询各目标最近状态、配置一致性、失败次数、下次运行和待续页状态。
- `GET /api/v1/retrieval/search`：兼容原参数，并增加可选 `ai_label` 筛选。

成员 B 在构建索引、检索评测和生成答案时，建议默认显式传入 `ai_label=relevant`，将 `needs_review` 单独作为候选池展示。

## 限制与下一阶段

- 当前只有 4 类来源，赛题方案中的社区、厂商博客、标准与法规等来源仍待扩充。
- NVD 的 CPE、受影响版本和 CVSS 还未转成统一可推理结构；`unknown` 不能解释为不存在风险。
- vLLM 公告中的 patched version range 保存在 `vendor_patched_ranges`，尚未推断成单个修复版本。
- Crossref 不提供论文全文；摘要可能含 JATS 标记，清洗时必须保留原文与可追溯偏移。
- 规则置信度不是校准后的概率，本轮没有宣称 95% 自动富化准确率、检索召回率或 6 小时/7 天时延达标。
- 第三周应推进实体抽取、版本范围标准化、CVSS/CPE 解析、人工复核闭环和质量评测集。

## 上游接口

- GitHub Global Security Advisories API
- GitHub Repository Security Advisories API
- NVD CVE API 2.0
- CISA Known Exploited Vulnerabilities JSON Feed
- Crossref REST API

