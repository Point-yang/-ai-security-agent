# 第六周运维与评测手册

## 本地检查

```bash
.venv/bin/python -m zhidu init-db
.venv/bin/python -m zhidu doctor --output docs/doctor-current.json
.venv/bin/python -m zhidu ops-eval --output docs/operations-current.json
.venv/bin/python -m zhidu enrichment-eval --output docs/enrichment-current.json
```

`ops-eval` 保存快照，并对 degraded/failed 返回非零退出码；`enrichment-eval` 任一指标不通过也返回非零。没有检查原文的轻量 status API 明确返回 `not_checked`，完整原文审计用 CLI。

```bash
# 只在检查后需要重建时执行；CLI 会获取写入互斥锁
.venv/bin/python -m zhidu doctor --repair --output docs/doctor-repair-current.json
# 一轮到期采集（不强制重跑尚未到期的目标）
.venv/bin/python -m zhidu monitor --once
# 常驻进程，需要保持运行；Ctrl+C 停止
.venv/bin/python -m zhidu monitor
```

原文损坏：从可信备份按 SHA-256 恢复文件，再执行 doctor；不要按系统猜测生成替代原文。数据库/写锁暂时不可用：常驻调度器记录错误类型，30 秒后重试；不输出数据库连接串或凭据。

## 可观测性

| 接口 | 含义 |
|---|---|
| `/health/live` | API 进程可响应，不依赖数据库 |
| `/health/ready` | 数据库可访问且第六周必需表/列可读、配置合法、原文目录可访问 |
| `/metrics` | Prometheus 格式：事件数、富化覆盖、来源失败/新鲜度、每路由 HTTP 时延直方图 |
| `/api/v1/operations/status` | 轻量实时运行检查，不逐个读取原文 |
| `/api/v1/operations/evaluations` | 持久化历史评测快照 |
| `/api/v1/operations/recovery-actions` | 崩溃重启与 doctor 修复审计 |
| `/api/v1/enrichment/evaluations` | 固定富化回归断言结果 |

HTTP 指标按路由模板聚合，进程重启后计数清零；日志不包含问题正文、令牌、查询串或数据库密码。真实发布时间至首次观察的指标排除 replay 和非漏洞日期语义，仍包含回填，应单独制定在线监测时间窗。

## 容器部署

沿用项目名 `zhidu-week1` 以保留原有卷命名。修改 `.env` 中的 PostgreSQL 密码后运行：

```bash
docker compose --profile monitoring up --build -d
docker compose ps
docker compose logs --tail 50 api collector
```

如 Docker Hub 不可达，可在 `.env` 设置 `ZHIDU_PYTHON_BASE=public.ecr.aws/docker/library/python:3.12-slim`。这是 [Docker 官方文档介绍的 ECR 分发方式](https://www.docker.com/blog/news-from-aws-reinvent-docker-official-images-on-amazon-ecr-public/)。镜像构建时仍需访问依赖仓库。

API/collector 使用非 root、只读根目录和临时 tmpfs，写入原文只落在 app-data 卷。日志每文件 10 MiB、保留 3 份。重启策略处理退出，来源失败由退避和续传处理。不要通过 `down -v` 清理有业务数据的卷。

`config/prometheus.yml` 和 `config/prometheus-alerts.yml` 可挂载到同一 Compose 网络中的 Prometheus。没有部署外部通知服务时，不能宣称已实现邮件/消息告警。

## 复现验收

```bash
# 独立项目，测试口令仅限本机隔离验收；不复用业务库或业务卷
POSTGRES_PASSWORD=week6-isolated-test ZHIDU_API_PORT=18000 ZHIDU_DB_PORT=15432 \
  ZHIDU_PYTHON_BASE=public.ecr.aws/docker/library/python:3.12-slim \
  docker compose -p zhidu-week6-check up --build -d db api
.venv/bin/python scripts/verify_week6_container.py
```

脚本只允许固定 `zhidu-week6-check` 容器，导入虚构样本后会终止测试 API 服务进程来验证自动恢复。`scripts/verify_week6_postgres.py` 只接受 `zhidu_acceptance_*` 数据库名；数据库 URL 和独立原文目录通过环境变量传入。测试库和真实 SQLite 不共享原文写路径。

## 金标集准备

```bash
.venv/bin/python scripts/export_enrichment_annotations.py \
  --per-source 30 --output docs/member-a-week6-annotation-pack.json
```

候选包包含原文、不可变 revision/哈希和空白标注栏，不输出模型预测。按 CVE 分组的切分只是初始建议：标注者应核对同义标识，冻结测试集并独立双人复核。当前 127 个候选仍为 unlabeled；现有 8 例固定回归集不能替代它们。
