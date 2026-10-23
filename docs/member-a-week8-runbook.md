# 第八周现场启动、备份恢复与故障预案

2026-09-26。面向演示机上的本地 SQLite 主部署。备份、模型、用户问答和审核材料属于本地交付数据，不上传到代码仓库。

## 现场优先顺序

1. 使用已验证的环境与快照，不在答辩前临时升级依赖或更换模型。
2. 首先展示现有来源与证据，再展示检索和资产；需要联网采集时单独展示有限任务，不阻塞主流程。
3. 现场故障时切到恢复副本；不要覆盖主数据库或清空原文。
4. 展示固定回归时明确开发集和人工金标边界，不将模型摘要、来源一致性或快照哈希称为事实正确率。

## SQLite 完整备份

在项目根目录执行，output 必须是一个尚不存在的目录：

```bash
.venv/bin/python -m zhidu.backup create \
  --output data/backups/competition-bundle --include-model
.venv/bin/python -m zhidu.backup verify data/backups/competition-bundle
```

包含在线一致性数据库快照、快照引用的全部原文、选定源码/配置/迁移/文档/示例、实际使用的非敏感路由配置、人工审核 JSON，以及当前模型清单中的文件。不会复制 `.env`、Git 凭据或整个虚拟环境。只有最后写入完整 manifest 且校验通过的包可以恢复；中断形成的目录不要继续复用，换新名称重新创建。

备份 manifest 记录每个文件的大小和 SHA-256。SQLite 使用 [Online Backup API](https://sqlite.org/backup.html)获得一致性快照，再依据快照引用复制原文。校验用于检测缺失与损坏，不是带身份认证的数字签名；不要执行来路不明的备份源码。

## 恢复到隔离目录

```bash
.venv/bin/python -m zhidu.backup restore data/backups/competition-bundle \
  --destination data/restores/competition-demo
.venv/bin/python scripts/serve_restored.py data/restores/competition-demo --port 8020
```

恢复只允许新目录，拒绝覆盖已存在目录。模型清单中的路径会改为恢复目录的绝对路径，模型文件摘要不变。服务使用恢复包里的源码、数据库、原文、路由和模型；默认 HTTP 写入关闭，不启动采集器，也不继承原管理员密钥。

浏览 `http://127.0.0.1:8020/workspace`；只读混合检索可用 `/api/v1/rag/search?q=vllm%20audio%20decompression%20bomb&mode=hybrid`。

如果要在恢复副本演示“生成证据回答”，在启动它的终端设置独立的 `ZHIDU_DEMO_ADMIN_KEY`，再运行：

```bash
.venv/bin/python scripts/serve_restored.py data/restores/competition-demo \
  --port 8020 --enable-local-answers
```

在网页“本次管理员密钥”输入该演示口令。口令只通过进程环境传递，不写回备份包或生产 `.env`。默认只读模式不需要演示口令。

## 离线演示的环境前提

包不包含 Python 解释器、venv 或跨平台 wheel。当前主机已安装依赖时可以离线运行；换机器必须提前准备兼容 Python、核心依赖、可选语义依赖，并完成一次实际启动。模型文件已包含不等于新机器无需安装 FastEmbed/ONNX。GPU 不是当前 MiniLM CPU 基线的必需项。

模型目录和 SQLite 是不同资产：若忘记 `--include-model`，恢复后关键词检索仍可运行，但不能把语义检索报错当成数据库损坏。

## 故障处理表

| 现象 | 先检查 | 处理与演示替代 |
|---|---|---|
| 页面打不开 | PyCharm/终端进程、端口、`/health/live` | 只启动一个目标端口；现有端口被占用时选择 8020 等备用端口 |
| `.env` 已修改仍提示写入关闭 | `/health` 的 `http_writes_enabled` | 配置在启动时加载；停止旧进程后重启，在页面填相同密钥 |
| 401 | 页面密钥与当前服务配置 | 使用对应服务的密钥；每次提交后页面会清空密钥 |
| 数据库不可用/迁移不一致 | `/health/ready`、`alembic current` | 先备份；对新部署执行 `init-db`。不要无备份降级主库 |
| 模型不可用 | `/api/v1/rag/status`、模型清单路径 | 恢复含模型的包；环境未准备时使用词项模式并说明限制 |
| 向量未覆盖当前版本 | 当前片段数与有效向量数 | 使用本地已准备模型运行 `semantic-sync`；不要返回旧版本向量 |
| 原文缺失/哈希错误 | `evidence-audit`、`catalog-audit` | 不修改哈希跳过检查；切到完整恢复副本，失败保留为待补证 |
| 外网断开/限流 | 原始来源错误、调度状态 | 继续演示本地证据与离线检索；来源失败和待补证如实显示 |
| 采集停了或来源超期 | worker 心跳与来源最近成功时间 | 显式重启 monitor；新鲜度覆盖不等于发布后 ≤6h 的 SLA |
| 答案片段不相关 | 原始查询、引用、模式与规则 | 保留失败案例和查询快照；不临时改期望答案或删题 |

## PostgreSQL 备份说明

当前 `zhidu.backup` 只处理 SQLite。PostgreSQL 应使用版本兼容的 `pg_dump`/`pg_restore`，而不是复制正在运行的数据库目录：

```bash
docker compose exec -T db pg_dump -U zhidu -d zhidu -Fc > data/backups/zhidu.dump
docker compose exec -T api tar -C /app/data -cf - raw > data/backups/raw.tar
```

先完成数据库快照，再打包不可变原文。恢复到专门的新数据库和新原文目录；不要使用指向生产库的 `--clean`。例如已创建新库后：

```bash
pg_restore --exit-on-error --no-owner --dbname=zhidu_restore_test data/backups/zhidu.dump
```

命令依据 [PostgreSQL pg_dump](https://www.postgresql.org/docs/current/app-pgdump.html) 和 [pg_restore](https://www.postgresql.org/docs/current/app-pgrestore.html)。本周自动化完整包围绕真实使用的 SQLite；PostgreSQL 的这些手工命令不冒充本周新增的完整恢复实测。

## 验收清单

- 备份 verify passed，恢复目录与主目录不同。
- 新副本的原文字段引用和元数据字节定位可复验。
- 已准备本地模型时，实际混合检索成功；仅 status ready 不足以证明推理成功。
- 备份没有生产 `.env`，恢复服务默认不继承写入权限。
- 记录本次快照时间、数据规模、代码摘要、模型摘要及环境条件。
- 人工金标、来源覆盖、连续监测等未达标项目继续列为交付限制。
