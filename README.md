# 知盾 · 智能体驱动的 AI 安全知识情报系统

GitHub 源码版 · 实现与评测基准 2026-10-18

知盾将公开安全公告、漏洞库、论文与扩展目录汇入可追溯的知识库，提供来源监测、结构化富化、跨来源比较、资产条件判断，以及带逐字证据引用的 Agent 问答。

本仓库包含源码、配置模板、数据库迁移、虚构示例、测试及评测文档。不附运行数据库、采集原文、模型文件、私人会话、真实资产、比赛视频或历史归档；`data/`、`output/`、`release/`、`archives/` 和本地 `.env` 均不进入版本管理。

发布前检查方式与凭证处理范围见 [仓库安全说明](docs/repository-security.md)。

历史比赛运行包的目录与演示说明见 [交付说明](docs/submission/DELIVERY.md)、[演示路径](docs/submission/DEMO.md) 和 [初赛材料清单](docs/submission/INITIAL_REQUIREMENTS.md)。这些文档涉及的快照、模型及比赛材料需单独准备，克隆本仓库后不会自动获得。

## 快速启动

使用 Python 3.12，在克隆后的项目根目录执行。以下最小启动无需模型 API 密钥，也不下载语义模型：

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install --no-deps -e .
cp .env.example .env
.venv/bin/python -m zhidu init-db
.venv/bin/python -m zhidu import-json examples/ghsa-demo-v1.json
.venv/bin/python -m zhidu import-json examples/ghsa-demo-v2.json
.venv/bin/python -m zhidu enrich
.venv/bin/python -m zhidu index-sync
.venv/bin/python -m zhidu serve --host 127.0.0.1 --port 8010
```

已有 `.env` 时保留它，不重复执行复制。Windows 对应使用 `.venv\Scripts\python.exe`。首次安装 Python 依赖需要网络。示例中的 `CVE-2099-0001` 是虚构漏洞，两次导入用于展示公告版本变化。

浏览器打开 [研究工作台](http://127.0.0.1:8010/workspace)，不要直接打开 HTML 文件。另有 [采集工作台](http://127.0.0.1:8010/)、[资产研判](http://127.0.0.1:8010/assets) 和 [API 文档](http://127.0.0.1:8010/docs)。

首次启动会在本地创建 `data/`。此时可浏览示例、版本及词法检索；语义检索需要额外准备本地模型，云端生成需要自行配置供应商。管理员密钥留空时 HTTP 写接口禁用，CLI 导入仍可使用。

## 使用模型与多角色 Agent

需要语义检索或多角色 Agent 时，先安装对应依赖：

```sh
.venv/bin/python -m pip install -r requirements-semantic.lock -r requirements-agent.lock
# 显式联网下载本地 embedding 模型，并生成模型清单
.venv/bin/python scripts/prepare_week6_model.py
.venv/bin/python -m zhidu.rag_cli semantic-sync --output data/semantic-sync.json
```

新模型问答需在本地 `.env` 填写自己的配置。仓库中的 `.env.example` 仅提供空白模板：

```dotenv
ZHIDU_ADMIN_KEY=填写自行生成的管理员访问密钥
ZHIDU_LLM_PROVIDER=deepseek
ZHIDU_DEEPSEEK_API_KEY=填写自己的供应商密钥
```

重启服务后，在工作台授权区填写 **管理员访问密钥**。选择“多角色规划、补查与引用核验（实验）”启用 `team`；默认 `workflow` 为固定工作流。模型供应商密钥只保存在服务端本地配置中，不应写入源码、文档或示例。云端生成会发送问题和检索到的公开证据片段，可能产生供应商费用。

技术栈为 FastAPI、SQLAlchemy、SQLite/PostgreSQL、FastEmbed、LangChain `create_agent`、LangGraph 和 DeepSeek/标准兼容模型接口。规划、研究、生成、核验通过状态图协作；研究角色包含真实工具循环，其余角色是受限模型节点。详见 [架构及边界](docs/submission/ARCHITECTURE.md)。

## 采集、检索与数据维护

```sh
# 持续采集，并在每轮后同步已有本地模型的向量
.venv/bin/python -m zhidu monitor --sync-semantic
# 单轮采集
.venv/bin/python -m zhidu monitor --once
# 显式重建派生状态
.venv/bin/python -m zhidu enrich
.venv/bin/python -m zhidu index-sync
.venv/bin/python -m zhidu.rag_cli semantic-sync --output data/semantic-sync.json
```

采集目标在 `config/sources.json`。启动监测需要外网；GitHub Token 可选。不要同时启动多个相同数据库的采集器。在项目根目录运行命令，使配置和模型清单的相对路径保持有效。

## 验证与部署

```sh
# 完整回归测试需要语义和 Agent 依赖
.venv/bin/python -m pip install -r requirements-semantic.lock -r requirements-agent.lock
.venv/bin/pytest -q
node --test tests/*.test.mjs
.venv/bin/ruff check src tests scripts
```

前端测试需要 Node.js 22。2026-10-23 在不含本地 `.env`、数据库、模型及历史输出的源码导出目录中验证：1019项Python通过、4项历史快照测试跳过、56项前端测试通过，Ruff检查和格式检查通过。4个跳过项需要另行准备旧实验数据库。工程测试通过数不能作为问答准确率。

自动检查配置保留为 [CI 模板](docs/ci/verify.yml)，本次发布尚未启用 GitHub Actions。需要启用时，可在 GitHub 网页中将模板内容保存到 `.github/workflows/verify.yml`。

`scripts/verify_submission.py` 专用于包含 `data/SNAPSHOT.json`、数据快照和模型的独立导出运行包，不能直接用于只有源码的克隆目录。

Docker Compose 使用独立 PostgreSQL 和数据卷。设置本地 `.env` 中的 `POSTGRES_PASSWORD` 后执行 `docker compose up --build -d`；`docker compose --profile monitoring up -d` 启用采集容器。首次启动使用空数据库，不导入历史演示快照。

## 评测口径

2026-10-09 冻结 test 富化回归为24条、99项来源事实，精确率和召回率均100%；该成绩不能等同总体问答准确率。最近完整6题复杂对照中，普通 RAG 严格通过0/6、固定工作流2/6、团队0/6；团队必答事实召回43.48%，尚不能宣称 Agent 已证明整体增益。最新版仍有规划超时和复杂问题漏答记录。

完整方法、对应版本和局限见 [评测与已知问题](docs/submission/EVALUATION.md)。页面通过只读 `/api/v1/release/evidence` 展示配置中的冻结评测摘要，区分AI审核方法、富化回归和复杂问答；摘要引用的导出包 `evidence/` 原始产物不随本源码仓库提供。本次整理没有新增付费模型效果评测。
