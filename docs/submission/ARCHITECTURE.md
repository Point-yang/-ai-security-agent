# 架构与模块

本提交以 `langgraph-source-team-v12`、`durable-agent-roles-v6`、`source-answer-v10` 的当前实现为基础。保留固定工作流作为默认策略，多角色策略须在界面选择。

| 层次 | 技术与实现 | 职责 |
|---|---|---|
| 网页 | 原生 HTML/CSS/JavaScript，FastAPI 静态服务 | 指挥中心、证据、比较、资产、会话、评测六个入口 |
| API 与存储 | FastAPI、SQLAlchemy、Alembic、SQLite/PostgreSQL | 情报和修订、原文索引、会话、资产、运行及评测记录 |
| 数据采集 | HTTP 来源适配器、持久化调度、水位、退避和去重 | CVE/NVD、GitHub、厂商、论文与扩展目录；保存失败与缺口 |
| 结构化处理 | 领域规则与字段来源定位 | 组件、版本、CVSS、CPE、分类、跨来源差异和资产条件判断 |
| 检索 | 词项、FastEmbed 本地 ONNX、混合检索与重排 | 同一证据库支撑普通 RAG、固定工作流和 Agent 比较 |
| Agent | LangChain create_agent、LangGraph、langchain-deepseek/openai | 自主工具选择、状态分支、补查、生成、核验与持久恢复 |
| 审计与评测 | pytest、Node 测试、JSON 记录、统计脚本 | 来源复验、成本与调用预算、逐题评估和冻结对照 |

主要源码位于 `src/zhidu/`。`agent_team.py` 组织状态图；`agent_research.py` 承担工具循环；`agent_roles.py` 组织规划、生成和核验；`agent_tools.py` 和 `langchain_tools.py` 封装检索、字段读取、来源比较等领域工具。

流程为规划 → 研究准备 → 自主检索补证 → 形成结论 → 核验。状态图按缺口决定补查或改写，受模型次数、工具次数、累计输出量与截止时间约束。研究角色具有 LangChain 工具循环；其他角色是有明确输入输出契约的模型节点，不能描述为四个各自无限自主的 Agent。

正文证据使用来源版本、JSON 指针、原文区间和服务器生成的正文 ID。目录导航不作为证据；字节复验与问题完整性分开记录。逐任务读取计划减少重复读取，但最新版真实请求发生过规划超时，其效率改善尚未完成独立验收。

工具只读现有知识库，不执行 PoC、不提供 shell。资产版本比较基于来源条件，不能等同漏洞已复现或真实互联网资产已确认。论文和扩展目录的元数据也不等同全文理解。

本地 SQLite 快照适合演示；Docker Compose 使用独立 PostgreSQL。模型凭据仅从部署环境读取，提交包不内置管理员密钥或供应商密钥。模型权重文件及其清单随包提供，来源许可见 [第三方说明](THIRD_PARTY.md)。
