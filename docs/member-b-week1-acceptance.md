# 成员 B 第一周交付与验收

完成日期：2026-09-18。范围依据仓库 `member-b-handoff.md` 的五项可开展工作；仓库未提供另一份独立的成员 B 周计划。本次交付为基础检索和研究工作台，不代表 RAG、多智能体或整个系统完成。

## 交付清单

| 接口交接任务 | 实际交付 | 状态 |
|---|---|---|
| 情报列表 | `/workspace`：标题/GHSA、CVE 别名、组件、严重程度、分页及撤回标识 | 完成 |
| 第一版检索输入 | 当前版本分片、关键词检索、匹配词与引用元数据、输入 JSON 导出 | 完成 |
| 引用侧栏 | 字段证据、JSON Pointer、原文哈希与链接、指定版本引用导出 | 完成 |
| 版本对比 | 两版归一化字段差异，区分 current / superseded / stale / conflict | 完成 |
| 虚构样本联调 | 独立 demo.db，v1/v2 差异、replay 标识、资料范围隔离 | 完成 |

使用原生 HTML/CSS/JavaScript 和已有 FastAPI 服务，无前端构建要求，无新增运行依赖，无数据库结构变更。原成员 A 工作台 `/` 保留，并增加 B 工作台入口。

## 本机启动

已有 `.venv` 和真实数据时直接执行：

```bash
.venv/bin/python -m zhidu serve --port 8002
```

打开 http://127.0.0.1:8002/workspace 。若服务关闭，重新运行上面的命令。默认 `serve` 仍使用 8000，本次采用 8002 避免干扰旧服务。

独立离线演示（只在同一终端中设置演示库）：

```bash
export ZHIDU_DATABASE_URL=sqlite:///./data/demo.db
.venv/bin/python -m zhidu init-db
.venv/bin/python -m zhidu import-json examples/ghsa-demo-v1.json
.venv/bin/python -m zhidu import-json examples/ghsa-demo-v2.json
.venv/bin/python -m zhidu serve --port 8003
```

打开 http://127.0.0.1:8003/workspace 。结束服务后运行 `unset ZHIDU_DATABASE_URL`。重复导入已有样本会被幂等识别，不会新增重复事件。

## 验证结果

- `pytest -q`：29 项通过；保留 2 个原有 Starlette/httpx、anyio 上游弃用警告。
- `ruff check .`、`ruff format --check .` 和 `node --check src/zhidu/static/workspace.js`：通过。
- 已重新导出 `docs/openapi.json`，包含两项新增检索接口及类型契约。
- 真实库只读核对：69 条事件，其中 3 条已撤回；69 条当前版本原文均为 live。570 个检索片段的事件/版本/原文关联、JSON Pointer、字符偏移和内容哈希全部一致。69 条公告保存在同一个原始批次 JSON 中，因此核对的独立原文文档数为 1。
- `decompression` 查询返回 3 个片段，确认连字符词可以按组成词检索；这仅是功能示例，不是召回率评估。

机器可读核对结果保存在 `member-b-week1-live-check.json`。可复核：

```bash
.venv/bin/pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
node --check src/zhidu/static/workspace.js
.venv/bin/python -m zhidu export-openapi
.venv/bin/python scripts/verify_member_b.py
```

脚本读取当前配置的数据库，不联网采集、不修改情报或原文。需要另存核对报告时加 `--output <文件路径>`。

新增测试覆盖长描述分片与批次 JSON Pointer、当前版本替换、旧引用可追溯、stale/conflict 排除、live/replay 过滤、撤回筛选、CVE 和组件标识、中文双字检索、连字符词、分页、空结果和参数校验。

## 浏览器验收

已用本机浏览器验证：

1. 真实库显示 69 条情报总数，默认列表排除 3 条撤回记录后显示 66 条；详情和引用侧栏可读。
2. `decompression` 检索能够命中描述中的 `decompression-bomb`，点击结果打开其对应版本。
3. 独立演示库中 v1 → v2 展示描述、`packages.0.fixed_version`（null → 1.2.0）、references 和来源更新时间的变化。
4. 引用版本切换为 v1 后显示 superseded、replay 和非当前事实提示，原文 ID / 哈希随版本切换。
5. 演示库在 live 检索范围下返回 0，切换 replay 后命中 example-ai-demo 的 v2 组件片段。
6. 实际下载并解析检索结果、真实引用、历史演示引用与当前检索输入四类 JSON，确认历史引用保留 v1，而当前输入为 v2。
7. 桌面三栏布局已目视检查，浏览器控制台未见 JavaScript 错误。窄屏样式已实现，但未作移动设备实测。

## 当前边界

无持久向量库、LLM 调用、生成式回答、问答服务端审计、多智能体编排或资产受影响判断。当前检索按请求扫描并排序，适用于小规模本地数据；不承诺生产负载、跨语言检索、语义召回或准确率指标。原文及描述以文本节点展示，外部公告中的 HTML/Markdown 不执行。

第二周可在现有分片/引用契约上接入索引增量更新与回答存证，再加入模型和评测集。应保持 current 版本筛选和独立演示库隔离，不将检索得分或来源声明包装成独立验证结果。
