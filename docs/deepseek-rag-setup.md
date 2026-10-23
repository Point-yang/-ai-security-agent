# DeepSeek 知识库回答：配置与验证

2026-09-28 上下文更新：默认先补入同版本的标题、版本/补丁字段、修复候选段落与参考链接，最多 24 条引用、18,000 字符。模型提示更新为 `deepseek-grounded-context-v2`，引用编号校验上限从 10 扩至 24。历史联调数字仍保留；详见 [A 上下文验收](member-a-rag-context-acceptance.md)。

2026-09-27。新链路：问题 → 本地词项/embedding 检索 → 原文哈希与引用复验 → DeepSeek 中文生成 → 引用编号和逐字摘录检查 → 显示并保存审计。没有结果、原文损坏、缺失必要资产上下文或前置预算失败时，不调用大模型。

## 在 PyCharm 中使用

1. 打开项目根目录 `.env`，填写：

```dotenv
ZHIDU_LLM_PROVIDER=deepseek
ZHIDU_DEEPSEEK_API_KEY=在此填入你的真实DeepSeek密钥
ZHIDU_DEEPSEEK_MODEL=deepseek-v4-flash
```

本轮已准备以上配置项，Key 留空等待本机填写。不要把 API Key 填到网页、截图、提交到仓库或发进聊天。项目已有 `ZHIDU_ADMIN_KEY` 无需替换。

2. 停止并重新启动 PyCharm 中的服务；工作目录必须为项目根目录，解释器选择项目 `.venv`。终端等价命令：

```bash
.venv/bin/python -m zhidu serve --host 127.0.0.1 --port 8010
```

3. 打开 `http://127.0.0.1:8010/workspace`，使用顶部“知识库问答”。选择“Embedding 混合检索与重排”与“按服务配置生成回答”，输入问题及**本项目管理员密钥**，点击生成。DeepSeek API Key 与网页管理员密钥用途不同。

可先用问题“vLLM 音频解压导致内存耗尽的漏洞是什么？”，检索词填 `vllm audio decompression bomb`。只有顶部这个 RAG 表单新增了生成能力；下方旧会话/抽取式接口保持原行为。

## 模型名称

配置保留用户指定的 `deepseek-v4-flash`。截至本轮查阅，[官方更新说明](https://api-docs.deepseek.com/updates/)称它是兼容名称，实际请求已路由到 V4.1 Flash，推荐名称为 `deepseek-flash`。因此不能宣称锁定了旧 V4 权重；请求名称和响应模型名都记录在审计中。若官方未来移除旧别名，可修改 `ZHIDU_DEEPSEEK_MODEL=deepseek-flash` 并重启。

使用官方 `https://api.deepseek.com/chat/completions`（亦接受 `/v1` 基址），通过现有 HTTPX 依赖调用，无需另装 SDK。为避免密钥被误发，本实现只接受官方 HTTPS 主机，不跟随重定向、不读取代理环境变量、不自动重试。本次关闭 thinking，使用 [JSON Output](https://api-docs.deepseek.com/guides/json_mode/)；参数依据 [Thinking Mode](https://api-docs.deepseek.com/guides/thinking_mode/)。

## 故障和配置状态

`GET /api/v1/rag/status` 新增 `generation`：显示配置是否存在，不返回密钥，也不将“已配置”当作“已经实测连通”。

| 状态 | 含义与处理 |
|---|---|
| missing_api_key | `.env` Key 为空；填写后重启 |
| authentication_failed | 官方 API 返回 401，检查密钥有效性 |
| insufficient_balance | 官方 API 返回 402，检查账户余额 |
| rate_limited | 429 限流，本次降级；稍后再试 |
| timeout / network_error | 超时或无法连接，检查网络；保留本地回答 |
| invalid_citation / invalid_response | 引用不属于本次来源、摘录不匹配或 JSON 无效，不采用该生成结果 |
| skipped | 本地证据或上下文不足，本次没有外部请求 |
| completed | API 返回完整答案且引用结构检查通过；不等于答案语义已独立验证 |

可选参数：`ZHIDU_DEEPSEEK_TIMEOUT_SECONDS=30`、`ZHIDU_DEEPSEEK_MAX_TOKENS=1800`。本轮每个答案至多一次外部请求，证据文本最多 20,000 字符、单片段最多 4,000 字符。检索工具预算和生成 HTTP 超时分别设置；UI 总耗时包含两阶段。没有流式输出，不统计首字延迟。

独立真实调用检查（会把这一问题和相关公开来源片段发给 DeepSeek，消耗 API 额度）：

```bash
.venv/bin/python scripts/check_deepseek.py
```

退出码 0 表示真实生成及引用检查成功；1 表示未配置、拒答或降级。脚本不写入正式问答记录。缺少本地模型时可加 `--mode lexical` 验证接口，但这不是混合检索验收。

## 接口与审计

`POST /api/v1/rag/answers` 新增 `generation` 字段：`configured` 使用服务配置、`extractive` 强制本地摘录、`deepseek` 显式生成。原有管理员验证不变。

响应新增 `generation`（状态、原因、请求/响应模型、token、提示版本、输入摘要、耗时）、`generated_claims`（中文结论和对应引用/摘录）、`extractive_answer`（成功生成时保留原证据回答）。原 `claims` 仍是来源摘录；不能拿它计算新模型概括的正确率。`api_usd` 在发生外部请求后为 null，不虚构为零；token 取自官方 usage，不在代码里硬编码价格。上游错误正文、密钥和模型隐藏思考内容不保存。

只发送本次问题、选中且本地校验通过的来源片段和回答约束；不发送全部数据库、完整 SBOM、资产名称、历史会话、原文文件或 `.env`。来源文本属于不可信资料，系统提示要求不遵循其中指令；模型不能执行工具。前端按文本显示结果。

## 当前边界

- 这是“大模型生成 + 现有受限工具工作流”，尚未让模型自主规划或选择工具，也没有新增多 Agent 协作。
- 检查引用编号和连续原文摘录，只能证明引用真实存在，不能证明中文概括一定由引文推出。页面显式提示需要核查，准确率需另行独立评测。
- 既有 20 题抽取式 benchmark 强制 `generation=extractive`，不会因 `.env` 配置消耗额度或把旧准确率冠给新模型；评测器拒绝直接将生成答案按旧摘录指标评分。
- 当前只使用选中的检索片段，不保证整篇文档或所有关联漏洞都被模型读取；没有资料的版本/修复建议不得靠模型常识编造。
- 旧八周离线备份仍代表原历史版本；恢复启动显式关闭云端生成并清空 DeepSeek Key。要备份本次新增代码，需另建新包。
- 真实连通性需要本地有效 Key；模拟测试通过不能代替官方 API 实测。

## 本轮验证记录

- 全量 **168 项测试通过**，含新增 16 项 DeepSeek 模拟集成测试；结果见 [JUnit](deepseek-integration-test-results.xml)。恢复测试另验证不继承云端密钥。
- Ruff、80 个 Python 文件格式检查、前端 JS 语法和 Alembic 检查通过；OpenAPI 已更新。
- 本机 8010 新服务已启动；浏览器确认新回答选择器及“DeepSeek Key 尚未配置”提示正常，检查时无控制台错误。
- 本轮 `.env` 的 Key 为空，真实检查脚本返回 `missing_api_key`，没有调用官方模型、没有消耗模型额度。填入 Key 并重启后还需执行真实问答联调。

## 2026-09-28 真实 API 联调补验

用户已在本机填写 Key。执行 `scripts/check_deepseek.py`，本地混合检索及原文检查后向官方 API 发起一次真实请求，返回 `generation.status=completed`、`citation_checks_passed=true`。请求模型 `deepseek-v4-flash`，实际响应模型 `deepseek-flash`。

测试问题为“vLLM 音频解压导致内存耗尽的漏洞是什么？”。发送的证据片段共 1319 字符；API 返回中文回答及来源编号。usage 为输入 996、输出 502、总计 1498 token；模型阶段 2350.998 ms，完整脚本问答阶段 4302.750 ms。金额未估算，且这只是单次连通性样本，不是 P95 或准确率评测；`semantic_support_verified=false`，不把引用匹配称为独立语义验证。

8010 服务已重新启动以加载新配置。密钥、请求 Authorization 和上游隐藏思考没有写入本记录。此前“Key 为空”是上一轮测试状态，现已完成真实联调。
