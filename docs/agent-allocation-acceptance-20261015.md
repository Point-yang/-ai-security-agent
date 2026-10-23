# 按任务分配读取的工程验收

日期：2026-10-15。`langgraph-source-team-v12` / `durable-agent-roles-v6` 已部署到本机 8010。1018 项 Python 测试、50 项前端测试、Ruff 和 JavaScript 语法检查通过。默认后端仍为 workflow，团队模式保持实验状态。

工程改进已完成。本轮真实评测在首个规划请求超时，尚未进入新研究逻辑，因此没有可用于确认准确率或 Agent 增益的新答案。

## 本轮改动

新增 `read_plan`：模型通过 `task_reads` 为每个计划任务选择已有证据 ID 或要读取的结构 ID。服务器检查任务对应及 ID 来源，将同一事件、同一字段的选择合并为正常 `read_fields` 调用，每个调用最多四个结构、每个研究决定最多三个子调用。缺项、重复或未知 ID 返回明确反馈，该计划不部分执行，也不补造选择。

阅读意图不代表语义覆盖。Composer 会收到各任务实际返回的证据 ID，以及模型建议复用的既有 ID；最终结论仍须阅读原文、逐句引用并经原有核验流程检查。

新增纯调度模块，依据冻结输入和已保存工具回执处理模型已经选择的请求：

- 优先照顾尚未实际取到正文的不同任务；跨研究轮次保留该观测记录，但不把它标记为 covered。
- 仅根据实际返回的字段目录，过滤当前本地索引已知不能提供的字段；不推断原来源没有相关事实。
- 仅当已实际获得同一结构 ID 的对应页面与结构证明时，省略重复读取；未知 ID、非法参数和跨范围请求继续走原工具拒绝及计数路径。
- 对同一任务映射、同一来源修订中包含关系的选择，优先模型已选的完整小结构，并明确记录外层暂缓。不同任务或不同/未知来源绑定的结构不互相替代。
- 保持原子调用 ID 和精确的结构—任务映射。被跳过的请求不算已执行；未读的范围也不算已覆盖。

每次实际 `read_fields` 返回的 `available_fields` 纳入输出预算，只有真正发给模型的字段表才保存到 `field_catalog`。目录、字段表及调度进展均与原文证据、新增字符和语义覆盖分开记录。页面也区分预算未准入、调度省略和阅读计划关系校验失败。

实现：[阅读计划编译](../src/zhidu/research_plan.py)、[确定性调度](../src/zhidu/research_allocation.py)、[框架接线](../src/zhidu/agent_research.py)、[工具与字段目录](../src/zhidu/langchain_tools.py)。

## 回归及交叉检查

离线测试使用实际 LangChain Agent/ToolNode 循环及脚本化模型响应，验证目录返回后逐任务选择、合并读取、反馈时零读取、缓存恢复、真实字符预算、私有资产隔离及逐句来源绑定。它们不是云模型实测或准确率。

交叉检查发现并修复了两处边界：跨轮调度曾漏接已保存的任务观测；不同修订的内外层结构曾可能因坐标相似而互相替代。现在目录带有共同 canonical field 身份的 `source_binding`，跨 ID 包含去重要求绑定相同；旧目录没有绑定时保守保留请求。原 context ID 计算及旧引文复验兼容未改变。

冻结语料上的零模型固定工具诊断也通过：core 与 ONNX 各用总计四次工具调用（含冻结初始检索）读取指定关键段落，输出分别为 17073/18000、14702/18000 字符，来源复验为 7/7、9/9。这只是已知源定点读取能力，不是自主 Agent 选择成功。

记录：[Python 回归](../output/agent-allocation-development-20261015/tests.xml)、[前端回归](../output/agent-allocation-development-20261015/node-tests.txt)、[工程审计](../output/agent-allocation-development-20261015/engineering-audit.json)、[固定工具诊断](../output/agent-allocation-development-20261015/fixed-tool-diagnostic.json)、[诊断脚本](../output/agent-allocation-development-20261015/fixed-tool-diagnostic.py)。

## 本轮真实请求的状态

先冻结代码、原问题、原语料、初始检索包、模型及费率快照，再创建新实验身份。限制保持每题 8 次模型请求、6 次工具调用、60 秒软截止、每次 2400 输出 token、工具总输出 18000 字符；首个失败或未知结果即停止。

| 检查项 | 实际结果 |
|---|---|
| 新模型请求尝试 | 1 次：core 的 `planner:0` |
| 返回状态 | uncertain，`OpenAITimeoutError` |
| core 本轮耗时 | 约 60.57 秒 |
| 本轮新增业务工具调用 | 0；仅恢复原初始检索包 |
| 生成结论 | 无，不做语义评分 |
| ONNX | 按停止规则未启动 |
| token、总费用 | 未知，不能按零处理 |
| 自动重试、额外评审 API | 均为 0 |

客户端记录了规划请求超时，原因尚不能进一步确定。该失败发生在新调度逻辑执行之前，不能据此判断新调度的真实效果。未知请求与上轮 ONNX 核验网络失败分别保存，没有改写成成功，也没有重发旧请求。

见 [冻结协议](../output/agent-allocation-development-20261015/protocol.json)、[停止记录](../output/agent-allocation-development-20261015/stopped.json)、[运行汇总](../output/agent-allocation-development-20261015/summary.json)、[请求与成本审计](../output/agent-allocation-development-20261015/execution-audit.json)、[不可评分状态说明](../output/agent-allocation-development-20261015/development-quote-review.json)。

## 部署与未完成项

本机 `/workspace` 和当前脚本均返回 200、UTF-8，资产信息不足的团队模式请求正常返回 clarification，部署检查新增模型调用为零。见 [部署记录](../output/agent-allocation-development-20261015/deployment-audit.json)。

真实题目的答案完整性，以及相对普通 RAG 的准确率、耗时或成本增益仍待验证。需在模型请求能够完成的条件下，以新的实验身份继续冻结验证，保留本轮超时和旧评分；不能用离线工具检查代替完整 Agent 实测。
