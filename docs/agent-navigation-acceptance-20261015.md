# 定点导航与缺口分类验收

日期：2026-10-15。最终实现 `langgraph-source-team-v11` / `durable-agent-roles-v5` 已部署到本机 8010。916 项 Python 测试、49 项前端测试、Ruff 和 JavaScript 语法检查通过。默认仍为 workflow，团队模式保持实验状态。此次完成导航能力和缺口分类改进；整题质量验收尚未通过，不更新独立评分。

## 实现与证据边界

`read_fields(context="outline")` 消耗一次正常工具调用，返回最多 12 项原文目录；只含标题或列表引导语、来源范围及服务器生成的结构 ID，不提供正文证据。目录计入每次及全局字符预算，预算省略的 ID 不授予后续读取权限。只保存真正返回的导航项，恢复时复用原回执，不现场补读、不新增原文覆盖。

模型可使用 `context="section", context_ids=[...]` 一次读取同字段最多四个结构。ID 绑定事件、原始文件、修订、字段和结构范围；跨事件、跨字段、过期或伪造 ID 拒绝。每个片段仍最多 1200 字符，分别保留续页位置，显式报告未返回和待续读的 ID。新出处协议为 `source-context-span-v2`，旧两种引文协议保持复验兼容。

核验账本分别记录 AI 原始语义意见和正文、来源、结构、未获支持等阻断原因。只有结构证明不足时，页面显示“正文已覆盖，结构引用待核”，正文缺口为“完整结构引用待补核”。已经存在的正文漏项不会被结构问题覆盖，已有候选的 missing_facts 和 partial 不被自动清空。

首次工程冻结后，交叉复核发现“显式正文缺口与结构缺口并存时，前者可能被隐藏”的组合漏洞。该候选在任何模型请求前停止，记录保留在 [预检停止记录](../output/agent-navigation-development-20261015/stopped.json)。修复后新增混合缺口和重复规范化回归，再创建独立 v2 实验身份；没有改写先前冻结目录。

主要实现：[原文导航及出处](../src/zhidu/source_spans.py)、[工具预算和恢复](../src/zhidu/langchain_tools.py)、[缺口分类](../src/zhidu/agent_requirements.py)、[研究角色](../src/zhidu/agent_research.py)。

## 真实开发运行

本轮继续使用已见的 Stage6 core / ONNX 题目，冻结原语料、初始检索包、模型、费率及金标。每题 8 次模型请求、6 次工具调用、60 秒软截止、每次 2400 输出 token、工具总输出 18000 字符的限制均未提高。遇到运行、格式或未知结果即停止，不重试已保存的请求。

| 项目 | langchain-core | ONNX |
|---|---:|---:|
| 生成状态 | completed，答案 partial | 核验请求 network_error，降级 |
| 模型请求尝试 | 7 | 5（其中 1 次结果不确定） |
| 工具调用，含冻结初始检索 | 6 | 6 |
| 耗时 | 32.87 秒 | 31.58 秒 |
| 工具输出字符 | 16830 / 18000 | 14653 / 18000 |
| 来源复验 | 6/6 | 9/9，仅来源片段 |
| 最终结论的逐字引文 | 8/8 | 无最终生成结论，不评分 |

合计 12 次模型请求尝试，其中 11 次完成、1 次核验请求用量未知。已知 token 合计 90513；未知调用不按零计费，总 token 和总费用均保持未知。按冻结费率快照核算的已知费用小计为 USD 0.014792964，不代表账户账单。没有追加评审 API，没有自动重试网络失败。

core 确实自主读取目录并使用返回的结构 ID，完整表达四项暴露条件，新增了凭据泄露或服务端请求的可能性及对象初始化条件，8 条最终结论均有自身引文支持。但 load()/loads() 的可信输入与窄 allowlist 建议仍未回答，故仍为 partial。

实际轨迹显示 Guidance 的 ID 已返回但未被选择；模型消耗一次工具读取本轮 NVD 记录未提供的 packages 字段，并在剩余预算中同时选择 Impact 及其重叠子列表，后者被字符预算省略。NVD 自己的 Prior to / fixed in 措辞已在正文陈述，额外要求其提供 GitHub 式分支字段仍偏严。当前瓶颈包括研究优先级和来源对照判断，不能仅靠增加提示语或可用工具证明已经解决。

ONNX 已自主读取完整 Impact 原文 `[2013,2484)`，其中包含此前遗漏的输出形状传播及潜在堆数据影响。但 `verify:0` 请求返回 `OpenAIConnectionError`，回执标记 uncertain，最终只有来源片段回退，没有通过核验的生成结论。不能把先前 composer 的候选或已读到的原文改记为整题成功。

审阅属于 AI 开发检查，不是人工审阅或新留出评分。见 [逐题复核](../output/agent-navigation-development-v2-20261015/development-quote-review.json)、[运行汇总](../output/agent-navigation-development-v2-20261015/summary.json)、[停止记录](../output/agent-navigation-development-v2-20261015/stopped.json)、[请求及成本审计](../output/agent-navigation-development-v2-20261015/execution-audit.json)。

## 零模型检查与下一步

在冻结数据库副本恢复原初始范围后，用已知目录项执行固定工具检查：两题均以总计 4 次工具调用完整读取指定关键段落，字符使用分别为 16131 和 14096，来源复验分别 7/7、9/9，新增 API 为 0。这证明有界工具读取能力，不是自主 Agent 成功；对应工具实现与最终 v2 冻结一致。

下一步应将必答项、目录选择和剩余预算关联起来：减少空字段请求和重叠段落读取，为尚未回答的主题保留预算，并继续纠正来源原生措辞的比较。网络失败保留独立记录，在新的实验身份和稳定环境下完成后续验证。通过新的冻结 RAG 对照前，不宣称准确率、效率或 Agent 实际增益已经提高。

记录：[冻结协议](../output/agent-navigation-development-v2-20261015/protocol.json)、[固定工具诊断](../output/agent-navigation-development-v2-20261015/navigation-diagnostic.json)、[复现脚本](../output/agent-navigation-development-v2-20261015/navigation-diagnostic.py)、[Python 测试](../output/agent-navigation-development-v2-20261015/tests.xml)、[前端测试](../output/agent-navigation-development-v2-20261015/node-tests.txt)、[工程审计](../output/agent-navigation-development-v2-20261015/engineering-audit.json)、[部署检查](../output/agent-navigation-development-v2-20261015/deployment-audit.json)。旧实验、金标及评分记录均保持原字节。
