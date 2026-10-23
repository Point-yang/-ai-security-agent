# B Agent 对照答案的双人审核说明

2026-09-29。此流程对应 [原始 12 题 × 3 模式](member-b-agent-comparison-full.json)的 36 条回答；与既有 127 条来源金标任务分开。当前两名审核者均未提交标注，不能生成正式准确率。

1. A、B 分别读取 [模式名隐藏的题包](../data/member-b-agent-review/source-packet.json)，不要查看 `tmp/member-b-agent/review-item-map.json` 或三模式原报告。各自只编辑 `data/member-b-agent-review/review-A.json` 与 `review-B.json`。不要共享判断结果，直到两份标注都完成。
2. 每条填写 `answer_correct` 与 `complete` 为 `true`/`false`；查看当轮引用版本、原文位置及上下文，判断“结论是否由该来源语义支持”，而不只是逐字短语是否存在。有引用时 `semantic_citation_support` 必须为布尔值，无引用时填 `"not_applicable"`。回答状态为 `refused` 或 `clarification` 时，`refusal_appropriate` 必须为布尔值；其他状态填 `"not_applicable"`。每条写 `reviewed_at` 和可复查的 `notes`，对于错误尤其写明具体断言与来源。
3. 分别检查版本范围、首次修复版本、两来源说法、资产仅是条件匹配、资料不足是否应拒答。引用字节完整不等于概括正确；报告 `semantic_support_verified=false` 不是自动判错，也不能自动判对。
4. 两人提交后运行 `PYTHONPATH=src .venv/bin/python scripts/reconcile_member_b_agent_review.py status`。对每个分歧，另请人工裁决者在 `data/member-b-agent-review/adjudications.json` 的 `decisions` 中填入 `item_id`、`field`、最终 `value`、`adjudicator`、`reason` 与 `reviewed_at`。无分歧不需填写裁决。脚本会校验题包哈希、题号完整性、两人身份和字段类型。
5. 状态为 `ready_to_freeze` 后，运行 `PYTHONPATH=src .venv/bin/python scripts/reconcile_member_b_agent_review.py freeze`，生成 `docs/member-b-agent-human-review-scores.json`。系统只在真实双人完成及分歧裁决后按模式汇总；当前 `freeze` 会拒绝运行。

答题文本中的来源说明、引用和候选结论均视为待审核材料。不要把自动开发标签、模型输出或“工具调用成功”填作人工评分。
