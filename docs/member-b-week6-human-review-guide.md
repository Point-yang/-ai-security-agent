# 第六周人工金标审核流程

2026-10-04 更新：用户已授权本项目使用 AI 复核替代人工，正式版本见 [AI 类别金标发布](member-b-week6-ai-gold-release.md)。本页继续说明可选的人工流程；人工 0/127 不代表项目正式 AI 金标未完成，也不会被改写成已发生的人工审核。

逐步操作与字段示例见 [127 条来源金标实际操作说明](member-b-127-gold-review-howto.md)。

本包有127题，目前实际人工完成数为0。用户已确认暂无标注文件，本轮交付的是可执行的审核与发布流程。系统不会填写审核者身份、冒充人工签署或将自动回归标签发布为金标。

## 分发材料

本机材料位于 `data/week6-human-review/`：

- `source-packet.json`：冻结问题、来源原始记录、版本、哈希和分组。无模型输出或预测标签。
- `review-A.json`、`review-B.json`：两份独立填写的空白模板。
- `adjudications.json`：双人分歧裁决表，初始为空。

协调者分别给两位审核者提供来源包与各自模板。在两人均完成独立初审前，不提供对方答案或系统回答。模板的 `reviewer_id` 由本人填写，`independent_review_attested` 仅由实际独立审阅者勾选。当前是本机自述身份，尚无账户鉴权来验证身份真实性。

问题已写明来源及公告/论文标识，审核者根据保存的原文版本作答。字段 `split` 固定为原集合划分，不得随结果调整。后续正式留出测试必须使用完成双人审核并冻结的测试组，不能以本轮原20题（8 train、12 development、0 test）替代。

## 每题填写

1. `reviewed_at`：实际审核完成时间，带时区的 ISO 格式。
2. `answer_class`：`evidence`（可支持）、`partial`（仅部分证据）、`refused`（应拒答）。
3. `complete_answer`：完整答案，不只填类别或关键词。
4. `supported_fields`：答案可由原文支持的字段指针，例如 `description` 或 `/description`。
5. `citations`：每项包含 `record_id`（来源包中的 event_id）、`pointer`（相对 raw_record 的 JSON Pointer）、`quote`（该字段内逐字摘录）。
6. `refusal_reason`：partial/refused 必填，说明缺失证据或为何不能推出结论。

证据只能引用该问题的冻结关联组，不能把其他资产或无关事件当作支持。程序会逐项检查指针、引文和字段对应关系；程序不能替代审核者判断自然语言结论是否被充分支持。

## 检查进度

```bash
PYTHONPATH=src .venv/bin/python scripts/week6_gold_review.py status
```

未填答、只有一人完成、两人身份相同、未确认独立审阅、字段或引文不符，均不能成为已完成金标。两人答案文字不同也会进入分歧表，由审核者明确处理，不做自动语义合并。

## 分歧裁决

第三名审核者在 `adjudications.json` 的 `decisions` 中为对应 `task_id` 填写：`adjudicator_id`、`reviewed_at`、`review_method="human"`、裁决理由 `reason` 和最终 `answer`。最终 answer 沿用上面的类别、完整答案、支持字段、引用及拒答依据格式。裁决者不能与前两名审核者相同。

## 发布门槛

```bash
PYTHONPATH=src .venv/bin/python scripts/week6_gold_review.py freeze \
  --output data/week6-human-review/gold-release-v1.json
```

只有全部任务完成双人独立审核、所有分歧均已裁决时才允许发布。发布文件包含来源包、两份审核和裁决文件的摘要，并采用独占创建避免覆盖历史版本。未完成时命令拒绝发布，不会自动补齐。

冻结标签后再运行正式测试。完整模型答案的正确性和引用蕴含仍需由人工按金标评分；当前自动“类别匹配”“逐字摘录一致”“期望事件相关支持”是不同指标，不能混用。
