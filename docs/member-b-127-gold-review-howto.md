# 127 条来源金标：实际操作说明

**当前生效流程（2026-10-04）：** 用户已授权以 AI 复核替代人工，项目正式采用 [AI 类别金标 v1](member-b-week6-ai-gold-release.md)：127/127 已冻结，112 evidence、15 partial。当前状态使用 `PYTHONPATH=src .venv/bin/python scripts/release_week6_ai_gold.py status` 查询。以下双人人工流程作为独立可选流程保留，其 0/127 状态不再阻止本次 AI 金标发布；原人工文件没有被代签。

范围说明：127 是本项目现有冻结题包的规模，不是主办方规定必须恰好审核的数量。双人独立审核与第三人裁决是项目选择的可信评测方法。若另选规模，应先定义抽样规则并冻结新题包，不能看过测试结果后删题、换组或缩小分母。以下 127/127 发布条件仅适用于当前题包。

2026-10-01 补充：[来源 AI 辅助预审与冻结测试组暂行富化评测](member-b-source-review-provisional-evaluation.md)已提供单独的审核稿、逐字引用、来源差异及预测快照。它不构成两位真人的独立审核，未填写或签署下述 A/B 人工模板，正式人工金标进度仍为 0/127。为保持人工盲审，初审人员不要先阅读 AI 审核稿或测试评分。

当前状态：0/127。题包含 66 条 train、37 条 development、24 条 test；来源分布为 CISA KEV 7 条、Crossref 30 条、GitHub Advisories 30 条、NVD 30 条、vLLM 厂商 30 条。每条由两名不同的人独立审核，因此需要 **254 份独立标注**；文字或证据有分歧时再由第三人裁决。

## 1. 分配人员和材料

- 协调者保管 [冻结题包](../data/week6-human-review/source-packet.json) 和 [裁决文件](../data/week6-human-review/adjudications.json)。
- 审核者 A 只编辑 [review-A.json](../data/week6-human-review/review-A.json)，审核者 B 只编辑 [review-B.json](../data/week6-human-review/review-B.json)。两人可读同一题包，但初审结束前不看对方答案或模型输出。
- 两人分别把自己的 `reviewer_id` 填成真实可区分的标识；确实独立完成后才把 `independent_review_attested` 改为 `true`。`review_method` 保持 `human`。脚本只验证本机自述，不验证真实身份。

题包已经保存对应来源的 `raw_record`、来源 ID、版本和哈希。审核者一般不必重新上网找原文；若原文有外部链接，不能把“链接存在”当作“已阅读链接正文”。

## 2. 每条题目的操作

在项目根目录执行：

```bash
PYTHONPATH=src .venv/bin/python scripts/week6_gold_review.py show --index 1
```

`--index` 从 1 到 127。输出中的 `task.id` 对应模板 `reviews[].task_id`，`records[].raw_record` 是这题可引用的冻结来源。先看题目、来源和原文字段，再独立写答案。

每一行必须填写：

| 字段 | 怎么填 |
|---|---|
| `reviewed_at` | 实际审核完成时间，例 `2026-09-30T10:30:00+08:00`；不能批量伪造同一时间 |
| `answer_class` | `evidence`：问题要求的结论有足够来源；`partial`：只有部分结论；`refused`：不应给事实性答案 |
| `complete_answer` | 亲自写清楚可确认的结论和不能确认的边界，不能只填一个版本号或类别 |
| `supported_fields` | 使用相对 `raw_record` 的字段名，如 `shortDescription`、`requiredAction` 或 `/shortDescription` |
| `citations` | 每项有 `record_id`、`pointer`、`quote`；`record_id` 是题包 `records[].event_id`，`pointer` 如 `/shortDescription`，`quote` 是该字段的连续逐字原文 |
| `refusal_reason` | `partial`、`refused` 必须解释缺什么证据；`evidence` 可为 `null` |

例如第 1 题的 `raw_record.shortDescription` 含有 `Langflow contains a code injection vulnerability`。若审核者需要引用这个字段，引用对象的**格式**是：

```json
{
  "record_id": "b1a7d612-c54d-421c-824f-01101f8d6729",
  "pointer": "/shortDescription",
  "quote": "Langflow contains a code injection vulnerability"
}
```

相应 `supported_fields` 至少要包含 `shortDescription`。上例只说明指针和逐字摘录的填法，不预先给第 1 题定类别或完整答案。数组、对象字段被引用时，校验器按 `json.dumps(..., ensure_ascii=False, sort_keys=True)` 的文本查找 quote；优先使用清晰的字符串字段。

## 3. 检查 A/B 进度

```bash
PYTHONPATH=src .venv/bin/python scripts/week6_gold_review.py status
```

输出现在包含 A、B 各自已填写数、双方已完成数、待审数和分歧数。需要查具体 `task_id` 时加 `--detailed`。若已填写字段无效，脚本会报错并指出问题类型；修正后重跑。**不要运行 `prepare`**，现有题包与模板已冻结，重新准备会被拒绝创建并可能扰乱工作。

## 4. 第三人裁决

两人都完成后，按 `status --detailed` 的 `conflict_task_ids` 逐条审阅。程序对类别、完整答案、支持字段、拒答原因和引用做严格比较；即使两人只是用词不同，也可能列为分歧。第三人应判断语义和原文支持，并在 `adjudications.json` 的 `decisions` 中为每个冲突放一项：

```json
{
  "task_id": "对应的题目 ID",
  "adjudicator_id": "与 A、B 不同的真实审核者标识",
  "reviewed_at": "实际裁决时间，含时区",
  "review_method": "human",
  "reason": "说明两份答案的差异、原文依据与最终取舍",
  "answer": {
    "answer_class": "evidence 或 partial 或 refused",
    "complete_answer": "第三人确认后的完整答案",
    "supported_fields": ["对应字段"],
    "refusal_reason": null,
    "citations": []
  }
}
```

`answer` 内的字段仍须遵守第 2 步校验规则；上面的空 `citations` 仅是结构占位，`evidence` 或 `partial` 时必须换成真实引文。裁决者不能与 A 或 B 是同一人。

## 5. 冻结与使用

只有 `status` 显示 127/127 完成、无待审和无冲突时，执行：

```bash
PYTHONPATH=src .venv/bin/python scripts/week6_gold_review.py freeze \
  --output data/week6-human-review/gold-release-v1.json
```

冻结脚本不会覆盖已有发布文件。之后用冻结的 **24 条 test 组**做正式留出评测；train/development 用于开发和错误分析。金标发布本身不会自动生成模型准确率，仍需把模型答案与人工金标逐题比较，并分别报告正确性、召回率、拒答和引用语义支持。
