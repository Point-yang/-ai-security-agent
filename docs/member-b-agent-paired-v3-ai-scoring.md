# v3 Agent AI 候选评分

状态：历史 AI 候选评分，不是人工金标。A/B 文件后来已由用户确认并转为 `human_reviewed`；本文件保留预审时的原始判断，不能作为当前评分直接引用。

审计更正：`6c71044f0fd1876f` 的“只有 14 个 citations，`[15]` 越界”判断有误。原始 v3 报告和盲审题包均有 15 个 citations，第 15 条厂商描述包含前缀缓存机制与 TTFT。保留本文件作为历史 AI 候选记录，正式更正依据见 [修复与审计](member-b-agent-two-failure-repair-20260929.md)。

共 21 条；候选支持引用 6 条；候选完整回答 17 条；答案语义仍需人工判断 7 条。

- `0eedb26a72807dd3`：correct=likely_false；support=likely_true；complete=likely_false；只引用 vllm-vendor 的 packages，未回答 GitHub 来源分别给出的修复依据；虽标 partial，但题目要求两来源，建议判不完整。
- `1700d766656158a6`：correct=likely_true；support=not_applicable；complete=likely_true；无引用的拒答符合当前资料缺口/资产/复现限制。
- `197572af33fe0a61`：correct=likely_true；support=not_applicable；complete=likely_true；无引用的拒答符合当前资料缺口/资产/复现限制。
- `21035cb1c17abb4e`：correct=likely_true；support=not_applicable；complete=likely_true；无引用的拒答符合当前资料缺口/资产/复现限制。
- `2ed9d1a748db0f4d`：correct=human_required；support=likely_true；complete=likely_true；两来源 packages、标题和描述均有引用；需人工确认 PR/复杂度表述是否完全由对应片段支持。
- `3da5d9349de5ffc6`：correct=likely_true；support=not_applicable；complete=likely_true；无引用的拒答符合当前资料缺口/资产/复现限制。
- `3ebf1cc04d2211af`：correct=likely_true；support=not_applicable；complete=likely_true；无引用的拒答符合当前资料缺口/资产/复现限制。
- `53cb97e95562882b`：correct=human_required；support=likely_true；complete=likely_true；问题、版本边界和描述均有来源字段；需人工核对测试环境与攻击结论是否超出原文。
- `5ee4256f4e979036`：correct=human_required；support=likely_true；complete=likely_true；两来源首个修复字段和补丁链接均被覆盖；需人工核对 Patches 片段的具体 PR 是否与来源一致。
- `6c71044f0fd1876f`：correct=likely_false；support=likely_false；complete=likely_false；答案引用了 [15]，但该条目只有 14 个 citations；存在越界引用，不能作为完整正确答案。
- `6fa61940638cfcef`：correct=human_required；support=human_required；complete=likely_false；这是本地抽取式证据包，包含两来源 packages，但没有形成完整的自然语言回答；题目要求首个修复版本及依据，建议人工判完整性。
- `733119772c428f38`：correct=human_required；support=likely_true；complete=likely_true；两来源版本字段、描述和引用差异均有候选依据；需人工核对每个描述结论是否支撑。
- `74c3dad06e0e88bf`：correct=likely_true；support=not_applicable；complete=likely_true；无引用的拒答符合当前资料缺口/资产/复现限制。
- `8a0756dec8abb996`：correct=human_required；support=human_required；complete=likely_false；这是本地原文摘录而非整理后的比较答案；有完整候选证据，但没有直接回答两来源差异，建议人工判完整性。
- `9b0924462c150afd`：correct=likely_true；support=not_applicable；complete=likely_true；无引用的拒答符合当前资料缺口/资产/复现限制。
- `9c41aa090767ae75`：correct=human_required；support=likely_true；complete=likely_true；问题、漏洞机制、版本边界和测试条件均有引用；需人工核对 AUC、环境和修复表述是否逐项对应。
- `b2fb43e8f17584af`：correct=likely_true；support=not_applicable；complete=likely_true；无引用的拒答符合当前资料缺口/资产/复现限制。
- `d36b47b1ca09fe6b`：correct=likely_true；support=not_applicable；complete=likely_true；无引用的拒答符合当前资料缺口/资产/复现限制。
- `dc3d38bb2e329f08`：correct=likely_true；support=not_applicable；complete=likely_true；无引用的拒答符合当前资料缺口/资产/复现限制。
- `e32e4014f717e73d`：correct=likely_true；support=not_applicable；complete=likely_true；无引用的拒答符合当前资料缺口/资产/复现限制。
- `f782a6d7a827d42f`：correct=likely_true；support=not_applicable；complete=likely_true；无引用的拒答符合当前资料缺口/资产/复现限制。

下一步：A/B 独立复核 21 条，尤其先看 likely_false 和 human_required 项；完成后运行 reconcile，再裁决分歧。
