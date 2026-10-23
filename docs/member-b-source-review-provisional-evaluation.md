# 冻结来源 AI 辅助预审与暂行富化评测

2026-10-04 后续状态：用户授权 AI 替代人工后，已按逐题类别复核发布 [项目正式 AI 金标](member-b-week6-ai-gold-release.md)。本页保留 2026-10-01 暂行版本的历史记录；当前正式结果以新发布文件为准。

日期：2026-10-01。已为全部 127 条记录生成来源结论、证据边界、支持字段和逐字引用的 AI 辅助审核稿，并用原冻结 test 的 24 条记录完成一次结构化事实评测。**这不是已完成的双人人工金标评测：A/B 仍为 0/127，正式指标为 null。**

后续[对照复核结论](member-b-source-review-verification.md)：原文、引文与指标计算再次核验一致；统一 `partial` 仍需逐题语义复核，整份审核稿未获人工通过。

127 是项目现有题包规模，主办方未规定必须恰好审核 127 条。当前题包的发布门槛仍适用；另设规模应事先冻结抽样规则，不能根据本次结果删题。

## 结果与定义

本次评测对象为旧评测库 `data/member-b-week6-eval.db` 的 `structured-v1` 富化输出。所有 24 条预测均与冻结题包的 revision_id、原始文档哈希、record_pointer 和原文一致。当前主库已有 8 条 test 记录的版本不同，未混入本次评测；这些结果也不能用来代表当前 structured-v2 系统。

| 指标 | 分子 / 分母 | 结果 |
|---|---:|---:|
| 逐条完全匹配准确率 | 19 / 24 | 79.17% |
| 来源事实精确率 Precision | TP / (TP + FP) = 84 / 84 | 100.00% |
| 来源事实召回率 Recall | TP / (TP + FN) = 84 / 99 | 84.85% |
| 关联组宏平均召回率 | 各组内微平均召回率再等权平均 | 89.49% |
| 全部记录正确的关联组比例 | 16 / 21 | 76.19% |

TP=84，FP=0，FN=15。逐条准确率要求该条在评测范围内的事实集合完全一致；事实精确率不能称为二分类 accuracy，因为未定义 TN。重复事实只在同一题内去重，跨来源记录保留。24 条记录属于 21 个冻结关联组；这些关联组不保证每组就是一个独立漏洞。

### 计分范围与限制

纳入：CVE/GHSA/DOI 标识、厂商/产品/包实体、公告原始受影响及修复范围、CVSS 版本/向量/分值/发布方、CPE 叶节点及版本边界、NVD affectedData 的带发布方和产品身份的版本状态对象。缺失预测保留分母；空分母返回 null。

实体忽略大小写；空包生态记 unknown；公告版本字符串仅移除空白，不补上界，也不把一个修复版本改成所有后续版本。NVD 的 affectedData 版本对象单独计分，保留 affected/unaffected、defaultStatus 和发布方；CPE 叶节点不能替代该对象。因此指标包含对这类来源表示的结构化覆盖要求，而不是仅比较版本集合的语义等价性。

未评测：完整问答语义、拒答质量、引文蕴含、版本解析器正确性、CPE AND/OR/negate 语义、selected CVSS 排序、质量标志、现实漏洞真伪和本地资产命中。Crossref 在本次富化事实口径中只计 DOI；其 100% 不表示论文结论已核验。源码和少量已有输出在设计口径时已被查看，标注仍由同一 AI/规则生成，不能称为独立盲测。规则未从生产富化函数导入预期值。

## 分来源结果

| 来源 | test 数 | TP | FP | FN | 精确率 | 召回率 | 逐条准确率 |
|---|---:|---:|---:|---:|---:|---:|---:|
| cisa-kev | 2 | 6 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| crossref | 8 | 8 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| github-advisories | 3 | 18 | 0 | 0 | 100.00% | 100.00% | 100.00% |
| nvd | 5 | 16 | 0 | 15 | 100.00% | 51.61% | 0.00% |
| vllm-vendor | 6 | 36 | 0 | 0 | 100.00% | 100.00% | 100.00% |

NVD 的 15 项遗漏为：5 项厂商实体、4 项产品实体、6 个版本状态对象。版本状态对象中含 1 个明确 unaffected 的 0.28.0 版本；这里的“事实召回”包括该有意义的否定事实。CVE-2026-90553 已从 CPE 抽取产品 vllm，但来源 affectedData 的厂商 vllm-project 和版本对象仍未保留。

## 逐条测试结果

| 来源 / 编号 | TP | FP | FN | 完全匹配 |
|---|---:|---:|---:|---|
| cisa-kev / CVE-2025-34291 | 3 | 0 | 0 | 是 |
| cisa-kev / CVE-2026-9198 | 3 | 0 | 0 | 是 |
| crossref / 10.1007/s00231-026-03780-8 | 1 | 0 | 0 | 是 |
| crossref / 10.21686/1818-4243-2026-4-4-11 | 1 | 0 | 0 | 是 |
| crossref / 10.5195/jmla.2025.2022 | 1 | 0 | 0 | 是 |
| crossref / 10.1145/3645103 | 1 | 0 | 0 | 是 |
| crossref / 10.1007/978-3-031-96093-2_12 | 1 | 0 | 0 | 是 |
| crossref / 10.69693/dcs.v3i2.74 | 1 | 0 | 0 | 是 |
| crossref / 10.3390/cancers17223691 | 1 | 0 | 0 | 是 |
| crossref / 10.1007/s42979-026-05334-5 | 1 | 0 | 0 | 是 |
| github-advisories / GHSA-rxc4-3w6r-4v47 | 6 | 0 | 0 | 是 |
| github-advisories / GHSA-w6q7-j642-7c25 | 6 | 0 | 0 | 是 |
| github-advisories / GHSA-mgrm-fgjv-mhv8 | 6 | 0 | 0 | 是 |
| nvd / CVE-2026-94625 | 3 | 0 | 3 | 否 |
| nvd / CVE-2026-93436 | 3 | 0 | 3 | 否 |
| nvd / CVE-2026-73558 | 2 | 0 | 3 | 否 |
| nvd / CVE-2026-90553 | 6 | 0 | 3 | 否 |
| nvd / CVE-2026-69147 | 2 | 0 | 3 | 否 |
| vllm-vendor / GHSA-7m6h-x95x-82q5 | 6 | 0 | 0 | 是 |
| vllm-vendor / GHSA-w6q7-j642-7c25 | 6 | 0 | 0 | 是 |
| vllm-vendor / GHSA-jrf6-vqxq-pjv2 | 6 | 0 | 0 | 是 |
| vllm-vendor / GHSA-v359-jj2v-j536 | 6 | 0 | 0 | 是 |
| vllm-vendor / GHSA-rxc4-3w6r-4v47 | 6 | 0 | 0 | 是 |
| vllm-vendor / GHSA-6qc9-v4r8-22xg | 6 | 0 | 0 | 是 |

## 来源差异处理

当前没有两位人工审核者的答案，所以不存在可以宣称“已裁决”的 A/B 分歧。AI 稿列出 20 个涉及多个记录的版本范围对照组，并采取来源分别归属的处理：相同表示可对应，缺失上界不补齐，实质差异并列陈述，统一范围无法确认。对照组数量不是冲突数量。

| 事项 | 依据与处理 |
|---|---|
| CVE-2026-73558 / GHSA-7m6h-x95x-82q5 | NVD 为 < 0.27.0；厂商字段为 < 0.21.0，修复为 >= 0.27.0，正文还涉及 0.21.0 后路径。保留冲突，不能宣称中间区间安全。 |
| GHSA-pmqf-x6x8-p7qw / GHSA-wv77-2vpf-vmmg | 相同受影响范围，但修复字段分别是 0.11.1、0.14.0。分别引用，不选一个覆盖另一个。 |
| GHSA-3f6c-7fw2-ppm4 / GHSA-qh4c-xf7m-gxfc | 冻结别名组把不同 GHSA 放在一组；不能因此推定为同一漏洞或合并修复版本。 |
| GHSA-rh4j-5rhw-hr54 | 受影响 <= 0.7.0 与修复 v0.7.0 边界重叠，0.7.0 安全性不确认。 |
| GHSA-hhv2-872h-628q | 受影响 <= 0.28.0 与修复 >= 0.28.0 边界重叠，0.28.0 安全性不确认。 |
| GHSA-x8xr-mj9x-6h7w、GHSA-78fp-cf4h-g36p | 冻结正文及 withdrawn_at 明示重复公告已撤回；保留历史声明，不能计作新独立漏洞。 |
| CVE-2026-7141 | 原文明示 disputed，且有替代解释；只能报告争议与来源声明，不能确认漏洞已被独立验证。 |

## 可复核交付

- [127 条可读 AI 审核稿](../output/week6-source-review-v2/source-review-ai.md)：每题来源结论、边界、支持字段、逐字引文。
- [机器可读审核稿](../output/week6-source-review-v2/source-review-ai.json)：821 项答案引文、1046 项事实证据引用（可能重复），含 20 组来源对照。
- [冻结预测快照](../output/week6-source-review-v2/test-predictions.json)：24 条旧库原始富化输出。
- [逐题计分及差异](../output/week6-source-review-v2/test-enrichment-evaluation.json)：TP/FP/FN、预期事实、预测事实和全部遗漏。
- [校验记录](../output/week6-source-review-v2/validation.json)：127 条原始记录字节哈希/指针校验、分组隔离、受保护文件摘要。
- [生成与评分脚本](../scripts/review_week6_sources.py)及[计分保护测试](../tests/test_week6_source_review.py)。

`review_method=ai_assisted_source_extraction`，`independent_review_attested=false`，`reviewed_at=null`；每题 `drafted_at` 记录实际自动生成时间。全部草稿暂标 partial，表示可转述来源但现实有效性尚未独立确认，不能拿这些类别直接评价模型拒答能力。两份人工槽位、裁决表和冻结题包未修改，未发布 human gold。人工盲审人员初审时不应看到本稿或预测。

来源题包摘要：`2a60c7098e2f25a8ccfa2d2d5810a821a4ddbc0311e8ddea1fbf3e2763e7bd14`。审核稿摘要：`910556186abd3ff3597eb2d3d58e3469224fa52157c6f689cb0476d6324fe089`。预测快照摘要：`5a4332f920e36743d0f2846ee2e118cf96a888585a1f321eafde232ecb181606`。评分摘要：`c56dc4996c54846566ec87a765f1838bb0c6f79b7d3346c19cbbe6fe02b5b7a1`。

## 复跑与正式完成条件

保留原预测重算（输出目录须为新目录，脚本拒绝覆盖）：

```bash
mkdir -p tmp/week6-score-replay
cp output/week6-source-review-v2/source-review-ai.json output/week6-source-review-v2/test-predictions.json tmp/week6-score-replay/
PYTHONPATH=src .venv/bin/python scripts/review_week6_sources.py score --output tmp/week6-score-replay
```

从来源和旧库重建可分别运行 draft、snapshot、score，三步使用同一个新的 --output 目录；默认目录已存在，直接覆盖会被拒绝。

校验：Ruff 通过；计分保护与原金标流程测试共 24 项通过。覆盖缺失预测、错误值、重复预测、漏题、版本错配、错误题包、篡改摘要、输出防覆盖、AI 无法冒充人工发布及 NVD unaffected 保留。

正式完成仍需要两名真人独立填写 A/B，并由不同的第三人处理真实分歧；审核后按原流程冻结金标，再确定同一事实口径下的正式评分。逐字匹配校验不能替代自然语言语义判断，本次暂行结果不得填入正式验收准确率/召回率。
