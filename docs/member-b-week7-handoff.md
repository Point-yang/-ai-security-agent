# A→B 第七周集成交接

2026-09-24。A 第一轮数据与工程修复已完成，B 的问答质量修复继续按[六周独立审查](member-b-week6-independent-review.md)完成后单独验收。

收尾时已发现 B 的[质量修正补交](member-b-week6-quality-resubmission.md)，本次未代替其开展独立质量复验。以下项目用于核对补交成果与后续冻结条件。

## 接口与数据变化

- 数据库迁移至 `a730cf924be1`，API 0.11.0。独立评测库也需备份后 `init-db`，不能用新代码直接查询旧 schema。
- `/api/v1/comparisons` 默认只返回 active；`include_inactive=true` 查看归档。新增 `is_active`、`retired_at`。
- 来源更新、撤回和重新出现会递增 annotation_version 并标为 needs_evidence。归档项拒绝复核写入，原审计和补证任务仍保留。
- 复核历史新增 `change_kind`、`observations`，旧记录可能为 null。自动变更快照保存变更前观察，不能冒充当前事实。
- `structured-v2` 新增 CPE 父配置复杂性标记；`conservative-match-v2` 对未支持的生态和配置保持 unknown。

## 持续采集与冻结库

真实库已启动 `monitor --sync-semantic`，初次补齐 648 个向量；当前快照为 669 条情报、3120 个片段和向量。模型不可用不回滚采集，语义查询保持显式不可用，后台后续重试。

真实库持续变化，不应改写旧 corpus hash 强行运行 benchmark。请使用独立冻结评测库，或生成新版本协议。派生 schema 改变后，旧实现下的性能成绩仍属于旧报告。

## B 冻结前补交

1. 修复空期望集合的引用支持计数，分别列原文一致性和问题相关性；按 split/语言汇总并保留旧报告。
2. 复跑中文召回和无答案拒答，三种模式用同一冻结问题集。
3. 独立金标应含完整答案、字段证据、两名复核者和分歧裁决，不能把自动开发标签改成人工标签。
4. 验证包含 inactive 比较的会话重放与补证页面：历史可追溯，归档不参与新答案的当前事实判断。
5. 总结 Agentic 相对混合检索的实测收益或局限，列出时延、成本、硬件、缓存和并发条件。

[A 冻结前证据包](member-a-week7-release-check.json)当前 `release_ready=false`，工程通过不能替代上述门槛。
