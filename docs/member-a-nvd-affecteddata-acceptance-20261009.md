# 成员 A：NVD affectedData 富化修复验收（2026-10-09）

## 验收结论

本轮 A 的 NVD 数据富化修复通过本地数据与服务验收：此前 5 条 NVD/CVE 样本中记录的 15 项遗漏事实，现均可在结构化富化中找到，并能追溯到 NVD 原文 JSON Pointer；6 条版本状态记录全部与原始指针核对一致，相关证据片段已进入检索索引。

这次验收范围是已知遗漏的定点回归，不是完整人工金标评测，不能据此宣称全库准确率或竞赛最终得分。

## 完成内容

- NVD 适配器现在读取每个 CVE 条目中的 `affected[].affectedData[]`，保留发布方、厂商、产品、包标识、`defaultStatus` 与逐项版本对象。
- 富化结果保留 `versionType`、`status`、`version`、`lessThan` / `lessThanOrEqual`、`changes` 等原字段，不将范围臆测成某个生态的版本比较，也不把 `unaffected` 推断为“首个修复版本”。CVE 版本状态语义见 [CVE Project 版本状态规范](https://github.com/CVEProject/cve-schema/blob/main/schema/docs/versions.md)。
- 新增的字段证据和版本对象片段各自带有原始文档 ID、来源发布方与 JSON Pointer；既有采集原始修订记录未被改写。
- 重建结构化富化、跨来源比较、检索索引和本地向量；比较差异仍保留为待核验状态，没有自动合并。

## 验收证据

| 检查项 | 结果 |
| --- | --- |
| 之前 5 条记录中的遗漏事实 | 15 / 15 已找回 |
| 原文版本状态指针 | 6 / 6 与原始 NVD 文档一致 |
| 对应版本状态检索片段 | 6 / 6 已建索引 |
| 主库事件数 / 搜索片段 | 1,117 / 6,364 |
| 当前有效本地向量 | 6,364 / 6,364；384 维 `all-MiniLM-L6-v2` |
| 8010 健康检查 | HTTP 200；数据库、采集配置、原文存储均可用 |
| RAG 状态 | `ready`；在线接口报告 6,364 / 6,364 个片段有有效向量 |
| 在线富化详情 | `CVE-2026-94625` 返回 NVD 发布方、vllm-project/vllm、版本范围、affected/unaffected 状态与原文指针 |
| 在线精确编号检索 | `CVE-2026-94625` 的词法检索返回原文引用片段，含版本对象指针 |

逐条核对见 [定点验证 JSON](member-a-nvd-affecteddata-verification-20261009.json)；全量富化统计见 [富化同步报告](member-a-nvd-affecteddata-enrichment-20261009.json)；向量同步快照见 [向量报告](member-a-nvd-affecteddata-vectors-20261009.json)；操作前 SQLite 在线备份和校验值见 [备份记录](member-a-nvd-affecteddata-backup-20261009.json)。

## 影响与边界

本次把 1,117 条事件的派生富化升级至 `structured-v5-nvd-authority`，把检索索引升级至 `lexical-v8-nvd-authority`。同步后共 6,364 个片段，覆盖率统计为 100%；跨来源比较重新计算了 75 个标识，状态为 agreement 103、variation 104、conflict 4。这里的“覆盖率”是派生富化记录覆盖，不代表字段完整率或语义正确率。

样本中的 15 项事实来自此前冻结的 AI 辅助评估报告，属于已知漏项回归集；本轮没有新增人工标注，也没有跑完整答案正确率评估。NVD 的版本区间继续作为发布方原始声明展示；产品资产匹配逻辑仍只使用原有明确的受影响包实体，不会因 NVD 声明而自动判定资产受影响。

## 后续安排

1. 由成员 A 为 `affectedData` 增加独立人工金标样本，覆盖 `affected`、`unaffected`、`unknown`、`defaultStatus`、边界版本和 `changes`，然后评估精确率、召回率与引用指针准确率。
2. 采集器保持连续观察。单轮服务运行和成功采集不等于 SLA 达标；此前日志存在多源网络失败以及 `WriterBusy` 重试记录，需另行观察连续窗口并区分外部来源超时与本地资源竞争。
3. 在确认新语料评测不回退后，再进入下一项 A 任务；本次没有将采集恢复或 SLA 标注为完成。

