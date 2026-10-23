# A 第七周扩展来源：离线适配验收

此文件保留 2026-09-25 的离线验收状态。四类来源在 2026-09-30 的真实采集结果见 [扩展来源真实采集验收](member-a-catalog-live-acceptance-20260930.md)。

日期：2026-09-25。交付状态：**四类来源的元数据采集代码和离线回归已完成；联网持续采集尚未验收，不能计入正式来源覆盖分。**

## 边界和数据契约

| 来源 | 可用入口 | 本地回放结果 | 限制 |
|---|---|---:|---|
| Hugging Face 博客 | `/api/blog` JSON 索引 | 14 条 | 仅首页标题、日期和链接，未采集正文；包含非安全文章，不当作漏洞公告 |
| NIST AI RMF | Crossref 指定 DOI 元数据 | 1 条 | DOI 与 NIST 发布方均核对；只保存元数据，未采 PDF 全文 |
| Federal Register | AI 关键词政策目录 | 0 条 | 首个缓存页面的标题严格筛选为零；不能声称政策资料已经覆盖 |
| ProjectDiscovery | `nuclei-templates` 的 `cves.json` 目录 | 22 条 | 只读 CVE/标题/描述/模板路径；没有下载 YAML、运行模板或复现漏洞 |

来源资料：[Hugging Face 博客](https://huggingface.co/blog)、[NIST AI RMF](https://doi.org/10.6028/NIST.AI.100-1)、[Federal Register API](https://www.federalregister.gov/developers/documentation/api/v1)、[ProjectDiscovery 模板目录](https://github.com/projectdiscovery/nuclei-templates)。目录内容来自来源声明，未证明文章与某漏洞的关联或模板有效性。

`catalog_items` 与 `catalog_revisions` 独立保存元数据、修订、来源哈希和证据位置。JSON 使用 JSON Pointer；POC 目录是 NDJSON，使用 `byte:start:end` 定位，保留 HTTP 响应原始字节、SHA-256 和 `application/x-ndjson` 媒体类型。POC 没有来源发布时间时保存 null，不把采集日或 CVE 年份伪装成发布时间。元数据没有进入漏洞 `events`、资产 exposure 或 B 的正式问答索引。

## 可复验结果

新增 `catalog-import`、`catalog-audit`、`/api/v1/catalog/items`、历史接口和 `/catalog` 页面。数据库升级前完整性为 ok，在线备份在 `data/backups/before-member-a-catalog.sqlite`，迁移到 `c61e40a782fb`，API 代码版本 0.12.0。

先前只读探测已取得四份公开响应。本轮以 `origin=replay` 导入，不执行新的外部请求：三类共 37 条目录记录，政策页严格匹配 0 条；四份响应均按原始字节留存。37/37 条版本指针、标题和元数据指纹通过审计，原有事件数在导入前后不因目录增加而变化。

机器记录：[博客](member-a-catalog-blog-replay.json)、[NIST](member-a-catalog-standard-replay.json)、[政策](member-a-catalog-policy-replay.json)、[POC](member-a-catalog-poc-replay.json)、[目录审计](member-a-catalog-integrity.json)、[旧引用兼容](member-a-catalog-citation-check.json)、[历史字段审计](member-a-catalog-evidence-check.json)。

新增和既有全量回归 145 项通过；Ruff、格式、Alembic、前端脚本语法和 Compose 配置检查通过。原有事件问答引用保持兼容。`/catalog` 在本地进程使用新代码启动后可用；已运行的旧 API 进程不会自动热加载新路由，首页在旧版本下会隐藏入口。

## 尚未完成的联网验收

`config/catalog-sources-staging.json` 的四个目标默认 disabled，不会改变现有六个真实监测目标，也不会把回放记录显示为 live。当前元数据目录的 live 行数为 0。Federal Register 的首个缓存页面没有符合严格标题条件的条目；需要调整官方查询并复验，而非放宽为不相关内容。

进一步核对博客分页和模板目录提交时间的只读联网命令被自动审批系统拒绝，原因是当前用量上限、自动审批无法完成；**并非安全风险判定**。未通过其他接口绕过审批。恢复联网验收后应先验证分页/时间语义、真实更新留史和来源有效结果，再按目标逐个启用。POC 只应作为待复核模板元数据，不进行自动扫描。

现在仍为原有 5 个 live 来源适配器、4 类经真实采集验收的来源。新四类属于已实现代码与回放资料，不能将注册数当作赛题优秀档所需的真实覆盖。24 小时窗口仍显示 `insufficient_coverage`，见[监测窗口](member-a-catalog-monitoring-window.json)。独立人工金标和 B 的正式问答质量也仍是整体冻结门槛。
