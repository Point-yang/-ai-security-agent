# 成员B采集恢复展示与交付验收

2026-10-07。依据[10月4日B要求](member-b-collector-recovery-requirements-20261004.md)。**状态展示、隔离页面验收、正式服务部署与材料更新已完成；真人演练和真实发布到发现时延仍未完成。** 本验收不宣称全部比赛指标达标。

## 交接条目与结果

| 条目 | 实现及验收 | 状态 |
|---|---|---|
| 紧凑目标总览 | 首页、研究页、目录页显示目标总数、最近轮次成功/失败、当前超期数。研究页1次点击进入目标详情；保留上次成功、连续失败、下次计划与脱敏错误类型 | 已完成并部署8010 |
| 三种证据分开 | API来自ready接口；采集进程来自新增worker接口，检查独立脉冲文件mtime和进程存在；目标成功来自monitoring/operations。未用数据库heartbeat_at推断进程 | 已完成 |
| 24h / 168h窗口 | 读取window接口，展示insufficient_coverage、每目标覆盖率及成功区间补集形成的断档，显式保留两个false标记 | 已完成 |
| 问答新鲜度 | 超期显示“资料截至上次成功采集；最新状态未验证”；新鲜也保留来源时间与引用版本。引用不改写；空检索不等于无漏洞 | 已完成 |
| 目录边界 | live/replay及元数据范围可见，目录行不称独立漏洞。博客、NIST、政策、POC索引不声称采正文、执行模板或完成语义关联 | 已完成 |
| 文档与演示 | 技术报告8页、PPT15页、两份PDF、新视频脚本；历史实验保留原分母，当前规模与窗口单独标注日期 | 已完成 |
| 真人及发布时效 | 正常/超期真人流程已写清，人员栏未签署；A应继续自然采集并提交发布到首次发现时延报告 | 待实际执行 |

`completed`表示目标最近轮次成功，超期按距上次成功是否超过两个配置周期计算，两者可重叠。operations读取失败时，页面显示“当前超期未验证”，不把未知状态强行计为超期。

## 正式服务实际观察

8010已重启加载本次代码，独立worker接口可读。只读快照采于**2026-10-07 09:56（上海）**，各接口顺序读取，非原子数据库快照：[原始JSON](member-b-collector-recovery-live-20261007.json)。没有触发采集、回答或云模型调用，没有在主库制造失败。

- API：ready；独立采集进程：healthy；目标最近轮次成功6/10、失败4/10、当前超期4/10。
- 1031事件；4660片段、4660/4660当前向量。这里是索引计数一致性，本轮未进行真实嵌入推理或云问答质量复验。
- 41目录行：live27、replay14。live分别为HF博客1、NIST1、政策2、Nuclei索引23；replay为HF博客14。不是41个独立漏洞。

| 当前失败目标 | 连续失败 | 类型 | 上次成功（上海） |
|---|---:|---|---|
| papers-prompt-injection | 6 | ConnectError | 10月6日18:30:55 |
| hf-blog-index | 5 | ConnectError | 10月6日20:02:12 |
| federal-register-ai-index | 6 | ConnectError | 10月6日18:32:17 |
| nuclei-cve-index | 6 | ConnectError | 10月6日18:32:19 |

这些真实网络故障已展示，属于采集链路后续恢复事项；本轮B没有伪造成功水位、清除历史失败或修改原文。采集器仍按现有计划重试。10:09（上海）的正式页面只读验证仍显示6成功/4失败/4超期，桌面1365px、手机375px均通过，无横向溢出或JS异常：[页面JSON](member-b-collector-recovery-live-pages-20261007.json)，[正式页面截图目录](../output/member-b-collector-recovery-20261007/live-screenshots/)。研究页到详情只点击1次，记录的请求全为GET。

## 历史恢复和窗口对照

10月4日[A恢复后快照](member-a-collector-recovery-postcheck-20261004.json)为10/10目标新鲜、0失败、981事件、4278/4278向量，仅支持该时点单轮恢复。[恢复前窗口](member-a-collector-recovery-before-window-20261004.json)及旧原始记录完整保留。10月7日当前失败不回写这些旧结果。

| 窗口 | 上海时间起止（约） | 全覆盖目标 / 10 | 各目标覆盖率范围 | 状态 |
|---|---|---|---|---|
| 当前24小时 | 10月6日09:56至10月7日09:56 | 1/10 | 50.00%–100.00% | insufficient_coverage |
| 当前168小时 | 9月30日09:56至10月7日09:56 | 0/10 | 23.08%–96.28% | insufficient_coverage |

覆盖按成功轮次后两个配置周期形成的区间计算。原始JSON包含每个目标成功/失败轮次数、覆盖秒数及成功区间，页面展示其补集为断档。窗口恢复后仍保留过去未覆盖区间，没有将历史失败抹去。

**process_uptime_measured=false；publication_latency_sla_proven=false。** 它们既不是连续进程在线率，也不是公告发布到首次发现时延。在A提交真实发布时延报告前，本交付不申领赛题≤24/12/6小时档位。

## 三组隔离页面验收

[脚本](../scripts/verify_member_b_recovery_pages.mjs)在独立8036进程与新SQLite测试库执行。使用合成原文、受控mtime/进程状态和模拟2维向量；没有读取正式库，没有真实云生成或嵌入推理。这些截图是页面及工程边界证据，不能当作真实来源恢复或模型准确率证据。

1. 使用SourceHTTP的MockTransport抛出连接超时，实际执行两次sync_target失败后模拟200响应恢复。页面9成功/1失败/1超期更新到10/0/0，显示ConnectTimeout与两次失败，历史失败轮次保留。
2. API就绪但来源超期，词项摘录仍返回已保存原文，答案区有完整超期文案；接口结果与持久化结果中的引用SHA-256一致。恢复后重新查询显示来源时间和版本，旧引用不改写。
3. 删除隔离向量使index_incomplete，页面显示混合当前不可用，词项查询仍返回原文引用。

附加核对375px布局、目录live/replay元数据限制及前端JS异常。[结果JSON](member-b-collector-recovery-page-tests-20261006.json)状态passed，js_errors=[]；[14张截图](../output/member-b-collector-recovery-20261006/screenshots/)含7张全页与7张局部图。文件日期沿用任务启动日10月6日，实际最后复验日期10月7日以checked_at为准。测试实例验收后停止，测试库和截图保留。

## 全量检查与格式整理

- pytest：251 passed，0失败/错误/跳过，[JUnit](member-b-collector-recovery-tests-20261007.xml)。有2条依赖弃用警告，不影响本轮结果。
- Ruff check与format --check全库通过；9份静态JS、脚本及Node测试文件语法通过；Node监测策略测试3 passed。
- 原17份非A本轮文件加当前测试/fixture共19份独立格式整理，格式前后AST相同；[清单及SHA](member-b-recovery-formatting-20261007.json)。没有改写历史模型质量报告的哈希或分数。
- Word/PDF8页与PPT/PDF15页全部渲染核对。PPT6个原生表格、1个原生图表与实际源工作簿保留，图表XML和工作簿与原文件字节一致，原讲者备注保留。结构/字体/几何检查通过，匿名XML/PDF文本检查通过。未声称实际PowerPoint设备测试或真人签收：[交付校验](member-b-collector-recovery-delivery-validation-20261007.json)。

## 新交付材料

目录：[交付说明](../output/member-b-collector-recovery-20261007/README.md)。旧2026-09-27报告/PPT/82秒视频保留为历史材料；旧20题开发回归与旧备份分母不改名为当前结果。

- [技术报告Word](../output/member-b-collector-recovery-20261007/知盾技术报告采集恢复更新版.docx)与[PDF](../output/member-b-collector-recovery-20261007/知盾技术报告采集恢复更新版.pdf)。
- [答辩PPT](../output/member-b-collector-recovery-20261007/知盾答辩采集恢复验收版.pptx)与[PDF](../output/member-b-collector-recovery-20261007/知盾答辩采集恢复验收版.pdf)。
- [视频脚本和人工排练步骤](../output/member-b-collector-recovery-20261007/演示脚本与人工排练记录.md)，记录栏保持未执行。
- [SHA-256交付清单](../output/member-b-collector-recovery-20261007/manifest.json)。

当前标签方法已按项目现行策略核对：AI类别金标v1冻结127/127（112 evidence、15 partial），见[发布说明](member-b-week6-ai-gold-release.md)。保留的可选独立双人人工流程仍0/127，不阻断现行AI标签发布，也没有冒称人工已完成。

## 复跑及剩余工作

本机依赖安装后，在项目根目录运行：

```sh
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
node --test tests/monitoring_ui.test.mjs
PYTHONPATH=src .venv/bin/python scripts/serve_member_b_recovery_fixture.py --directory tmp/member-b-recovery-NEW --port 8036
# 另开终端；使用项目已有Node或打包运行时Node及本机Chrome
node scripts/verify_member_b_recovery_pages.mjs
node scripts/verify_member_b_recovery_live.mjs
.venv/bin/python scripts/report_member_b_recovery.py --output tmp/member-b-current-snapshot.json
```

不要覆盖本轮固定证据来展示后来的状态；未来采集与截图另建日期目录和JSON文件。

剩余事项按职责：A恢复当前4个网络失败目标并继续自然运行、提交真实发布到首次发现时延报告；A/B真人各在实际设备演练正常与超期路线并本人填写记录，然后按新脚本重录视频、核对正式版式。若主办方明确要求独立人工金标，再按真实双人审核和分歧裁决执行，现有AI类别标签不得改名冒充该过程。
