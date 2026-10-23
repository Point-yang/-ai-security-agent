# 成员 B 第一周接口交接

服务地址默认 `http://127.0.0.1:8000`。机器可读契约在 `docs/openapi.json`；字段定义以 `src/zhidu/schemas.py` 与运行中的 `/openapi.json` 为准。

2026-09-18 更新：以下五项工作已在成员 B 第一周实现，入口 `/workspace`。新增检索契约在 `src/zhidu/retrieval.py`，见 [检索接口说明](member-b-retrieval-api.md) 和 [成员 B 验收记录](member-b-week1-acceptance.md)。本文保留成员 A 原始接口语义。

## B 可以立即开展的工作

1. 用 `GET /api/v1/events` 开发情报列表，不必等待第二周采集扩展。
2. 用情报详情的 description / packages 建立第一版检索输入。
3. 用 current_revision.evidence 和原文接口开发引用侧栏。
4. 用 history 页面开发版本对比；不能把 stale/conflict 当成最新事实。
5. 用显式虚构的 `examples` 做联调，与真实知识库隔离。

## 接口清单

| 方法与路径 | 用途 |
|---|---|
| GET /health | 数据库连接和事件数量 |
| GET /api/v1/events | 分页列表；支持 q、alias、package、severity、updated_since、include_withdrawn |
| GET /api/v1/events/{id} | 当前事件、别名、影响组件、当前版本和证据 |
| GET /api/v1/events/{id}/history | 所有版本，含 stale/conflict |
| GET /api/v1/events/{id}/evidence?revision=1 | 指定版本的证据，不指定时取当前有效版本 |
| GET /api/v1/events/{id}/audit | 源数据变更和人工备注审计 |
| GET /api/v1/raw-documents/{id} | 来源 URL、哈希、获取时间、模式、content_url |
| GET /api/v1/raw-documents/{id}/content | 完整原文 JSON，响应 ETag 为内容哈希 |
| PATCH /api/v1/events/{id}/annotation | 更新人工备注/核验状态，要求管理员 key |
| GET /api/v1/sources | 已注册来源 |
| GET /api/v1/collection-runs | 最近联网采集记录 |
| GET /api/v1/sync-states | 各组件采集水位 |

分页使用 `limit`（1—100）和 `offset`，结果有 total/items。q 是标题和 GHSA 的字面子串检索，不是语义检索；CVE 用 alias 精确过滤，组件名称用 package 精确过滤。默认包含撤回记录，B 要展示撤回状态。

```javascript
const response = await fetch('http://127.0.0.1:8000/api/v1/events?package=vllm&limit=20');
const { items } = await response.json();
if (items.length) {
  const detail = await fetch(`http://127.0.0.1:8000/api/v1/events/${items[0].id}`).then(r => r.json());
  console.log(detail.current_revision.evidence);
}
```

## 更新约定

上游字段由采集器更新；B 不要直接覆盖公告标题、版本范围或原文。人工备注单独通过接口提交：

```json
{
  "expected_version": 0,
  "review_status": "in_review",
  "analyst_note": "正在核对官方补丁"
}
```

请求头 `X-Admin-Key` 必须匹配配置。expected_version 使用详情中的 annotation_version，成功后加 1；409 表示已有其他更改，需要重新读取。未配置 key 时写接口返回 503，错误 key 返回 401。可选状态：unreviewed、in_review、verified、needs_evidence。

## 不应作出的推断

- 有版本范围不等于资产已确认受影响；A 第四周会接入版本判断和配置核查。
- 有 references 不等于链接中的代码是有效 POC。
- 缺失评分不是低风险；first_patched_version 为 null 不等于不存在修复。
- 有引用不等于结论已被独立验证；当前核验标签是 source_asserted。
- 每次回答保存所引用 event_id、revision 和 raw_document_id，便于后续重查。

前端默认允许 localhost:5173 和 127.0.0.1:5173。其他地址由 A 修改 CORS 配置。读接口目前仅面向本地开发，无独立用户隔离，请勿直接暴露到公网。
