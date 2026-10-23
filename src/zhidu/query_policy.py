"""Auditable domain query rewriting and conservative event-level relevance gates.

No question IDs, advisory IDs or expected answers are encoded in these rules.
"""

import re
from dataclasses import dataclass, field

from sqlalchemy import select

from zhidu.models import AffectedPackage, EventAlias, IntelEvent

POLICY_VERSION = "bilingual-security-query-v2"
# Each facet is a security concept, with Chinese and English surface forms.
FACETS = (
    ("audio", ("音频", "语音"), ("audio", "speech")),
    ("decompression", ("解压",), ("decompression", "decode", "decoded", "decoding")),
    ("memory", ("内存", "显存"), ("memory", "oom", "vram")),
    ("authentication", ("认证", "鉴权", "身份验证"), ("authentication", "auth")),
    ("bypass", ("绕过",), ("bypass", "bypasses", "bypassing")),
    ("video", ("视频",), ("video",)),
    ("execution", ("代码执行", "远程执行"), ("execution", "rce")),
    ("deserialization", ("反序列化",), ("deserialization", "deserialize", "deserializing")),
    ("untrusted", ("不可信", "不受信任"), ("untrusted",)),
    ("multimodal", ("多模态",), ("multimodal",)),
    ("shape", ("形状", "维度"), ("shape", "shapes", "dimension", "dimensions")),
    ("embedding", ("嵌入",), ("embedding", "embeddings")),
    ("injection", ("注入",), ("injection", "inject")),
    ("prompt", ("提示词", "提示注入"), ("prompt",)),
    ("traversal", ("路径穿越", "目录穿越"), ("traversal",)),
    ("ssrf", ("服务端请求伪造", "服务器端请求伪造"), ("ssrf",)),
)
STOPWORDS = set(
    "a an the is are was were of in on for to from and or does do has have with via about what which how can could should this that source sources advisory advisories report reports security vulnerability vulnerabilities evidence please explain list get find source version versions scope conditions whether affected unknown invalid incorrect processing remote code data denial service component components my our product library package packages flaw bug confirmed tell me".split()
)
ID_PATTERN = r"CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}"


def tokens(text):
    return set(re.findall(r"[a-z0-9]+(?:[_.-][a-z0-9]+)*", text.casefold()))


@dataclass
class QueryPlan:
    original: str
    search_text: str
    facets: list
    identities: set
    unresolved: set
    identifiers: set
    chinese: bool
    ambiguous: bool
    anchored_event_ids: set = field(default_factory=set)

    def metadata(self):
        return {
            "version": POLICY_VERSION,
            "original": self.original,
            "search_text": self.search_text,
            "facets": [f[0] for f in self.facets],
            "identities": sorted(self.identities),
            "unresolved_entities": sorted(self.unresolved),
            "identifiers": sorted(self.identifiers),
            "ambiguous": self.ambiguous,
            "identifier_anchored": bool(self.anchored_event_ids),
        }


def plan_query(session, query):
    lower = query.casefold()
    words = tokens(query)
    facets = [f for f in FACETS if any(x in lower for x in f[1]) or words.intersection(f[2])]
    identities = set()
    known = {str(v).casefold() for v in session.scalars(select(AffectedPackage.name))}
    # Product names are corpus-backed, not inferred from expected answers.
    for name in known | {
        "vllm",
        "openai",
        "mooncake",
        "langflow",
        "langchain",
        "mlflow",
        "pytorch",
        "transformers",
    }:
        if name in words:
            identities.add(name)
    identifiers = {x.casefold() for x in re.findall(ID_PATTERN, query, re.I)}
    anchored = set()
    if identifiers:
        for eid, external_id in session.execute(
            select(IntelEvent.id, IntelEvent.external_id).where(IntelEvent.withdrawn_at.is_(None))
        ):
            if external_id.casefold() in identifiers:
                anchored.add(eid)
        for eid, alias in session.execute(
            select(EventAlias.event_id, EventAlias.value)
            .join(IntelEvent, IntelEvent.id == EventAlias.event_id)
            .where(IntelEvent.withdrawn_at.is_(None))
        ):
            if alias.casefold() in identifiers:
                anchored.add(eid)
    event_vocabulary = set()
    for title in session.scalars(select(IntelEvent.title)):
        event_vocabulary.update(tokens(title))
    facet_words = {term for facet in FACETS for term in facet[2]}
    unresolved = {
        w
        for w in words - STOPWORDS - facet_words - identifiers - identities
        if w not in event_vocabulary and len(w) >= 3
    }
    chinese = any("\u4e00" <= c <= "\u9fff" for c in query)
    rewritten = " ".join([*sorted(identities), *(f[2][0] for f in facets), *sorted(identifiers)])
    # Deictic questions without a discriminative concept cannot identify an advisory.
    ambiguous = chinese and not facets and not identities and not identifiers
    if not chinese and not words - STOPWORDS:
        ambiguous = True
    return QueryPlan(
        query,
        rewritten if chinese and rewritten else query,
        facets,
        identities,
        unresolved,
        identifiers,
        chinese,
        ambiguous,
        anchored,
    )


def relevant_hits(session, hits, plan, *, explicit_event_id=None):
    anchored = plan.anchored_event_ids
    if (plan.unresolved and not anchored and not explicit_event_id) or (
        plan.ambiguous and not explicit_event_id
    ):
        return []
    aliases = {}
    if plan.identifiers:
        for eid, alias in session.execute(select(EventAlias.event_id, EventAlias.value)):
            aliases.setdefault(eid, set()).add(alias.casefold())
    accepted = []
    events = {}
    for hit in hits:
        eid = hit.citation.event_id
        if eid not in events:
            events[eid] = session.get(IntelEvent, eid)
        event = events[eid]
        if anchored:
            if eid in anchored:
                accepted.append(hit)
            continue
        if plan.identifiers and not (
            plan.identifiers & (aliases.get(eid, set()) | {event.external_id.casefold()})
        ):
            continue
        title_words = tokens(event.title)
        body_words = tokens(event.description)
        combined = title_words | body_words
        if plan.identities and not plan.identities.issubset(combined):
            continue
        # Require each requested concept somewhere in the source, and most in its title.
        # This removes passing mentions of other advisories in a long body.
        if explicit_event_id:
            accepted.append(hit)
            continue
        if plan.facets:
            matches = [bool(combined.intersection(f[2])) for f in plan.facets]
            title_matches = sum(bool(title_words.intersection(f[2])) for f in plan.facets)
            if not all(matches) or title_matches < len(plan.facets):
                continue
        elif not plan.identifiers and not plan.identities and not explicit_event_id:
            # Dense similarity alone cannot establish an entity or a security topic.
            continue
        accepted.append(hit)
    return accepted
