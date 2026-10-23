"""Adapters preserve JSON pointers into the exact upstream response, including papers."""

import copy
import json
from dataclasses import dataclass
from datetime import UTC, datetime

from zhidu.classification import classify


@dataclass(frozen=True)
class SourceSpec:
    id: str
    name: str
    category: str
    base_url: str


SOURCES = {
    "github-advisories": SourceSpec(
        "github-advisories",
        "GitHub Global Security Advisories",
        "vulnerability_database",
        "https://api.github.com/advisories",
    ),
    "vllm-vendor": SourceSpec(
        "vllm-vendor",
        "vLLM 官方仓库安全公告",
        "vendor_advisory",
        "https://api.github.com/repos/vllm-project/vllm/security-advisories",
    ),
    "nvd": SourceSpec(
        "nvd",
        "NVD CVE API",
        "vulnerability_database",
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
    ),
    "cisa-kev": SourceSpec(
        "cisa-kev",
        "CISA 已知被利用漏洞目录",
        "government_alert",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    ),
    "crossref": SourceSpec(
        "crossref",
        "Crossref AI 安全论文元数据",
        "academic_metadata",
        "https://api.crossref.org/works",
    ),
    "hf-blog": SourceSpec(
        "hf-blog",
        "Hugging Face 博客元数据",
        "security_blog",
        "https://huggingface.co/api/blog",
    ),
    "nist-ai-rmf": SourceSpec(
        "nist-ai-rmf",
        "NIST AI RMF DOI 元数据",
        "technical_standard",
        "https://api.crossref.org/works/10.6028/NIST.AI.100-1",
    ),
    "federal-register-ai": SourceSpec(
        "federal-register-ai",
        "Federal Register AI 政策索引",
        "policy_registry",
        "https://www.federalregister.gov/api/v1/documents.json",
    ),
    "nuclei-cves": SourceSpec(
        "nuclei-cves",
        "ProjectDiscovery 检测模板索引",
        "poc_metadata",
        "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main/cves.json",
    ),
}


@dataclass
class PreparedRecord:
    normalized: dict
    pointer: str
    fields: dict[str, str]


def resolve_pointer(data, pointer):
    for token in pointer.split("/")[1:]:
        token = token.replace("~1", "/").replace("~0", "~")
        data = data[int(token)] if isinstance(data, list) else data[token]
    return data


def timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    # NVD documents UTC timestamps without a suffix; this is a source-specific conversion.
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def base_record(identity, title, description, published, updated, url, kind="vulnerability"):
    return dict(
        external_id=identity,
        aliases=[identity],
        kind=kind,
        title=title,
        description=description,
        severity="unknown",
        source_url=url,
        published_at=timestamp(published).isoformat(),
        source_updated_at=timestamp(updated).isoformat(),
        withdrawn_at=None,
        packages=[],
        cvss=None,
        cwes=[],
        references=[],
        verification="source_asserted",
    )


def prepare(source_id: str, content: bytes) -> tuple[list[PreparedRecord], int]:
    from zhidu.ingest import normalize
    from zhidu.schemas import AdvisoryInput

    data = json.loads(content)
    records = []
    if source_id in {"github-advisories", "vllm-vendor"}:
        rows = data if isinstance(data, list) else [data]
        for i, raw in enumerate(rows):
            adapted = raw
            if source_id == "vllm-vendor":
                adapted = copy.deepcopy(raw)
                for package in adapted.get("vulnerabilities", []):
                    package["package"]["name"] = package["package"].get("name") or "unknown"
                    package["package"]["ecosystem"] = (
                        package["package"].get("ecosystem") or "unknown"
                    )
                    package["vulnerable_version_range"] = (
                        package.get("vulnerable_version_range") or "unknown"
                    )
            record = normalize(AdvisoryInput.model_validate(adapted))
            if source_id == "vllm-vendor":
                # A patched version range is not a single first_patched_version.
                record["vendor_patched_ranges"] = [
                    v.get("patched_versions") for v in raw.get("vulnerabilities", [])
                ]
            ptr = f"/{i}" if isinstance(data, list) else ""
            mapping = {
                "external_id": "ghsa_id",
                "cve_id": "cve_id",
                "title": "summary",
                "description": "description",
                "severity": "severity",
                "packages": "vulnerabilities",
                "published_at": "published_at",
                "source_updated_at": "updated_at",
                "withdrawn_at": "withdrawn_at",
                "references": "references",
                "cwes": "cwes",
                "cvss": "cvss_severities" if raw.get("cvss_severities") else "cvss",
            }
            records.append(
                PreparedRecord(
                    record, ptr, {k: f"{ptr}/{v}" for k, v in mapping.items() if v in raw}
                )
            )
    elif source_id == "nvd":
        rows = data["vulnerabilities"]
        for i, item in enumerate(rows):
            cve = item["cve"]
            descriptions = cve["descriptions"]
            d = next((j for j, x in enumerate(descriptions) if x["lang"] == "en"), 0)
            ptr = f"/vulnerabilities/{i}/cve"
            record = base_record(
                cve["id"],
                cve["id"],
                descriptions[d]["value"],
                cve["published"],
                cve["lastModified"],
                f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
            )
            record["cvss"] = cve.get("metrics") or None
            record["references"] = [r["url"] for r in cve.get("references", [])]
            if cve.get("vulnStatus") == "Rejected":
                record["withdrawn_at"] = record["source_updated_at"]
            fields = {
                "external_id": f"{ptr}/id",
                "cve_id": f"{ptr}/id",
                "title": f"{ptr}/id",
                "description": f"{ptr}/descriptions/{d}/value",
                "published_at": f"{ptr}/published",
                "source_updated_at": f"{ptr}/lastModified",
            }
            if "metrics" in cve:
                fields["cvss"] = f"{ptr}/metrics"
            # NVD 2.0 carries CNA version facts in cve.affected[].affectedData[].
            # Keep each product object separately addressable instead of flattening
            # its statuses into a guessed SemVer interval.
            authorities = cve.get("affected", [])
            for authority_index, authority in enumerate(
                authorities if isinstance(authorities, list) else []
            ):
                if not isinstance(authority, dict):
                    continue
                if authority.get("source") is not None:
                    fields[f"nvd_affected_data_{authority_index}_source"] = (
                        f"{ptr}/affected/{authority_index}/source"
                    )
                products = authority.get("affectedData", [])
                for product_index, _product in enumerate(
                    products if isinstance(products, list) else []
                ):
                    if not isinstance(_product, dict):
                        continue
                    product_pointer = (
                        f"{ptr}/affected/{authority_index}/affectedData/{product_index}"
                    )
                    for key in (
                        "vendor",
                        "product",
                        "collectionURL",
                        "packageName",
                        "packageURL",
                        "defaultStatus",
                        "cpes",
                    ):
                        if key in _product:
                            fields[f"nvd_affected_data_{authority_index}_{product_index}_{key}"] = (
                                f"{product_pointer}/{key}"
                            )
                    versions = _product.get("versions", [])
                    for version_index, _version in enumerate(
                        versions if isinstance(versions, list) else []
                    ):
                        if not isinstance(_version, dict):
                            continue
                        fields[
                            f"nvd_affected_data_{authority_index}_{product_index}_version_{version_index}"
                        ] = f"{product_pointer}/versions/{version_index}"
            records.append(PreparedRecord(record, ptr, fields))
    elif source_id == "cisa-kev":
        rows = data["vulnerabilities"]
        for i, raw in enumerate(rows):
            ptr = f"/vulnerabilities/{i}"
            record = base_record(
                raw["cveID"],
                raw["vulnerabilityName"],
                raw["shortDescription"],
                raw["dateAdded"],
                data["dateReleased"],
                SOURCES[source_id].base_url,
                "exploitation_alert",
            )
            record["required_action"] = raw.get("requiredAction")
            record["due_date"] = raw.get("dueDate")
            record["publication_semantics"] = "catalog_date_added_not_vulnerability_disclosure"
            fields = {
                "external_id": f"{ptr}/cveID",
                "cve_id": f"{ptr}/cveID",
                "title": f"{ptr}/vulnerabilityName",
                "description": f"{ptr}/shortDescription",
                "published_at": f"{ptr}/dateAdded",
                "source_updated_at": "/dateReleased",
            }
            if "requiredAction" in raw:
                fields["required_action"] = f"{ptr}/requiredAction"
            records.append(PreparedRecord(record, ptr, fields))
    elif source_id == "crossref":
        rows = data["message"]["items"]
        for i, raw in enumerate(rows):
            ptr = f"/message/items/{i}"
            date = raw.get("published", {}).get("date-parts", [[]])[0]
            # If no publication date exists, retain Crossref registration time explicitly.
            published = (
                datetime(*((date + [1, 1])[:3]), tzinfo=UTC).isoformat()
                if date
                else raw["created"]["date-time"]
            )
            record = base_record(
                raw["DOI"].lower(),
                raw["title"][0],
                raw.get("abstract", ""),
                published,
                raw["indexed"]["date-time"],
                f"https://doi.org/{raw['DOI']}",
                "paper",
            )
            record["metadata_only"] = True
            record["publication_precision"] = {1: "year", 2: "month", 3: "day"}.get(
                len(date), "registration_fallback"
            )
            fields = {
                "external_id": f"{ptr}/DOI",
                "title": f"{ptr}/title/0",
                "source_updated_at": f"{ptr}/indexed/date-time",
            }
            fields["published_at"] = (
                f"{ptr}/published/date-parts/0" if date else f"{ptr}/created/date-time"
            )
            if "abstract" in raw:
                fields["description"] = f"{ptr}/abstract"
            records.append(PreparedRecord(record, ptr, fields))
    else:
        raise ValueError("unsupported source")
    return records, len(rows)


def relevant_records(records):
    return [r for r in records if classify(r.normalized)["label"] != "unrelated"]
