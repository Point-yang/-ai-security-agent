"""CycloneDX inventory ingestion and conservative source-asserted exposure matching."""

import hashlib
import json
import re
from urllib.parse import unquote

from packaging.version import InvalidVersion, Version
from sqlalchemy import delete, select

from zhidu.models import (
    Asset,
    AssetComponent,
    AssetExposure,
    EventEnrichment,
    IntelEvent,
    now_utc,
)

PURL = re.compile(r"^pkg:([^/]+)/(.+?)(?:@([^?#]+))?(?:[?#].*)?$")
ECOSYSTEMS = {
    "pypi": "pip",
    "npm": "npm",
    "golang": "go",
    "maven": "maven",
    "cargo": "rust",
    "gem": "rubygems",
    "nuget": "nuget",
    "composer": "composer",
}
SUPPORTED_OPERATORS = {"<", "<=", ">", ">=", "=", "=="}
ASSET_REPORT_VERSION = "asset-report-v1"
MATCH_POLICY_VERSION = "conservative-match-v2"
ASSET_REPORT_LIMITATIONS = [
    "affected 只表示 SBOM 组件匹配来源声明的身份与版本条件，不代表漏洞已复现。",
    "not_affected 只针对当前来源记录的范围，不能外推为资产安全。",
    "unknown 保留来源表达式或版本比较无法确定的原因。",
    "没有身份匹配不会生成 exposure，也不能解释为不受影响。",
    "来源记录、SBOM 或富化规则变化后必须重新扫描。",
]


def normalize_package(ecosystem: str, name: str) -> tuple[str, str]:
    ecosystem = ECOSYSTEMS.get(ecosystem.casefold(), ecosystem.casefold())
    name = unquote(name).casefold()
    if ecosystem == "pip":
        name = re.sub(r"[-_.]+", "-", name)
    return ecosystem, name


def parse_purl(value: str) -> dict | None:
    match = PURL.match(value)
    if not match:
        return None
    package_type, path, version = match.groups()
    decoded_path = unquote(path)
    # A namespace is part of the package identity for these ecosystems. Keeping it
    # avoids collapsing e.g. npm @scope-a/core and @scope-b/core into one package.
    if package_type.casefold() in {"npm", "maven", "composer", "golang"}:
        name = decoded_path
    else:
        name = decoded_path.rsplit("/", 1)[-1]
    ecosystem, name = normalize_package(package_type, name)
    return {"ecosystem": ecosystem, "name": name, "version": unquote(version or "")}


def parse_cyclonedx(content: bytes) -> tuple[dict, list[dict]]:
    if len(content) > 10 * 1024 * 1024:
        raise ValueError("SBOM exceeds 10 MiB limit")
    data = json.loads(content)
    if (
        not isinstance(data, dict)
        or data.get("bomFormat") != "CycloneDX"
        or not isinstance(data.get("components"), list)
    ):
        raise ValueError("only CycloneDX JSON with a components array is supported")
    if len(data.get("components", [])) > 10000:
        raise ValueError("SBOM contains more than 10000 components")
    rows = []
    for index, item in enumerate(data.get("components", [])):
        if not isinstance(item, dict):
            raise ValueError(f"component {index} must be an object")
        purl = item.get("purl")
        for field, maximum in (
            ("purl", 1000),
            ("cpe", 1000),
            ("name", 500),
            ("version", 200),
            ("bom-ref", 500),
        ):
            value = item.get(field)
            if value is not None and (not isinstance(value, str) or len(value) > maximum):
                raise ValueError(f"component {index}: invalid {field}")
        parsed = parse_purl(purl) if purl else None
        if purl and not parsed:
            raise ValueError(f"component {index}: invalid purl")
        if (
            parsed
            and parsed["version"]
            and item.get("version")
            and parsed["version"] != item["version"]
        ):
            raise ValueError(f"component {index}: purl and component versions disagree")
        name = (parsed or {}).get("name") or str(item.get("name") or "").strip()
        version = (parsed or {}).get("version") or str(item.get("version") or "").strip()
        # CycloneDX `group` is a namespace, not a package ecosystem. Without a
        # purl we keep the ecosystem unknown and only allow an explicit CPE match.
        ecosystem = (parsed or {}).get("ecosystem") or "unknown"
        ecosystem, name = normalize_package(ecosystem, name)
        if not name or not version:
            raise ValueError(f"component {index} requires name and version")
        rows.append(
            {
                "ecosystem": ecosystem,
                "name": name,
                "version": version,
                "purl": purl,
                "cpe": item.get("cpe"),
                "bom_ref": item.get("bom-ref"),
                "component_type": str(item.get("type") or "library"),
            }
        )
    metadata = {
        "format": "CycloneDX",
        "spec_version": str(data.get("specVersion") or "unknown"),
        "serial_number": data.get("serialNumber"),
        "components": len(rows),
        "sha256": hashlib.sha256(content).hexdigest(),
    }
    return metadata, rows


def import_cyclonedx(
    session,
    content: bytes,
    *,
    asset_name: str,
    environment: str = "unknown",
    criticality: str = "medium",
) -> tuple[Asset, dict]:
    metadata, components = parse_cyclonedx(content)
    asset = session.scalar(select(Asset).where(Asset.name == asset_name))
    created = asset is None
    if asset is None:
        asset = Asset(
            name=asset_name,
            environment=environment,
            criticality=criticality,
            sbom_format=metadata["format"],
            sbom_version=metadata["spec_version"],
            sbom_sha256=metadata["sha256"],
        )
        session.add(asset)
        session.flush()
    else:
        session.execute(delete(AssetExposure).where(AssetExposure.asset_id == asset.id))
        session.execute(delete(AssetComponent).where(AssetComponent.asset_id == asset.id))
    asset.environment = environment
    asset.criticality = criticality
    asset.sbom_format = metadata["format"]
    asset.sbom_version = metadata["spec_version"]
    asset.sbom_sha256 = metadata["sha256"]
    asset.imported_at = now_utc()
    session.add_all(AssetComponent(asset_id=asset.id, **row) for row in components)
    session.flush()
    scan = scan_assets(session, asset.id)
    return asset, {"created": created, **metadata, "scan": scan}


def _version(value: str) -> Version | None:
    try:
        return Version(value)
    except InvalidVersion:
        return None


def evaluate_range(version: str, parsed: dict | None) -> tuple[str, str]:
    if not parsed or parsed.get("status") != "parsed":
        return "unknown", "source version expression is not safely parsed"
    clauses = parsed.get("clauses") or []
    if not clauses:
        return "unknown", "source version expression has no comparable clauses"
    current = _version(version)
    if current is None:
        return "unknown", "asset version is not comparable"
    results = []
    for clause in clauses:
        operator = clause.get("operator")
        boundary = _version(str(clause.get("version") or ""))
        if operator not in SUPPORTED_OPERATORS or boundary is None:
            return "unknown", "version operator or boundary is unsupported"
        results.append(
            {
                "<": current < boundary,
                "<=": current <= boundary,
                ">": current > boundary,
                ">=": current >= boundary,
                "=": current == boundary,
                "==": current == boundary,
            }[operator]
        )
    return (
        ("affected", "all source comparators match")
        if all(results)
        else (
            "not_affected",
            "asset version falls outside the source range",
        )
    )


def _cpe_parts(value: str | None) -> list[str] | None:
    if not value:
        return None
    parts = value.casefold().split(":")
    return parts if len(parts) >= 6 and parts[:2] == ["cpe", "2.3"] else None


def evaluate_cpe(component: AssetComponent, match: dict) -> tuple[str, str] | None:
    asset_cpe = _cpe_parts(component.cpe)
    criteria = _cpe_parts(match.get("criteria"))
    if not asset_cpe or not criteria or asset_cpe[2:5] != criteria[2:5]:
        return None
    # A non-vulnerable leaf can describe a required environment in an NVD
    # applicability expression; it cannot establish this asset is unaffected.
    if match.get("vulnerable") is not True:
        return "unknown", "CPE leaf is an environment condition, not a vulnerability exclusion"
    if (
        len(criteria) != 13
        or len(asset_cpe) != 13
        or "\\" in str(component.cpe)
        or "\\" in str(match.get("criteria"))
    ):
        return "unknown", "complex or malformed CPE identity requires full CPE name matching"
    if any(value not in {"*"} for value in criteria[6:]):
        return "unknown", "CPE has additional platform constraints not evaluated by this matcher"
    if asset_cpe[5] not in {"*", component.version.casefold()}:
        return "unknown", "asset CPE version disagrees with the component version"
    if criteria[5] == "-":
        return "unknown", "CPE not-applicable version is not a wildcard"
    numeric_versions = [component.version] + [
        match[key]
        for key in (
            "version_start_including",
            "version_start_excluding",
            "version_end_including",
            "version_end_excluding",
        )
        if match.get(key)
    ]
    if criteria[5] != "*":
        numeric_versions.append(criteria[5])
    if not all(re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value) for value in numeric_versions):
        return "unknown", "non-numeric CPE versions require product-specific ordering"
    version = _version(component.version)
    if version is None:
        return "unknown", "asset CPE identity matches but its version is not comparable"
    criteria_version = criteria[5]
    if criteria_version not in {"*", "-"}:
        expected = _version(criteria_version)
        if expected is None:
            return "unknown", "source CPE version is not comparable"
        matched = version == expected
    else:
        matched = True
    boundaries = [
        ("version_start_including", ">="),
        ("version_start_excluding", ">"),
        ("version_end_including", "<="),
        ("version_end_excluding", "<"),
    ]
    for field, operator in boundaries:
        if not match.get(field):
            continue
        result, reason = evaluate_range(
            component.version,
            {"status": "parsed", "clauses": [{"operator": operator, "version": match[field]}]},
        )
        if result == "unknown":
            return result, reason
        matched = matched and result == "affected"
    return (
        ("affected", "asset CPE and source version conditions match")
        if matched
        else (
            "not_affected",
            "asset CPE identity matches but version falls outside the source condition",
        )
    )


def evaluate_component(component, event, enrichment) -> dict | None:
    evaluations = []
    component_identity = normalize_package(component.ecosystem, component.name)
    for item in enrichment.version_ranges:
        identity = normalize_package(
            str(item.get("ecosystem") or "unknown"), str(item.get("package") or "")
        )
        if identity != component_identity or item.get("source_kind") != "affected_package":
            continue
        status, reason = (
            evaluate_range(component.version, item.get("vulnerable"))
            if component_identity[0] == "pip"
            else ("unknown", "ecosystem-specific version semantics are not implemented")
        )
        evaluations.append(
            {
                "status": status,
                "method": "package_version",
                "reason": reason,
                "source": item,
            }
        )
    for match in enrichment.cpe_matches:
        result = evaluate_cpe(component, match)
        if result:
            if match.get("requires_configuration_evaluation", True):
                result = (
                    "unknown",
                    "CPE parent logic requires full configuration evaluation or re-enrichment",
                )
            status, reason = result
            evaluations.append(
                {"status": status, "method": "cpe_version", "reason": reason, "source": match}
            )
    if not evaluations:
        return None
    # Multiple package rows are alternative affected intervals (OR), not
    # contradictory assertions. Unknown branches must never prove exclusion.
    by_method = {}
    for item in evaluations:
        by_method.setdefault(item["method"], set()).add(item["status"])
    aggregates = {
        method: (
            "affected"
            if "affected" in values
            else "unknown"
            if "unknown" in values
            else "not_affected"
        )
        for method, values in by_method.items()
    }
    if "unknown" in aggregates.values():
        status, reason = "unknown", "at least one source condition cannot be safely determined"
        method = "+".join(sorted(by_method))
    elif len(set(aggregates.values())) > 1:
        status, reason = "unknown", "package and CPE source conditions disagree"
        method = "conflicting_conditions"
    else:
        status = next(iter(aggregates.values()))
        reason = next(item["reason"] for item in evaluations if item["status"] == status)
        method = "+".join(sorted({item["method"] for item in evaluations}))
    return {
        "status": status,
        "match_method": method,
        "reason": reason,
        "evidence": [
            {
                "event_id": event.id,
                "revision_id": enrichment.revision_id,
                "source_id": event.source_id,
                "external_id": event.external_id,
                "verification": "source_asserted_asset_comparison",
                "matching_policy_version": MATCH_POLICY_VERSION,
                **item,
            }
            for item in evaluations
        ],
    }


def scan_assets(session, asset_id: str | None = None) -> dict:
    component_stmt = select(AssetComponent)
    if asset_id:
        component_stmt = component_stmt.where(AssetComponent.asset_id == asset_id)
    components = session.scalars(component_stmt).all()
    rows = session.execute(
        select(IntelEvent, EventEnrichment)
        .join(EventEnrichment, EventEnrichment.event_id == IntelEvent.id)
        .where(IntelEvent.withdrawn_at.is_(None))
    ).all()
    existing_stmt = select(AssetExposure)
    if asset_id:
        existing_stmt = existing_stmt.where(AssetExposure.asset_id == asset_id)
    existing = {(row.component_id, row.event_id): row for row in session.scalars(existing_stmt)}
    active = set()
    created = updated = unchanged = 0
    for component in components:
        for event, enrichment in rows:
            result = evaluate_component(component, event, enrichment)
            if result is None:
                continue
            key = (component.id, event.id)
            active.add(key)
            values = {
                "asset_id": component.asset_id,
                "revision_id": enrichment.revision_id,
                "enrichment_schema_version": enrichment.schema_version,
                **result,
            }
            row = existing.get(key)
            if row is None:
                session.add(AssetExposure(component_id=component.id, event_id=event.id, **values))
                created += 1
            elif all(getattr(row, field) == value for field, value in values.items()):
                unchanged += 1
            else:
                for field, value in values.items():
                    setattr(row, field, value)
                row.evaluated_at = now_utc()
                updated += 1
    stale = set(existing) - active
    removed = 0
    if stale:
        stale_ids = [existing[key].id for key in stale]
        removed = session.execute(
            delete(AssetExposure).where(AssetExposure.id.in_(stale_ids))
        ).rowcount
    session.flush()
    counts = {"affected": 0, "not_affected": 0, "unknown": 0}
    count_stmt = select(AssetExposure)
    if asset_id:
        count_stmt = count_stmt.where(AssetExposure.asset_id == asset_id)
    for row in session.scalars(count_stmt):
        counts[row.status] = counts.get(row.status, 0) + 1
    return {
        "components": len(components),
        "created": created,
        "updated": updated,
        "unchanged": unchanged,
        "removed": removed,
        "status_counts": counts,
        "scope": "source_asserted_component_version_comparison",
    }


def asset_view(session, asset: Asset) -> dict:
    components = session.scalars(
        select(AssetComponent)
        .where(AssetComponent.asset_id == asset.id)
        .order_by(AssetComponent.name)
    ).all()
    exposures = session.scalars(
        select(AssetExposure).where(AssetExposure.asset_id == asset.id)
    ).all()
    counts = {"affected": 0, "not_affected": 0, "unknown": 0}
    for row in exposures:
        counts[row.status] += 1
    return {
        "id": asset.id,
        "name": asset.name,
        "environment": asset.environment,
        "criticality": asset.criticality,
        "sbom_format": asset.sbom_format,
        "sbom_version": asset.sbom_version,
        "sbom_sha256": asset.sbom_sha256,
        "imported_at": asset.imported_at,
        "component_count": len(components),
        "exposure_counts": counts,
    }


def exposure_view(session, row: AssetExposure) -> dict:
    component = session.get(AssetComponent, row.component_id)
    event = session.get(IntelEvent, row.event_id)
    return {
        "id": row.id,
        "asset_id": row.asset_id,
        "component": {
            "id": component.id,
            "ecosystem": component.ecosystem,
            "name": component.name,
            "version": component.version,
            "purl": component.purl,
            "cpe": component.cpe,
        },
        "event": {
            "id": event.id,
            "source_id": event.source_id,
            "external_id": event.external_id,
            "title": event.title,
            "severity": event.severity,
        },
        "revision_id": row.revision_id,
        "enrichment_schema_version": row.enrichment_schema_version,
        "status": row.status,
        "match_method": row.match_method,
        "reason": row.reason,
        "evidence": row.evidence,
        "evaluated_at": row.evaluated_at,
        "independent_verification": False,
    }


def asset_report(session, asset_id: str) -> dict:
    asset = session.get(Asset, asset_id)
    if asset is None:
        raise LookupError("asset not found")
    rows = session.scalars(
        select(AssetExposure)
        .where(AssetExposure.asset_id == asset_id)
        .order_by(AssetExposure.status, AssetExposure.event_id)
    ).all()
    scan_time = max((row.evaluated_at for row in rows), default=None)
    return {
        "report_version": ASSET_REPORT_VERSION,
        "generated_at": now_utc(),
        "asset": asset_view(session, asset),
        "sbom_sha256": asset.sbom_sha256,
        "enrichment_schema_versions": sorted({row.enrichment_schema_version for row in rows}),
        "scan_time": scan_time,
        "scope": "source_asserted_component_version_comparison",
        "independent_verification": False,
        "limitations": ASSET_REPORT_LIMITATIONS,
        "exposures": [exposure_view(session, row) for row in rows],
    }
