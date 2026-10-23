import argparse
import json
from datetime import datetime
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy.exc import SQLAlchemyError

from zhidu.collector import collect
from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.ingest import ingest_document
from zhidu.locking import WriterBusy, writer_lock
from zhidu.models import now_utc
from zhidu.monitor import load_targets, resilient_cycle
from zhidu.observability import configure_logging
from zhidu.storage import BlobStore


def main():
    configure_logging()
    parser = argparse.ArgumentParser(description="知盾：成员 A 数据采集与维护")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db", help="将数据库迁移到最新版本")
    sub.add_parser("reclassify", help="按当前规则重算已有事件相关性，不修改原始证据或版本")
    sub.add_parser("index-sync", help="按当前版本和相关性标签对账持久化检索索引")
    enricher = sub.add_parser("enrich", help="重建实体、版本范围、CVSS/CPE 与质量标记")
    enricher.add_argument("--output", type=Path, help="可选：写出本次富化质量报告 JSON")
    evidence_audit = sub.add_parser(
        "evidence-audit", help="复验全部历史版本的原文哈希、字段指针和值"
    )
    evidence_audit.add_argument("--output", type=Path)
    operations_evaluator = sub.add_parser(
        "ops-eval", help="保存采集、富化、完整性与运行健康评测快照"
    )
    operations_evaluator.add_argument("--output", type=Path)
    enrichment_evaluator = sub.add_parser(
        "enrichment-eval", help="运行成员 A 固定富化断言回归集（非人工盲测）"
    )
    enrichment_evaluator.add_argument(
        "--config",
        type=Path,
        default=Path("config/member-a-week6-enrichment-eval.json"),
    )
    enrichment_evaluator.add_argument("--output", type=Path)
    doctor_parser = sub.add_parser("doctor", help="检查中断任务、原文完整性和派生状态")
    doctor_parser.add_argument("--repair", action="store_true", help="恢复中断状态并重建派生数据")
    doctor_parser.add_argument("--output", type=Path)
    window = sub.add_parser(
        "monitoring-window", help="按历史运行记录计算来源新鲜度覆盖，非实时 SLA"
    )
    window.add_argument("--hours", type=int, choices=range(1, 169), default=24)
    window.add_argument("--output", type=Path, required=True)
    asset_import = sub.add_parser("asset-import", help="导入 CycloneDX JSON 并扫描来源声明的影响")
    asset_import.add_argument("path", type=Path)
    asset_import.add_argument("--asset-name", required=True)
    asset_import.add_argument("--environment", default="unknown")
    asset_import.add_argument(
        "--criticality", choices=["low", "medium", "high", "critical"], default="medium"
    )
    asset_scan = sub.add_parser("asset-scan", help="按当前富化结果重建资产影响判断")
    asset_scan.add_argument("--asset-id")
    asset_reporter = sub.add_parser("asset-report", help="导出含证据与限制声明的可复现资产报告")
    asset_reporter.add_argument("asset_id")
    asset_reporter.add_argument("--output", type=Path)
    asset_evaluator = sub.add_parser("asset-eval", help="运行成员 B 资产影响固定题集")
    asset_evaluator.add_argument(
        "--config", type=Path, default=Path("config/member-b-week4-asset-eval.json")
    )
    asset_evaluator.add_argument("--output", type=Path)
    conversation_evaluator = sub.add_parser(
        "conversation-eval", help="运行成员 B 多轮、多跳和动态补证固定题集"
    )
    conversation_evaluator.add_argument(
        "--config",
        type=Path,
        default=Path("config/member-b-week5-conversation-eval.json"),
    )
    conversation_evaluator.add_argument("--output", type=Path)
    sub.add_parser("compare-sources", help="按共享 CVE 重建多来源字段比较")
    evaluator = sub.add_parser("retrieval-eval", help="运行成员 B 固定问题集检索与引用评测")
    evaluator.add_argument(
        "--config", type=Path, default=Path("config/member-b-retrieval-eval.json")
    )
    evaluator.add_argument("--output", type=Path)
    answer = sub.add_parser("answer-extractive", help="生成可引用证据包并写入服务端审计表")
    answer.add_argument("question")
    answer.add_argument("--query")
    answer.add_argument("--pool", choices=["formal", "candidate"], default="formal")
    answer.add_argument("--origin", choices=["live", "replay"], default="live")
    answer.add_argument("--asset-id")
    answer.add_argument("--event-id")
    answer.add_argument("--limit", type=int, choices=range(1, 11), default=5)
    importer = sub.add_parser("import-json", help="导入 GHSA JSON，明确标记为离线回放")
    importer.add_argument("path", type=Path)
    importer.add_argument("--source-url", default="offline://ghsa-replay")
    catalog_import = sub.add_parser(
        "catalog-import", help="离线回放博客、标准、政策或 POC 元数据，不执行模板"
    )
    catalog_import.add_argument("path", type=Path)
    catalog_import.add_argument(
        "--source",
        choices=["hf-blog", "nist-ai-rmf", "federal-register-ai", "nuclei-cves"],
        required=True,
    )
    catalog_import.add_argument("--source-url", default="offline://catalog-replay")
    catalog_audit = sub.add_parser("catalog-audit", help="复验扩展来源的字节、定位与元数据指纹")
    catalog_audit.add_argument("--output", type=Path, required=True)
    fetch = sub.add_parser("collect", help="联网采集指定组件的 GitHub 安全公告")
    fetch.add_argument("--package", default="vllm")
    fetch.add_argument(
        "--ecosystem",
        default="pip",
        choices=[
            "pip",
            "npm",
            "go",
            "maven",
            "rust",
            "other",
            "rubygems",
            "nuget",
            "composer",
            "erlang",
            "actions",
            "pub",
            "swift",
        ],
    )
    fetch.add_argument("--since", help="ISO 时间；首次默认最近 30 天，后续使用持久化水位")
    fetch.add_argument("--max-pages", type=int, default=10)
    monitor = sub.add_parser("monitor", help="按持久化计划运行多源监测；Ctrl+C 停止")
    monitor.add_argument("--config", type=Path, default=Path("config/sources.json"))
    monitor.add_argument("--once", action="store_true", help="只运行一轮到期任务")
    monitor.add_argument("--force", action="store_true", help="忽略本轮到期时间（仅可配 --once）")
    monitor.add_argument("--target", help="只运行指定任务 ID")
    monitor.add_argument(
        "--sync-semantic",
        action="store_true",
        help="使用已准备的本地模型对账语义索引（不下载模型）",
    )
    serve = sub.add_parser("serve", help="运行查询 API 和验收页面")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    exporter = sub.add_parser("export-openapi", help="导出成员 B 使用的 OpenAPI 契约")
    exporter.add_argument("path", type=Path, default=Path("docs/openapi.json"), nargs="?")
    args = parser.parse_args()
    settings = Settings()
    try:
        if args.command == "init-db":
            root = Path.cwd()
            if not (root / "alembic.ini").is_file():
                root = Path(__file__).resolve().parents[2]
            config = Config(str(root / "alembic.ini"))
            config.set_main_option("script_location", str(root / "migrations"))
            command.upgrade(config, "head")
            print(json.dumps({"status": "ready", "schema": "head"}))
            return
        if args.command == "serve":
            import uvicorn

            uvicorn.run("zhidu.api:create_app", factory=True, host=args.host, port=args.port)
            return
        if args.command == "export-openapi":
            from zhidu.api import create_app

            app = create_app(settings)
            args.path.parent.mkdir(parents=True, exist_ok=True)
            args.path.write_text(json.dumps(app.openapi(), ensure_ascii=False, indent=2) + "\n")
            app.state.engine.dispose()
            print(str(args.path))
            return
        if args.command == "monitor":
            import time
            from contextlib import ExitStack

            from zhidu.worker_health import worker_pulse

            if args.force and not args.once:
                raise ValueError("--force requires --once")
            targets = load_targets(args.config)
            if args.target:
                targets = [t for t in targets if t.id == args.target]
                if not targets:
                    raise ValueError("unknown target ID")
            engine = make_engine(settings.database_url)
            sessions = make_sessions(engine)
            try:
                stack = ExitStack()
                stack.enter_context(worker_pulse(settings.raw_dir.parent / "collector.heartbeat"))
                last_semantic_attempt = 0.0
                while True:
                    results = resilient_cycle(sessions, settings, targets, force=args.force)
                    semantic_result = None
                    if args.sync_semantic and (
                        results or time.monotonic() - last_semantic_attempt >= 300
                    ):
                        from zhidu.semantic_maintenance import maintain_semantics

                        semantic_result = maintain_semantics(sessions, settings)
                        last_semantic_attempt = time.monotonic()
                    if results or args.once:
                        print(
                            json.dumps(
                                {"results": results, "semantic": semantic_result},
                                ensure_ascii=False,
                                indent=2,
                            ),
                            flush=True,
                        )
                    if args.once:
                        if any(r["status"] != "completed" for r in results) or (
                            semantic_result and semantic_result["status"] != "completed"
                        ):
                            raise SystemExit(1)
                        break
                    time.sleep(30 if any(r.get("target") == "scheduler" for r in results) else 5)
            except KeyboardInterrupt:
                print('{"status":"stopped"}')
            finally:
                stack.close()
                engine.dispose()
            return
        engine = make_engine(settings.database_url)
        sessions = make_sessions(engine)
        try:
            if args.command == "monitoring-window":
                from zhidu.monitoring_experiment import window_report

                with sessions() as session:
                    result = window_report(
                        session, load_targets(settings.monitor_config), hours=args.hours
                    )
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
            elif args.command == "reclassify":
                from sqlalchemy import select

                from zhidu.indexing import sync_index
                from zhidu.ingest import save_triage
                from zhidu.models import EventRevision, IntelEvent

                with writer_lock(settings.database_url), sessions.begin() as session:
                    rows = session.execute(
                        select(IntelEvent, EventRevision).join(
                            EventRevision,
                            (EventRevision.event_id == IntelEvent.id)
                            & (EventRevision.number == IntelEvent.revision),
                        )
                    ).all()
                    for event, revision in rows:
                        save_triage(session, event.id, revision.normalized)
                    session.flush()
                    result = {
                        "classified": len(rows),
                        "source_revisions_changed": 0,
                        "index": sync_index(session),
                    }
            elif args.command == "index-sync":
                from zhidu.indexing import sync_index

                with writer_lock(settings.database_url), sessions.begin() as session:
                    result = sync_index(session)
            elif args.command == "enrich":
                from zhidu.enrichment import sync_enrichments

                with writer_lock(settings.database_url), sessions.begin() as session:
                    result = sync_enrichments(session, BlobStore(settings.raw_dir))
                if args.output:
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    args.output.write_text(
                        json.dumps(result, ensure_ascii=False, indent=2, default=str) + "\n"
                    )
            elif args.command == "evidence-audit":
                from zhidu.evidence import audit_all_evidence

                with sessions() as session:
                    result = audit_all_evidence(session, BlobStore(settings.raw_dir))
                if args.output:
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    args.output.write_text(
                        json.dumps(result, ensure_ascii=False, indent=2, default=str) + "\n"
                    )
            elif args.command == "ops-eval":
                from zhidu.operations import (
                    operational_evaluation_view,
                    operational_snapshot,
                    save_operational_evaluation,
                )

                targets = load_targets(settings.monitor_config)
                with writer_lock(settings.database_url), sessions.begin() as session:
                    snapshot = operational_snapshot(
                        session, BlobStore(settings.raw_dir), targets, verify_raw=True
                    )
                    result = operational_evaluation_view(
                        save_operational_evaluation(session, snapshot)
                    )
                if args.output:
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    args.output.write_text(
                        json.dumps(result, ensure_ascii=False, indent=2, default=str) + "\n"
                    )
            elif args.command == "enrichment-eval":
                from zhidu.enrichment_evaluation import (
                    enrichment_evaluation_view,
                    evaluate_enrichment,
                    load_enrichment_suite,
                )

                suite = load_enrichment_suite(args.config)
                with writer_lock(settings.database_url), sessions.begin() as session:
                    result = enrichment_evaluation_view(
                        evaluate_enrichment(session, BlobStore(settings.raw_dir), suite)
                    )
                    result["status"] = (
                        "passed"
                        if all(
                            result[key] == 1.0
                            for key in (
                                "assertion_accuracy",
                                "expected_fact_recall",
                                "evidence_verifiable_rate",
                            )
                        )
                        else "failed"
                    )
                if args.output:
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    args.output.write_text(
                        json.dumps(result, ensure_ascii=False, indent=2, default=str) + "\n"
                    )
            elif args.command == "doctor":
                from zhidu.operations import doctor

                targets = load_targets(settings.monitor_config)
                if args.repair:
                    with writer_lock(settings.database_url), sessions.begin() as session:
                        result = doctor(
                            session,
                            BlobStore(settings.raw_dir),
                            targets,
                            repair=True,
                        )
                else:
                    with sessions() as session:
                        result = doctor(
                            session,
                            BlobStore(settings.raw_dir),
                            targets,
                            repair=False,
                        )
                if args.output:
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    args.output.write_text(
                        json.dumps(result, ensure_ascii=False, indent=2, default=str) + "\n"
                    )
            elif args.command == "asset-import":
                from zhidu.asset_matching import import_cyclonedx

                with writer_lock(settings.database_url), sessions.begin() as session:
                    asset, details = import_cyclonedx(
                        session,
                        args.path.read_bytes(),
                        asset_name=args.asset_name,
                        environment=args.environment,
                        criticality=args.criticality,
                    )
                    result = {"asset_id": asset.id, "asset_name": asset.name, **details}
            elif args.command == "asset-scan":
                from zhidu.asset_matching import scan_assets

                with writer_lock(settings.database_url), sessions.begin() as session:
                    result = scan_assets(session, args.asset_id)
            elif args.command == "asset-report":
                from zhidu.asset_matching import asset_report

                with sessions() as session:
                    result = asset_report(session, args.asset_id)
                if args.output:
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    args.output.write_text(
                        json.dumps(result, ensure_ascii=False, indent=2, default=str) + "\n"
                    )
            elif args.command == "asset-eval":
                from zhidu.asset_evaluation import (
                    asset_evaluation_view,
                    evaluate_assets,
                    load_asset_suite,
                )

                suite = load_asset_suite(args.config)
                with writer_lock(settings.database_url), sessions.begin() as session:
                    result = asset_evaluation_view(
                        evaluate_assets(session, BlobStore(settings.raw_dir), suite)
                    )
                if args.output:
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    args.output.write_text(
                        json.dumps(result, ensure_ascii=False, indent=2, default=str) + "\n"
                    )
            elif args.command == "conversation-eval":
                from zhidu.conversation_evaluation import (
                    conversation_evaluation_view,
                    evaluate_conversations,
                    load_conversation_suite,
                )

                suite = load_conversation_suite(args.config)
                with writer_lock(settings.database_url), sessions.begin() as session:
                    result = conversation_evaluation_view(
                        evaluate_conversations(session, BlobStore(settings.raw_dir), suite)
                    )
                if args.output:
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    args.output.write_text(
                        json.dumps(result, ensure_ascii=False, indent=2, default=str) + "\n"
                    )
            elif args.command == "compare-sources":
                from zhidu.comparisons import sync_comparisons

                with writer_lock(settings.database_url), sessions.begin() as session:
                    result = sync_comparisons(session)
            elif args.command == "retrieval-eval":
                from zhidu.evaluation import evaluate, evaluation_view, load_suite

                suite = load_suite(args.config)
                with writer_lock(settings.database_url), sessions.begin() as session:
                    result = evaluation_view(evaluate(session, BlobStore(settings.raw_dir), suite))
                if args.output:
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    args.output.write_text(
                        json.dumps(result, ensure_ascii=False, indent=2, default=str) + "\n"
                    )
            elif args.command == "answer-extractive":
                from zhidu.answers import (
                    ExtractiveAnswerRequest,
                    audit_view,
                    make_extractive_answer,
                )

                request = ExtractiveAnswerRequest(
                    question=args.question,
                    query=args.query,
                    pool=args.pool,
                    origin=args.origin,
                    asset_id=args.asset_id,
                    event_id=args.event_id,
                    limit=args.limit,
                )
                with writer_lock(settings.database_url), sessions.begin() as session:
                    result = audit_view(make_extractive_answer(session, request))
            elif args.command == "import-json":
                with writer_lock(settings.database_url), sessions.begin() as session:
                    result = ingest_document(
                        session,
                        BlobStore(settings.raw_dir),
                        args.path.read_bytes(),
                        args.source_url,
                        now_utc(),
                        "replay",
                    )
                result["origin"] = "replay"
            elif args.command == "catalog-import":
                from zhidu.catalog import ingest_catalog

                with writer_lock(settings.database_url), sessions.begin() as session:
                    result = ingest_catalog(
                        session,
                        BlobStore(settings.raw_dir),
                        args.path.read_bytes(),
                        source_id=args.source,
                        url=args.source_url,
                        fetched_at=now_utc(),
                        origin="replay",
                    )
                result["origin"] = "replay"
            elif args.command == "catalog-audit":
                from zhidu.catalog import audit_catalog

                with sessions() as session:
                    result = audit_catalog(session, BlobStore(settings.raw_dir))
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
            else:
                since = (
                    datetime.fromisoformat(args.since.replace("Z", "+00:00"))
                    if args.since
                    else None
                )
                with writer_lock(settings.database_url):
                    result = collect(
                        sessions, settings, args.package, args.ecosystem, since, args.max_pages
                    )
            print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
            if result.get("status") in {"partial", "failed", "degraded"}:
                raise SystemExit(1)
        finally:
            engine.dispose()
    except (LookupError, ValueError, OSError, WriterBusy) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False))
        raise SystemExit(1) from None
    except SQLAlchemyError:
        print(
            json.dumps(
                {
                    "status": "error",
                    "error": "database operation failed; run init-db and check configuration",
                }
            )
        )
        raise SystemExit(1) from None
