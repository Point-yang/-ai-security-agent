"""Launch the bundled code against the restored database, with network collection disabled."""

import argparse
import os
import subprocess
import sys
from pathlib import Path

from zhidu.backup import restored_settings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--port", type=int, default=8020)
    parser.add_argument(
        "--enable-local-answers",
        action="store_true",
        help="Use ZHIDU_DEMO_ADMIN_KEY for writes to the restored copy only",
    )
    args = parser.parse_args()
    root = args.directory.resolve()
    settings = restored_settings(root)
    if not 1024 <= args.port <= 65535:
        parser.error("use a port between 1024 and 65535")
    if not (root / "code/src/zhidu/api.py").is_file():
        parser.error("restored code missing")
    demo_key = os.environ.get("ZHIDU_DEMO_ADMIN_KEY", "") if args.enable_local_answers else ""
    if args.enable_local_answers and not demo_key:
        parser.error("set an independent ZHIDU_DEMO_ADMIN_KEY before enabling local answers")
    env = {k: v for k, v in os.environ.items() if not k.startswith("ZHIDU_")}
    env.update(
        {
            "PYTHONPATH": str(root / "code/src"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "HF_HUB_OFFLINE": "1",
            "ZHIDU_DATABASE_URL": settings.database_url,
            "ZHIDU_RAW_DIR": str(settings.raw_dir),
            "ZHIDU_MONITOR_CONFIG": str(settings.monitor_config),
            "ZHIDU_RAG_CONFIG": str(settings.rag_config),
            "ZHIDU_EMBEDDING_MODEL": settings.embedding_model,
            "ZHIDU_EMBEDDING_CACHE": str(settings.embedding_cache),
            "ZHIDU_EMBEDDING_MANIFEST": str(settings.embedding_manifest),
            "ZHIDU_HUMAN_REVIEW_DIR": str(settings.human_review_dir),
            "ZHIDU_GITHUB_TOKEN": "",
            "ZHIDU_ADMIN_KEY": demo_key,
            "ZHIDU_LLM_PROVIDER": "extractive",
            "ZHIDU_DEEPSEEK_API_KEY": "",
        }
    )
    print(
        f"Restored local demo: http://127.0.0.1:{args.port}/workspace (answer writes: {bool(demo_key)})",
        flush=True,
    )
    raise SystemExit(
        subprocess.call(
            [
                sys.executable,
                "-m",
                "zhidu",
                "serve",
                "--host",
                "127.0.0.1",
                "--port",
                str(args.port),
            ],
            cwd=root / "code",
            env=env,
        )
    )


if __name__ == "__main__":
    main()
