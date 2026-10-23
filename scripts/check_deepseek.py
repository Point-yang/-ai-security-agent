"""Explicit live check: one question + verified public snippets sent to DeepSeek."""

import argparse
import json

from zhidu.config import Settings
from zhidu.db import make_engine, make_sessions
from zhidu.generation import generation_status
from zhidu.rag import RagRequest, run_rag
from zhidu.semantic import LocalEncoder
from zhidu.storage import BlobStore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--question", default="vLLM 音频解压导致内存耗尽的漏洞是什么？")
    parser.add_argument("--query", default="vllm audio decompression bomb")
    parser.add_argument("--mode", choices=["lexical", "hybrid"], default="hybrid")
    args = parser.parse_args()
    settings = Settings()
    state = generation_status(settings)
    if state["status"] != "configured":
        print(json.dumps(state, ensure_ascii=False, indent=2))
        raise SystemExit(1)
    engine = make_engine(settings.database_url)
    encoder = LocalEncoder(settings)
    try:
        with make_sessions(engine)() as session:
            result = run_rag(
                session,
                BlobStore(settings.raw_dir),
                settings,
                RagRequest(
                    question=args.question, query=args.query, mode=args.mode, generation="deepseek"
                ),
                encoder,
            )
        print(
            json.dumps(
                {
                    k: result.get(k)
                    for k in ("answer", "generation", "generation_model", "cost", "elapsed_ms")
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        raise SystemExit(0 if result["generation"]["status"] == "completed" else 1)
    finally:
        encoder.close()
        engine.dispose()


if __name__ == "__main__":
    main()
