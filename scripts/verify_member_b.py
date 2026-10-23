"""Read-only integration check against the configured database and stored raw documents."""

import argparse
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from zhidu.api import create_app


def main():
    parser = argparse.ArgumentParser(description="核对成员 B 检索片段与原始证据的一致性")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    raw_cache = {}
    event_count = chunk_count = withdrawn_count = 0
    origins = {}
    with TestClient(create_app()) as client:

        def get(path, **params):
            response = client.get(path, params=params)
            response.raise_for_status()
            return response

        offset = 0
        while True:
            page = get("/api/v1/events", limit=100, offset=offset).json()
            if not page["items"]:
                break
            for event in page["items"]:
                chunks = get(f"/api/v1/retrieval/events/{event['id']}").json()
                assert chunks, event["id"]
                detail = get(f"/api/v1/events/{event['id']}").json()
                revision = detail["current_revision"]
                assert revision["disposition"] == "current"
                event_count += 1
                withdrawn_count += bool(detail["withdrawn_at"])
                origin = chunks[0]["citation"]["origin"]
                origins[origin] = origins.get(origin, 0) + 1
                for chunk in chunks:
                    cite = chunk["citation"]
                    assert cite["event_id"] == event["id"]
                    assert cite["revision"] == detail["revision"]
                    assert cite["raw_document_id"] == revision["raw_document_id"]
                    assert chunk["withdrawn"] == bool(detail["withdrawn_at"])
                    if cite["raw_document_id"] not in raw_cache:
                        raw = get(f"/api/v1/raw-documents/{cite['raw_document_id']}/content")
                        metadata = get(f"/api/v1/raw-documents/{cite['raw_document_id']}").json()
                        digest = hashlib.sha256(raw.content).hexdigest()
                        assert raw.headers["etag"] == f'"{digest}"'
                        raw_cache[cite["raw_document_id"]] = (raw.json(), digest, metadata)
                    value, digest, metadata = raw_cache[cite["raw_document_id"]]
                    assert cite["sha256"] == digest == metadata["sha256"]
                    assert cite["origin"] == metadata["origin"]
                    for token in cite["json_pointer"].split("/")[1:]:
                        token = token.replace("~1", "/").replace("~0", "~")
                        value = value[int(token)] if isinstance(value, list) else value[token]
                    text = (
                        value
                        if isinstance(value, str)
                        else json.dumps(value, ensure_ascii=False, sort_keys=True)
                    )
                    assert text[chunk["start"] : chunk["end"]] == chunk["text"]
                    chunk_count += 1
            offset += len(page["items"])
        query = get("/api/v1/retrieval/search", q="decompression").json()
        assert all(hit["citation"]["origin"] == "live" for hit in query["items"])
    result = {
        "checked_at": datetime.now(UTC).isoformat(),
        "status": "passed",
        "events": event_count,
        "withdrawn_events": withdrawn_count,
        "origins": origins,
        "chunks_verified": chunk_count,
        "raw_documents_verified": len(raw_cache),
        "sample_query": "decompression",
        "sample_query_hits": query["total"],
        "note": "Only citation/content consistency; not independent vulnerability verification or recall evaluation.",
    }
    output = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output)
    print(output, end="")


if __name__ == "__main__":
    main()
