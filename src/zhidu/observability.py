"""Bounded process metrics and structured logs without request content or secrets."""

import json
import logging
import threading
from collections import defaultdict

from zhidu.models import now_utc

logger = logging.getLogger("zhidu.operations")


def log_event(event: str, **fields):
    logger.info(json.dumps({"timestamp": now_utc().isoformat(), "event": event, **fields}))


def configure_logging():
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False


class RequestMetrics:
    """Aggregate by registered route template; never by URL, user or asset ID."""

    bounds = (0.1, 0.5, 1.0, 2.5, 5.0, 10.0)

    def __init__(self):
        self.lock = threading.Lock()
        self.rows = defaultdict(lambda: {"count": 0, "seconds": 0.0, "buckets": [0] * 6})

    def observe(self, route, status, duration):
        with self.lock:
            row = self.rows[(route, status)]
            row["count"] += 1
            row["seconds"] += duration
            for i, bound in enumerate(self.bounds):
                row["buckets"][i] += duration <= bound

    def render(self):
        lines = [
            "# HELP zhidu_http_request_duration_seconds Request duration in this API process.",
            "# TYPE zhidu_http_request_duration_seconds histogram",
        ]
        with self.lock:
            for (route, status), row in sorted(self.rows.items()):
                labels = f'route={json.dumps(route)},status="{status}"'
                for bound, count in zip(self.bounds, row["buckets"], strict=True):
                    lines.append(
                        f'zhidu_http_request_duration_seconds_bucket{{{labels},le="{bound}"}} {count}'
                    )
                lines.extend(
                    [
                        f'zhidu_http_request_duration_seconds_bucket{{{labels},le="+Inf"}} {row["count"]}',
                        f"zhidu_http_request_duration_seconds_count{{{labels}}} {row['count']}",
                        f"zhidu_http_request_duration_seconds_sum{{{labels}}} {row['seconds']:.6f}",
                    ]
                )
        return lines
