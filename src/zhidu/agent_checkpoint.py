"""Durable graph state plus reply replay, avoiding blind retries of paid calls."""

import hashlib
import json
import os
import sqlite3
import threading


class RecoveryBlocked(ValueError):
    pass


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)


class RecoveryStore:
    def __init__(self, path, thread_id, manifest, *, require_existing=False):
        if require_existing and not path.exists():
            raise RecoveryBlocked("checkpoint_missing")
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, timeout=10, check_same_thread=False)
        os.chmod(path, 0o600)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.lock = threading.RLock()
        self.thread_id, self.replayed_models, self.replayed_tools = thread_id, 0, 0
        self._closed, self._final_calls = False, []
        with self.conn:
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS agent_context (thread_id TEXT PRIMARY KEY, manifest_hash TEXT NOT NULL, snapshot TEXT)"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS agent_model_replies (thread_id TEXT, step INTEGER, input_hash TEXT NOT NULL, status TEXT NOT NULL, response TEXT, audit TEXT, http_requests INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(thread_id,step))"
            )
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS agent_tool_replies (thread_id TEXT, input_hash TEXT, content TEXT NOT NULL, artifact TEXT NOT NULL, PRIMARY KEY(thread_id,input_hash))"
            )
            digest = hashlib.sha256(encode(manifest).encode()).hexdigest()
            row = self.conn.execute(
                "SELECT manifest_hash FROM agent_context WHERE thread_id=?", (thread_id,)
            ).fetchone()
            failure = (
                "checkpoint_missing"
                if row is None and require_existing
                else "checkpoint_configuration_changed"
                if row and row[0] != digest
                else None
            )
            if not failure:
                self.conn.execute(
                    "INSERT OR IGNORE INTO agent_context VALUES (?,?,NULL)", (thread_id, digest)
                )
        if failure:
            self._closed = True
            self.conn.close()
            raise RecoveryBlocked(failure)

    def close(self):
        if not self._closed:
            self._final_calls = self.calls()
            self._closed = True
            self.conn.close()

    def context(self):
        with self.lock:
            row = self.conn.execute(
                "SELECT snapshot FROM agent_context WHERE thread_id=?", (self.thread_id,)
            ).fetchone()
            return json.loads(row[0]) if row and row[0] else None

    def save_context(self, snapshot):
        with self.lock, self.conn:
            self.conn.execute(
                "UPDATE agent_context SET snapshot=? WHERE thread_id=?",
                (encode(snapshot), self.thread_id),
            )

    def tool_reply(self, name, arguments, call_identity=None):
        key = hashlib.sha256(encode([call_identity, name, arguments]).encode()).hexdigest()
        with self.lock:
            row = self.conn.execute(
                "SELECT content,artifact FROM agent_tool_replies WHERE thread_id=? AND input_hash=?",
                (self.thread_id, key),
            ).fetchone()
            if row:
                self.replayed_tools += 1
                return row[0], json.loads(row[1])
        return None

    def save_tool(self, name, arguments, content, artifact, snapshot, call_identity=None):
        key = hashlib.sha256(encode([call_identity, name, arguments]).encode()).hexdigest()
        with self.lock, self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO agent_tool_replies VALUES (?,?,?,?)",
                (self.thread_id, key, content, encode(artifact)),
            )
            self.conn.execute(
                "UPDATE agent_context SET snapshot=? WHERE thread_id=?",
                (encode(snapshot), self.thread_id),
            )

    def model_reply(self, step, input_hash, answer_type=None):
        with self.lock, self.conn:
            row = self.conn.execute(
                "SELECT input_hash,status,response FROM agent_model_replies WHERE thread_id=? AND step=?",
                (self.thread_id, step),
            ).fetchone()
            if row:
                if row[0] != input_hash:
                    raise RecoveryBlocked("checkpoint_model_input_changed")
                if row[1] != "completed":
                    raise RecoveryBlocked("model_request_outcome_unknown")
                from langchain.agents.middleware.types import ModelResponse
                from langchain_core.messages import messages_from_dict

                from zhidu.agent_state import AgentAnswer

                answer_type = answer_type or AgentAnswer

                value = json.loads(row[2])
                self.replayed_models += 1
                return ModelResponse(
                    result=messages_from_dict(value["messages"]),
                    structured_response=answer_type.model_validate(value["answer"])
                    if value["answer"]
                    else None,
                )
            self.conn.execute(
                "INSERT INTO agent_model_replies(thread_id,step,input_hash,status) VALUES (?,?,?,?)",
                (self.thread_id, step, input_hash, "inflight"),
            )
        return None

    def role_step(self, call_id, limit):
        """Stable graph-node identity, including replies saved before checkpoint."""
        with self.lock, self.conn:
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS agent_role_steps (thread_id TEXT, call_id TEXT, step INTEGER, PRIMARY KEY(thread_id,call_id), UNIQUE(thread_id,step))"
            )
            row = self.conn.execute(
                "SELECT step FROM agent_role_steps WHERE thread_id=? AND call_id=?",
                (self.thread_id, call_id),
            ).fetchone()
            if row:
                return row[0]
            step = self.conn.execute(
                "SELECT COALESCE(MAX(step),0)+1 FROM agent_role_steps WHERE thread_id=?",
                (self.thread_id,),
            ).fetchone()[0]
            if step > limit:
                raise ValueError("agent_budget_exceeded")
            self.conn.execute(
                "INSERT INTO agent_role_steps VALUES (?,?,?)", (self.thread_id, call_id, step)
            )
            return step

    def role_reply_status(self, call_id):
        with self.lock:
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS agent_role_steps (thread_id TEXT, call_id TEXT, step INTEGER, PRIMARY KEY(thread_id,call_id), UNIQUE(thread_id,step))"
            )
            row = self.conn.execute(
                "SELECT r.status FROM agent_role_steps s JOIN agent_model_replies r ON r.thread_id=s.thread_id AND r.step=s.step WHERE s.thread_id=? AND s.call_id=?",
                (self.thread_id, call_id),
            ).fetchone()
            return row[0] if row else None

    def record_http(self, step):
        with self.lock, self.conn:
            self.conn.execute(
                "UPDATE agent_model_replies SET http_requests=http_requests+1 WHERE thread_id=? AND step=?",
                (self.thread_id, step),
            )

    def save_model(self, step, response, audit):
        from langchain_core.messages import messages_to_dict

        value = {
            "messages": messages_to_dict(response.result),
            "answer": response.structured_response.model_dump()
            if response.structured_response
            else None,
        }
        with self.lock, self.conn:
            self.conn.execute(
                "UPDATE agent_model_replies SET status='completed',response=?,audit=? WHERE thread_id=? AND step=?",
                (encode(value), encode(audit), self.thread_id, step),
            )

    def failed_model(self, step, audit):
        with self.lock, self.conn:
            self.conn.execute(
                "UPDATE agent_model_replies SET status='uncertain',audit=? WHERE thread_id=? AND step=? AND status!='completed'",
                (encode(audit), self.thread_id, step),
            )

    def calls(self):
        if self._closed:
            return self._final_calls
        with self.lock:
            rows = self.conn.execute(
                "SELECT step,status,audit,http_requests FROM agent_model_replies WHERE thread_id=? ORDER BY step",
                (self.thread_id,),
            ).fetchall()
        return [
            {
                "attempt": step,
                "status": status,
                **(json.loads(audit) if audit else {}),
                "http_requests": requests,
            }
            for step, status, audit, requests in rows
        ]


def model_input_hash(request):
    from langchain_core.messages import messages_to_dict

    messages = messages_to_dict(request.messages)
    for message in messages:
        message["data"].pop("id", None)
    value = {
        "messages": messages,
        "system": request.system_message.content,
        "tools": sorted(
            t.name if hasattr(t, "name") else t["function"]["name"] for t in request.tools
        ),
        "response_format_type": type(request.response_format).__name__,
        "model_settings": {k: v for k, v in request.model_settings.items() if k != "timeout"},
        "tool_choice": request.tool_choice,
    }
    return hashlib.sha256(encode(value).encode()).hexdigest()
