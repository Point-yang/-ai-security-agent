"""Compile declared context reads without inventing IDs, facts or coverage.

Validation is atomic: any relational feedback prevents all children. The
caller owns admission, priority, budget, framework execution and observations.
"""

from collections.abc import Mapping


def _get(value, key, default=None):
    return value.get(key, default) if isinstance(value, Mapping) else getattr(value, key, default)


def _repeated(values):
    seen, repeated = set(), []
    for value in values:
        if value in seen and value not in repeated:
            repeated.append(value)
        seen.add(value)
    return repeated


def _locatable(entry):
    return isinstance(entry, Mapping) and all(
        isinstance(entry.get(key), str) and entry[key].strip() for key in ("event_id", "field")
    )


def compile_read_plan(decision, plan, state, call_id):
    """Return bounded read_fields requests or feedback, never execute them.

    Task order follows the plan. Context order within an event/field group
    follows each task's declaration. Shared IDs are fetched once and keep all
    declaring task IDs, without treating their intent as semantic coverage.
    """
    feedback = []

    def issue(code, ids, task_id=None):
        value = {"code": code, "ids": list(ids)}
        if task_id is not None:
            value["task_id"] = task_id
        feedback.append(value)

    rows = [
        {
            "task_id": _get(row, "task_id"),
            "evidence_ids": list(_get(row, "evidence_ids", [])),
            "context_ids": list(_get(row, "context_ids", [])),
            "note": _get(row, "note", ""),
        }
        for row in _get(decision, "task_reads", [])
    ]
    if _get(decision, "action") != "read_plan":
        issue("read_plan_action_required", [])
        return {"children": [], "feedback": feedback, "task_reads": rows}
    if not isinstance(call_id, str) or not call_id:
        issue("invalid_parent_call_id", [])
    task_order = [_get(task, "task_id") for task in _get(plan, "tasks", [])]
    requested_tasks = [row["task_id"] for row in rows]
    missing = [task_id for task_id in task_order if task_id not in requested_tasks]
    unknown = [task_id for task_id in dict.fromkeys(requested_tasks) if task_id not in task_order]
    repeated = _repeated(requested_tasks)
    if missing:
        issue("missing_task_ids", missing)
    if unknown:
        issue("unknown_task_ids", unknown)
    if repeated:
        issue("duplicate_task_ids", repeated)
    declared_tasks = _get(decision, "task_ids", [])
    unknown_declared = [
        task_id for task_id in dict.fromkeys(declared_tasks) if task_id not in task_order
    ]
    if unknown_declared:
        issue("unknown_task_ids", unknown_declared)
    if _repeated(declared_tasks):
        issue("duplicate_task_ids", _repeated(declared_tasks))
    context_index = _get(state, "context_index", {})
    evidence = _get(state, "evidence", {})
    context_index = context_index if isinstance(context_index, Mapping) else {}
    evidence = evidence if isinstance(evidence, Mapping) else {}
    selected_contexts = set()
    for row in rows:
        valid = []
        for name, registry in (("evidence_ids", evidence), ("context_ids", context_index)):
            ids = row[name]
            duplicate_ids = _repeated(ids)
            unknown_ids = [identity for identity in dict.fromkeys(ids) if identity not in registry]
            invalid_ids = [
                identity
                for identity in dict.fromkeys(ids)
                if identity in registry and not _locatable(registry[identity])
            ]
            if duplicate_ids:
                issue("duplicate_" + name, duplicate_ids, row["task_id"])
            if unknown_ids:
                issue("unknown_" + name, unknown_ids, row["task_id"])
            if invalid_ids:
                issue("unlocatable_" + name, invalid_ids, row["task_id"])
            accepted = [
                identity
                for identity in ids
                if identity in registry and _locatable(registry[identity])
            ]
            valid.extend(accepted)
            if name == "context_ids":
                selected_contexts.update(accepted)
        if not valid:
            issue("task_has_no_observed_or_selected_ids", [row["task_id"]], row["task_id"])
    if not selected_contexts:
        issue("no_context_selected", [])
    if feedback:
        return {"children": [], "feedback": feedback, "task_reads": rows}

    by_task = {row["task_id"]: row for row in rows}
    ordered_rows = [by_task[task_id] for task_id in task_order]
    groups, context_tasks = {}, {}
    for row in ordered_rows:
        for identity in row["context_ids"]:
            declaring_tasks = context_tasks.setdefault(identity, [])
            if row["task_id"] not in declaring_tasks:
                declaring_tasks.append(row["task_id"])
            entry = context_index[identity]
            ids = groups.setdefault((entry["event_id"], entry["field"]), [])
            if identity not in ids:
                ids.append(identity)
    children = []
    for (event_id, field), ids in groups.items():
        for start in range(0, len(ids), 4):
            selected = ids[start : start + 4]
            index = len(children)
            selected_tasks = {
                task_id for identity in selected for task_id in context_tasks[identity]
            }
            children.append(
                {
                    "child_id": f"{call_id}:tool:{index}",
                    "tool": "read_fields",
                    "arguments": {
                        "event_id": event_id,
                        "fields": [field],
                        "context": "section",
                        "context_ids": list(selected),
                    },
                    "task_ids": [task_id for task_id in task_order if task_id in selected_tasks],
                    "context_task_ids": {
                        identity: list(context_tasks[identity]) for identity in selected
                    },
                    "request_index": index,
                }
            )
    return {"children": children, "feedback": [], "task_reads": ordered_rows}
