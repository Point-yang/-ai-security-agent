"""Select an explicitly configured Agent implementation for API and conversations."""


def run_agent(session, store, settings, body, encoder, **kwargs):
    backend = body.agent_backend or settings.agent_backend
    if backend == "team":
        from zhidu.agent_team import run_agent_team

        return run_agent_team(session, store, settings, body, encoder, **kwargs)
    if backend in {"workflow", "auto"}:
        from zhidu.agent_workflow import run_workflow_agent

        return run_workflow_agent(session, store, settings, body, encoder, **kwargs)
    if backend == "langchain":
        from zhidu.langchain_agent import run_langchain_agent

        return run_langchain_agent(session, store, settings, body, encoder, **kwargs)
    from zhidu.agent_rag import run_agent as legacy_agent

    return legacy_agent(session, store, settings, body, encoder, **kwargs)
