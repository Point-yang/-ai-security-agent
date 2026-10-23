"""Configured standard chat/tool adapters; never forward another provider's key."""

from dataclasses import dataclass
from urllib.parse import urlsplit

from zhidu.generation import endpoint


class ModelConfigurationError(ValueError):
    pass


def generation_target(settings, profile):
    if profile.provider == "deepseek":
        key = (
            settings.agent_model_api_key.get_secret_value()
            or settings.deepseek_api_key.get_secret_value()
        )
        url = endpoint(settings)
    else:
        key = settings.agent_model_api_key.get_secret_value().strip()
        url = profile.base_url + "/chat/completions"
        if profile.provider == "ollama" and not key:
            key = "ollama-local"
    if not key.strip():
        raise ModelConfigurationError("missing_api_key")
    return url, key


@dataclass(frozen=True)
class ModelProfile:
    provider: str
    model: str
    base_url: str

    def public(self):
        return {
            "provider": self.provider,
            "model": self.model,
            "protocol": "chat_completions_tools",
        }


def model_profile(settings):
    provider = settings.agent_model_provider
    if provider == "deepseek":
        endpoint(settings)
        return ModelProfile(
            provider,
            settings.agent_model_name or settings.deepseek_model,
            settings.deepseek_base_url.rstrip("/"),
        )
    model = settings.agent_model_name
    base = settings.agent_model_base_url or (
        "http://127.0.0.1:11434/v1" if provider == "ollama" else ""
    )
    parts = urlsplit(base)
    if (
        not model
        or not parts.hostname
        or parts.username
        or parts.password
        or parts.query
        or parts.fragment
        or (
            parts.scheme != "https"
            and not (parts.scheme == "http" and parts.hostname in {"localhost", "127.0.0.1", "::1"})
        )
    ):
        raise ModelConfigurationError("invalid_model_configuration")
    return ModelProfile(provider, model, base.rstrip("/"))


def make_chat_model(settings, client):
    profile = model_profile(settings)
    options = {
        "model": profile.model,
        "http_client": client,
        "max_retries": 0,
        "temperature": settings.llm_temperature,
        "timeout": min(settings.deepseek_timeout_seconds, settings.agent_deadline_seconds),
        "max_tokens": settings.deepseek_max_tokens,
        "model_kwargs": {"parallel_tool_calls": False},
    }
    if profile.provider == "deepseek":
        from langchain_deepseek import ChatDeepSeek

        key = (
            settings.agent_model_api_key.get_secret_value()
            or settings.deepseek_api_key.get_secret_value()
        )
        if not key.strip():
            raise ModelConfigurationError("missing_api_key")
        return ChatDeepSeek(
            **options,
            api_key=key,
            api_base=profile.base_url,
            extra_body={"thinking": {"type": "disabled"}},
        )
    from langchain_openai import ChatOpenAI

    key = settings.agent_model_api_key.get_secret_value().strip()
    if not key and profile.provider != "ollama":
        raise ModelConfigurationError("missing_api_key")
    return ChatOpenAI(
        **options, api_key=key or "ollama-local", base_url=profile.base_url, use_responses_api=False
    )
