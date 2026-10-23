"""Deterministic, inspectable triage; not a calibrated ML confidence score."""

import re

RULE_VERSION = "rules-v2"

AI = re.compile(
    r"\b(llms?|large language models?|machine learning|artificial intelligence|vllm|ollama|langchain|langflow|mlflow|pytorch|hugging face)\b|大模型|人工智能|智能体",
    re.I,
)
RISK = re.compile(
    r"\b(security|vulnerab\w*|attack\w*|jailbreak\w*|poison\w*|prompt injection|adversarial|privacy|leak\w*)\b|安全|漏洞|投毒|注入|泄露",
    re.I,
)
PRODUCTS = {
    "vllm",
    "ollama",
    "langchain",
    "langchain-core",
    "transformers",
    "torch",
    "ray",
    "mlflow",
}


def classify(record: dict) -> dict:
    text = f"{record['title']} {record['description']}"
    products = sorted({p["name"].lower().replace("_", "-") for p in record["packages"]} & PRODUCTS)
    ai = sorted({m.group().lower() for m in AI.finditer(text)})
    risk = sorted({m.group().lower() for m in RISK.finditer(text)})
    if products or (ai and risk):
        label = "relevant"
    elif ai or re.search(r"prompt injection|jailbreak|提示注入|数据投毒", text, re.I):
        label = "needs_review"
    else:
        label = "unrelated"
    category = "ai_infrastructure"
    if re.search(r"prompt injection|agent|提示注入|智能体", text, re.I):
        category = "ai_application_agent"
    elif re.search(r"poison|model inversion|training data|投毒|训练数据", text, re.I):
        category = "model_data"
    elif re.search(r"supply.chain|dependency|供应链", text, re.I):
        category = "supply_chain"
    return {
        "label": label,
        "category": category,
        "rule_version": RULE_VERSION,
        "matches": {"products": products, "ai": ai, "risk": risk},
    }
