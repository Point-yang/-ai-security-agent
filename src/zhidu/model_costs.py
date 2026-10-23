"""Auditable token-price calculations, not an invoice or a currency converter.

Missing usage/prices stay unknown. Unknown cache splits or time bands produce
bounds rather than treating every input token as a cache miss. Durable replay
receipts count once by billing_id/provider_response_id (not by model step).
"""

import copy
import json
import math
import re
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

DEFAULT_PRICE_PATH = Path(__file__).resolve().parents[2] / "config" / "model-pricing.json"
_MILLION = Decimal(1_000_000)
_RATE_KEYS = ("input_cache_hit", "input_cache_miss", "output")


def _datetime(value: Any) -> datetime | None:
    try:
        if isinstance(value, datetime):
            result = value
        elif type(value) in (int, float):
            return datetime.fromtimestamp(value, UTC)
        elif isinstance(value, str):
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:
            return None
        return result.astimezone(UTC) if result.tzinfo else None
    except (ValueError, OverflowError, OSError):
        return None


def _decimal(value: Any) -> Decimal:
    if isinstance(value, bool):
        raise ValueError("invalid_rate")
    try:
        result = Decimal(str(value))
    except (InvalidOperation, ValueError):
        raise ValueError("invalid_rate") from None
    if not result.is_finite() or result < 0:
        raise ValueError("invalid_rate")
    return result


def _money(value: Decimal | None) -> tuple[float | None, str | None]:
    if value is None:
        return None, None
    approximate = float(value)
    return approximate if math.isfinite(approximate) else None, format(value, "f")


def validate_price_catalog(catalog: Mapping[str, Any]) -> None:
    """Validate a public/operator catalog before registering or using it."""
    if (
        type(catalog.get("schema_version")) is not int
        or catalog["schema_version"] != 1
        or not isinstance(catalog.get("prices"), list)
    ):
        raise ValueError("invalid_price_catalog")
    for entry in catalog["prices"]:
        if not isinstance(entry, dict):
            raise ValueError("invalid_price_entry")
        if any(
            not isinstance(entry.get(k), str) or not entry[k]
            for k in ("provider", "model", "currency", "source_url", "checked_at", "effective_from")
        ):
            raise ValueError("incomplete_price_provenance")
        if not re.fullmatch(r"[A-Z]{3}", entry["currency"]):
            raise ValueError("invalid_currency")
        start, end = _datetime(entry["effective_from"]), _datetime(entry.get("effective_to"))
        if start is None or _datetime(entry["checked_at"]) is None:
            raise ValueError("invalid_price_date")
        if entry.get("effective_to") is not None and (end is None or end <= start):
            raise ValueError("invalid_price_interval")
        aliases = entry.get("aliases", [])
        if not isinstance(aliases, list) or any(not isinstance(x, str) or not x for x in aliases):
            raise ValueError("invalid_model_aliases")
        rule = entry.get("pricing_rule", "flat")
        expected = {"flat"} if rule == "flat" else {"peak", "offpeak"}
        rates = entry.get("rates_per_million")
        if (
            rule not in {"flat", "deepseek_peak_offpeak"}
            or not isinstance(rates, dict)
            or set(rates) != expected
        ):
            raise ValueError("invalid_price_rule")
        for rate in rates.values():
            if not isinstance(rate, dict) or set(rate) != set(_RATE_KEYS):
                raise ValueError("invalid_rate_fields")
            for key in _RATE_KEYS:
                _decimal(rate[key])


def register_price(catalog: Mapping[str, Any], entry: Mapping[str, Any]) -> dict:
    """Return a validated copy with an operator entry; never mutate files implicitly.

    Later entries override equally dated entries. Operators save the returned
    catalog to an explicit path and configure that path for the service/eval.
    """
    result = copy.deepcopy(dict(catalog))
    result.setdefault("prices", []).append(copy.deepcopy(dict(entry)))
    validate_price_catalog(result)
    return result


def load_price_catalog(price_path: str | Path | None = None) -> dict:
    with Path(price_path or DEFAULT_PRICE_PATH).open(encoding="utf-8") as file:
        catalog = json.load(file)
    validate_price_catalog(catalog)
    return catalog


def _normalise_usage(usage: Any) -> tuple[dict, list[str]]:
    if not isinstance(usage, Mapping):
        return {}, ["missing_usage"]
    keys = {
        "prompt_tokens": ("prompt_tokens", "input_tokens"),
        "completion_tokens": ("completion_tokens", "output_tokens"),
        "prompt_cache_hit_tokens": ("prompt_cache_hit_tokens",),
        "prompt_cache_miss_tokens": ("prompt_cache_miss_tokens",),
        "total_tokens": ("total_tokens",),
    }
    normalised = {}
    for target, aliases in keys.items():
        values = [usage[k] for k in aliases if k in usage and usage[k] is not None]
        if any(type(v) is not int or v < 0 for v in values) or len(set(values)) > 1:
            return {}, ["invalid_usage"]
        normalised[target] = values[0] if values else None
    details = usage.get("prompt_tokens_details") or usage.get("input_token_details") or {}
    if isinstance(details, Mapping):
        cached = details.get("cached_tokens", details.get("cache_read"))
        if cached is not None:
            if (
                type(cached) is not int
                or cached < 0
                or normalised["prompt_cache_hit_tokens"] not in (None, cached)
            ):
                return {}, ["invalid_usage"]
            normalised["prompt_cache_hit_tokens"] = cached
    prompt, output = normalised["prompt_tokens"], normalised["completion_tokens"]
    if prompt is None or output is None:
        return normalised, ["missing_input_or_output_tokens"]
    if normalised["total_tokens"] not in (None, prompt + output):
        return normalised, ["inconsistent_total_tokens"]
    normalised["total_tokens"] = prompt + output
    hit, miss = normalised["prompt_cache_hit_tokens"], normalised["prompt_cache_miss_tokens"]
    if (hit is not None and hit > prompt) or (miss is not None and miss > prompt):
        return normalised, ["inconsistent_cache_tokens"]
    if hit is not None and miss is not None and hit + miss != prompt:
        return normalised, ["inconsistent_cache_tokens"]
    if hit is not None:
        normalised["prompt_cache_miss_tokens"] = prompt - hit
    elif miss is not None:
        normalised["prompt_cache_hit_tokens"] = prompt - miss
    elif prompt == 0:
        normalised["prompt_cache_hit_tokens"] = normalised["prompt_cache_miss_tokens"] = 0
    return normalised, []


def _periods(
    entry: dict, billed_at: datetime | None, pricing_period: str | None, public_holiday: bool | None
) -> tuple[list[str], list[str]]:
    if entry.get("pricing_rule", "flat") == "flat":
        return ["flat"], []
    if pricing_period is not None:
        if pricing_period not in {"peak", "offpeak"}:
            return [], ["invalid_pricing_period"]
        return [pricing_period], []
    if billed_at is None:
        return ["offpeak", "peak"], ["missing_billing_timestamp"]
    minutes = billed_at.hour * 60 + billed_at.minute
    peak_window = billed_at.weekday() < 5 and (60 <= minutes < 240 or 360 <= minutes < 600)
    if not peak_window or public_holiday is True:
        return ["offpeak"], []
    if public_holiday is False:
        return ["peak"], []
    return ["offpeak", "peak"], ["public_holiday_status_unknown"]


def cost_for_usage(
    provider: str,
    model: str,
    usage: Mapping | None,
    price_path: str | Path | None = None,
    *,
    billed_at: Any = None,
    pricing_period: str | None = None,
    public_holiday: bool | None = None,
    currency: str | None = None,
) -> dict:
    """Calculate a JSON-safe amount or interval from an exact named price snapshot.

    ``confirmed`` means tokens, date and rate are resolved by this calculation;
    it does not certify the provider invoice. ``estimated`` keeps unresolved
    cache/time bands explicit; ``unknown`` never silently becomes a zero charge.
    ``billed_at`` must be timezone-aware ISO/datetime or Unix seconds. An explicit
    ``pricing_period`` is a caller-supplied billing-band assertion, not inferred.
    """
    result = {
        "status": "unknown",
        "provider": provider,
        "model": model,
        "currency": None,
        "amount": None,
        "amount_decimal": None,
        "amount_min": None,
        "amount_max": None,
        "amount_min_decimal": None,
        "amount_max_decimal": None,
        "reasons": [],
        "basis": "usage_times_published_or_operator_token_rates_not_invoice",
        "exchange_rate_applied": False,
    }
    tokens, issues = _normalise_usage(usage)
    result["usage"] = tokens
    timestamp_value = (
        billed_at
        if billed_at is not None
        else (usage.get("created") if isinstance(usage, Mapping) else None)
    )
    timestamp = _datetime(timestamp_value)
    if timestamp_value is not None and timestamp is None:
        result["reasons"] = ["invalid_billing_timestamp", *issues]
        return result
    try:
        catalog = load_price_catalog(price_path)
    except (OSError, ValueError, TypeError):
        result["reasons"] = ["price_catalog_unavailable_or_invalid", *issues]
        return result
    matches = [
        entry
        for entry in catalog["prices"]
        if entry["provider"] == provider
        and model in [entry["model"], *entry.get("aliases", [])]
        and (currency is None or currency == entry["currency"])
    ]
    # A missing date may use the checked snapshot only as an explicit estimate.
    lookup_time = timestamp or _datetime(catalog.get("checked_at"))
    matches = [
        entry
        for entry in matches
        if lookup_time is not None
        and _datetime(entry["effective_from"]) <= lookup_time
        and (entry.get("effective_to") is None or lookup_time < _datetime(entry["effective_to"]))
    ]
    if not matches:
        result["reasons"] = ["price_not_configured_for_model_date_currency", *issues]
        return result
    if currency is None and len({e["currency"] for e in matches}) > 1:
        result["reasons"] = ["currency_selection_required", *issues]
        return result
    entry = max(
        enumerate(matches), key=lambda item: (_datetime(item[1]["effective_from"]), item[0])
    )[1]
    result["currency"] = entry["currency"]
    result["price"] = {
        k: copy.deepcopy(entry[k])
        for k in (
            "model",
            "served_model",
            "currency",
            "source_url",
            "effective_source_url",
            "checked_at",
            "effective_from",
            "effective_to",
            "pricing_rule",
            "rates_per_million",
            "assumptions",
        )
        if k in entry
    }
    result["billed_at"] = timestamp.isoformat() if timestamp else None
    if issues:
        result["reasons"] = issues
        return result
    periods, reasons = _periods(entry, timestamp, pricing_period, public_holiday)
    if not periods:
        result["reasons"] = reasons
        return result
    if timestamp is None:
        reasons.append("pricing_date_assumed_checked_at")
    hit = tokens["prompt_cache_hit_tokens"]
    hit_values = [hit] if hit is not None else [0, tokens["prompt_tokens"]]
    if hit is None and any(
        _decimal(entry["rates_per_million"][p]["input_cache_hit"])
        != _decimal(entry["rates_per_million"][p]["input_cache_miss"])
        for p in periods
    ):
        reasons.append("input_cache_split_unknown")
    amounts = []
    for period in periods:
        rate = entry["rates_per_million"][period]
        for cache_hit in hit_values:
            amounts.append(
                (
                    Decimal(cache_hit) * _decimal(rate["input_cache_hit"])
                    + Decimal(tokens["prompt_tokens"] - cache_hit)
                    * _decimal(rate["input_cache_miss"])
                    + Decimal(tokens["completion_tokens"]) * _decimal(rate["output"])
                )
                / _MILLION
            )
    low, high = min(amounts), max(amounts)
    result["amount_min"], result["amount_min_decimal"] = _money(low)
    result["amount_max"], result["amount_max_decimal"] = _money(high)
    if low == high:
        result["amount"], result["amount_decimal"] = _money(low)
    result["status"] = "estimated" if reasons else "confirmed"
    result["reasons"] = list(dict.fromkeys(reasons))
    result["pricing_periods"] = periods
    if pricing_period is not None:
        result["pricing_period_source"] = "caller_supplied"
    return result


def cost_for_calls(
    calls: Iterable[Mapping],
    provider: str | None = None,
    model: str | None = None,
    price_path: str | Path | None = None,
    *,
    billed_at: Any = None,
) -> dict:
    """Aggregate receipts in their original currencies, counting stable IDs once.

    A replay-only receipt still represents its original paid call. Pass the
    original and replay together with the same ``billing_id`` to deduplicate.
    Missing stable IDs are never guessed from attempt numbers across roles.
    """
    unique: list[dict] = []
    ids: dict[str, int] = {}
    duplicates = 0
    conflicts: set[int] = set()
    for call in calls:
        row = dict(call)
        identity = next(
            (
                str(row[k])
                for k in ("billing_id", "provider_response_id", "receipt_id", "call_id")
                if row.get(k)
            ),
            None,
        )
        if identity and identity in ids:
            duplicates += 1
            index = ids[identity]
            previous = unique[index]
            identity_conflict = any(
                previous.get(k) is not None and row.get(k) is not None and previous[k] != row[k]
                for k in ("provider", "model", "currency")
            )
            if identity_conflict or (
                previous.get("usage")
                and row.get("usage")
                and _normalise_usage(previous["usage"]) != _normalise_usage(row["usage"])
            ):
                conflicts.add(index)
            elif not previous.get("usage") and row.get("usage"):
                unique[index] = row
            continue
        if identity:
            ids[identity] = len(unique)
        unique.append(row)
    receipts = []
    for index, call in enumerate(unique):
        receipt = cost_for_usage(
            call.get("provider", provider) or "unknown",
            call.get("model", model) or "unknown",
            call.get("usage"),
            price_path,
            billed_at=call.get(
                "billed_at", call.get("created", call.get("started_at_utc", billed_at))
            ),
            pricing_period=call.get("pricing_period"),
            public_holiday=call.get("public_holiday"),
            currency=call.get("currency"),
        )
        if index in conflicts:
            receipt.update(
                status="unknown",
                amount=None,
                amount_decimal=None,
                amount_min=None,
                amount_max=None,
                amount_min_decimal=None,
                amount_max_decimal=None,
                reasons=["conflicting_replay_usage"],
            )
        receipts.append(receipt)
    status = (
        "unknown"
        if any(r["status"] == "unknown" for r in receipts)
        else ("estimated" if any(r["status"] == "estimated" for r in receipts) else "confirmed")
    )
    totals = {}
    for currency in sorted({r["currency"] for r in receipts if r["currency"]}):
        rows = [r for r in receipts if r["currency"] == currency]
        known = [r for r in rows if r["amount_min_decimal"] is not None]
        complete = len(known) == len(rows) and not any(r["currency"] is None for r in receipts)
        low = sum((Decimal(r["amount_min_decimal"]) for r in known), Decimal(0))
        high = sum((Decimal(r["amount_max_decimal"]) for r in known), Decimal(0))
        low_float, low_decimal = _money(low)
        high_float, high_decimal = _money(high)
        amount, amount_decimal = _money(low if complete and low == high else None)
        totals[currency] = {
            "complete": complete,
            "amount": amount,
            "amount_decimal": amount_decimal,
            "known_subtotal_min": low_float,
            "known_subtotal_max": high_float,
            "known_subtotal_min_decimal": low_decimal,
            "known_subtotal_max_decimal": high_decimal,
            "amount_min": low_float if complete else None,
            "amount_max": high_float if complete else None,
            "priced_calls": len(known),
            "unknown_calls": len(rows) - len(known),
        }
    return {
        "status": status,
        "unique_calls": len(unique),
        "duplicates_ignored": duplicates,
        "unknown_calls": sum(r["status"] == "unknown" for r in receipts),
        "estimated_calls": sum(r["status"] == "estimated" for r in receipts),
        "currency_totals": totals,
        "calls": receipts,
        "exchange_rate_applied": False,
    }
