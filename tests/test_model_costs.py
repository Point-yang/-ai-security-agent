import copy
import json
from datetime import UTC, datetime
from decimal import Decimal

import pytest

from zhidu.model_costs import (
    cost_for_calls,
    cost_for_usage,
    load_price_catalog,
    register_price,
    validate_price_catalog,
)

OFFPEAK = "2026-10-13T11:00:00Z"
PEAK = "2026-10-13T07:00:00Z"
USAGE = {
    "prompt_tokens": 1_000_000,
    "completion_tokens": 100_000,
    "prompt_cache_hit_tokens": 400_000,
    "prompt_cache_miss_tokens": 600_000,
    "total_tokens": 1_100_000,
}


def price(**kwargs):
    return cost_for_usage("deepseek", "deepseek-v4-flash", USAGE, billed_at=OFFPEAK, **kwargs)


def flat_entry(model="local", currency="CNY", input_rate="2", output_rate="3"):
    return {
        "provider": "ollama",
        "model": model,
        "currency": currency,
        "source_url": "operator-configured",
        "checked_at": OFFPEAK,
        "effective_from": "2026-10-13T00:00:00Z",
        "pricing_rule": "flat",
        "rates_per_million": {
            "flat": {
                "input_cache_hit": input_rate,
                "input_cache_miss": input_rate,
                "output": output_rate,
            }
        },
        "assumptions": ["operator supplied"],
    }


def catalog_path(tmp_path, *entries):
    catalog = {"schema_version": 1, "checked_at": OFFPEAK, "prices": list(entries)}
    path = tmp_path / "prices.json"
    path.write_text(json.dumps(catalog), encoding="utf-8")
    return path


def test_offpeak_exact_cache_cost_and_public_provenance():
    result = price()
    assert result["status"] == "confirmed"
    assert Decimal(result["amount_decimal"]) == Decimal("0.1512")
    assert result["amount_min"] == result["amount"] == result["amount_max"]
    assert result["currency"] == "USD"
    assert result["price"]["served_model"] == "DeepSeek-V4.1-Flash"
    assert result["price"]["effective_from"] == "2026-09-10T04:00:00Z"
    assert result["price"]["source_url"].startswith("https://api-docs.deepseek.com/")
    assert result["exchange_rate_applied"] is False


def test_legacy_flash_aliases_use_only_explicit_catalog_alias():
    direct = cost_for_usage("deepseek", "deepseek-flash", USAGE, billed_at=OFFPEAK)
    assert direct["amount"] == price()["amount"]
    missing = cost_for_usage("deepseek", "deepseek-chat", USAGE, billed_at=OFFPEAK)
    assert missing["status"] == "unknown"
    assert missing["amount"] is None


def test_peak_price_requires_holiday_resolution():
    known = cost_for_usage(
        "deepseek", "deepseek-flash", USAGE, billed_at=PEAK, public_holiday=False
    )
    assert known["status"] == "confirmed"
    assert known["amount"] == pytest.approx(0.3024)
    holiday = cost_for_usage(
        "deepseek", "deepseek-flash", USAGE, billed_at=PEAK, public_holiday=True
    )
    assert holiday["amount"] == price()["amount"]
    uncertain = cost_for_usage("deepseek", "deepseek-flash", USAGE, billed_at=PEAK)
    assert uncertain["status"] == "estimated" and uncertain["amount"] is None
    assert uncertain["amount_min"] == pytest.approx(0.1512)
    assert uncertain["amount_max"] == pytest.approx(0.3024)
    assert "public_holiday_status_unknown" in uncertain["reasons"]


@pytest.mark.parametrize(
    "timestamp,period",
    [
        ("2026-10-13T00:59:59Z", "offpeak"),
        ("2026-10-13T01:00:00Z", "peak"),
        ("2026-10-13T04:00:00Z", "offpeak"),
        ("2026-10-13T06:00:00Z", "peak"),
        ("2026-10-13T10:00:00Z", "offpeak"),
        ("2026-10-17T07:00:00Z", "offpeak"),
    ],
)
def test_peak_boundary_and_weekend(timestamp, period):
    result = cost_for_usage(
        "deepseek", "deepseek-flash", USAGE, billed_at=timestamp, public_holiday=False
    )
    assert result["status"] == "confirmed"
    assert result["pricing_periods"] == [period]


def test_unspecified_time_is_an_estimate_not_retroactive_price_certification():
    result = cost_for_usage("deepseek", "deepseek-flash", USAGE)
    assert result["status"] == "estimated"
    assert "pricing_date_assumed_checked_at" in result["reasons"]
    assert result["amount"] is None
    prior = cost_for_usage("deepseek", "deepseek-flash", USAGE, billed_at="2026-08-01T00:00:00Z")
    assert prior["status"] == "unknown" and prior["amount"] is None


def test_missing_cache_split_retains_bounds_not_all_input_cache_miss():
    usage = {"prompt_tokens": 1_000_000, "completion_tokens": 100_000}
    result = cost_for_usage("deepseek", "deepseek-flash", usage, billed_at=OFFPEAK)
    assert result["status"] == "estimated" and result["amount"] is None
    assert result["amount_min"] == pytest.approx(0.063)
    assert result["amount_max"] == pytest.approx(0.21)
    assert result["reasons"] == ["input_cache_split_unknown"]


def test_hit_tokens_can_derive_miss_from_official_token_identity():
    usage = {
        "prompt_tokens": 1_000_000,
        "completion_tokens": 100_000,
        "prompt_tokens_details": {"cached_tokens": 400_000},
    }
    result = cost_for_usage("deepseek", "deepseek-flash", usage, billed_at=OFFPEAK)
    assert result["status"] == "confirmed"
    assert result["usage"]["prompt_cache_miss_tokens"] == 600_000
    assert result["amount"] == price()["amount"]


def test_langchain_token_usage_normalizes_cache_details():
    usage = {
        "input_tokens": 1_000_000,
        "output_tokens": 100_000,
        "input_token_details": {"cache_read": 400_000},
    }
    result = cost_for_usage("deepseek", "deepseek-flash", usage, billed_at=OFFPEAK)
    assert result["status"] == "confirmed"
    assert result["amount"] == price()["amount"]


@pytest.mark.parametrize(
    "usage",
    [
        None,
        {},
        {"total_tokens": 1_100_000},
        {**USAGE, "prompt_tokens": True},
        {**USAGE, "completion_tokens": -1},
        {**USAGE, "total_tokens": 1},
        {**USAGE, "prompt_cache_hit_tokens": 900_000},
        {**USAGE, "prompt_tokens_details": {"cached_tokens": 0}},
        {**USAGE, "input_tokens": 1},
        {**USAGE, "prompt_cache_miss_tokens": 1_000_001},
    ],
)
def test_invalid_or_incomplete_usage_never_becomes_zero(usage):
    result = cost_for_usage("deepseek", "deepseek-flash", usage, billed_at=OFFPEAK)
    assert result["status"] == "unknown"
    assert result["amount"] is None and result["amount_min"] is None


def test_missing_price_model_or_provider_is_unknown(tmp_path):
    assert cost_for_usage("other", "deepseek-flash", USAGE, billed_at=OFFPEAK)["amount"] is None
    missing = cost_for_usage(
        "deepseek", "deepseek-flash", USAGE, tmp_path / "missing.json", billed_at=OFFPEAK
    )
    assert missing["status"] == "unknown"
    assert "price_catalog_unavailable_or_invalid" in missing["reasons"]


@pytest.mark.parametrize("timestamp", ["2026-10-13T11:00:00", "bad", float("nan")])
def test_invalid_or_naive_timestamp_is_not_silently_assumed(timestamp):
    result = cost_for_usage("deepseek", "deepseek-flash", USAGE, billed_at=timestamp)
    assert result["status"] == "unknown"
    assert "invalid_billing_timestamp" in result["reasons"]


def test_operator_cny_rates_without_exchange_conversion(tmp_path):
    path = catalog_path(tmp_path, flat_entry())
    usage = {"input_tokens": 1_000_000, "output_tokens": 100_000}
    result = cost_for_usage("ollama", "local", usage, path, billed_at=OFFPEAK)
    assert result["status"] == "confirmed"
    assert result["currency"] == "CNY" and result["amount"] == pytest.approx(2.3)
    assert result["exchange_rate_applied"] is False


def test_only_explicit_operator_zero_rates_confirm_free_model(tmp_path):
    path = catalog_path(tmp_path, flat_entry(input_rate="0", output_rate="0"))
    result = cost_for_usage("ollama", "local", USAGE, path, billed_at=OFFPEAK)
    assert result["status"] == "confirmed" and result["amount"] == 0
    absent = cost_for_usage("ollama", "not-priced", USAGE, path, billed_at=OFFPEAK)
    assert absent["status"] == "unknown" and absent["amount"] is None


def test_multiple_currencies_require_explicit_selection(tmp_path):
    path = catalog_path(tmp_path, flat_entry(), flat_entry(currency="USD"))
    assert cost_for_usage("ollama", "local", USAGE, path, billed_at=OFFPEAK)["reasons"] == [
        "currency_selection_required"
    ]
    selected = cost_for_usage("ollama", "local", USAGE, path, billed_at=OFFPEAK, currency="CNY")
    assert selected["status"] == "confirmed" and selected["currency"] == "CNY"


def test_effective_interval_and_later_operator_override(tmp_path):
    old = flat_entry()
    old["effective_to"] = "2026-10-14T00:00:00Z"
    newer = flat_entry(input_rate="4")
    newer["effective_from"] = "2026-10-14T00:00:00Z"
    path = catalog_path(tmp_path, old, newer)
    before = cost_for_usage("ollama", "local", USAGE, path, billed_at=OFFPEAK)
    after = cost_for_usage("ollama", "local", USAGE, path, billed_at="2026-10-14T01:00:00Z")
    assert before["amount"] == pytest.approx(2.3)
    assert after["amount"] == pytest.approx(4.3)


def test_register_price_is_validated_and_does_not_modify_catalog():
    initial = load_price_catalog()
    snapshot = copy.deepcopy(initial)
    changed = register_price(initial, flat_entry())
    assert len(changed["prices"]) == len(initial["prices"]) + 1
    assert initial == snapshot
    invalid = flat_entry(input_rate="-1")
    with pytest.raises(ValueError, match="invalid_rate"):
        register_price(initial, invalid)


def test_validate_rejects_nonfinite_rates_and_bad_provenance():
    for mutate in (
        lambda e: e["rates_per_million"]["flat"].update(output="NaN"),
        lambda e: e.update(effective_from="2026-10-13"),
        lambda e: e.update(currency="yen"),
        lambda e: e.pop("source_url"),
    ):
        entry = flat_entry()
        mutate(entry)
        with pytest.raises(ValueError):
            validate_price_catalog({"schema_version": 1, "prices": [entry]})


def test_replays_count_once_and_do_not_erase_original_paid_receipt():
    call = {
        "provider": "deepseek",
        "model": "deepseek-flash",
        "usage": USAGE,
        "provider_response_id": "reply-1",
        "created": int(datetime(2026, 10, 13, 11, tzinfo=UTC).timestamp()),
    }
    result = cost_for_calls([call, {**call, "replayed": True}])
    assert result["status"] == "confirmed"
    assert result["unique_calls"] == 1 and result["duplicates_ignored"] == 1
    assert result["currency_totals"]["USD"]["amount"] == price()["amount"]
    assert (
        cost_for_calls([{**call, "replayed": True}])["currency_totals"] == result["currency_totals"]
    )


def test_conflicting_replay_usage_is_unknown():
    call = {
        "provider": "deepseek",
        "model": "deepseek-flash",
        "usage": USAGE,
        "billing_id": "call-1",
        "billed_at": OFFPEAK,
    }
    result = cost_for_calls(
        [call, {**call, "usage": {**USAGE, "completion_tokens": 0, "total_tokens": 1_000_000}}]
    )
    assert result["unique_calls"] == 1 and result["status"] == "unknown"
    assert result["calls"][0]["reasons"] == ["conflicting_replay_usage"]
    assert result["currency_totals"]["USD"]["amount"] is None


def test_unknown_attempts_not_zero_and_same_attempt_across_roles_not_deduplicated():
    result = cost_for_calls(
        [
            {"attempt": 1, "usage": USAGE},
            {"attempt": 1, "usage": None},
        ],
        "deepseek",
        "deepseek-flash",
        billed_at=OFFPEAK,
    )
    assert result["unique_calls"] == 2 and result["status"] == "unknown"
    totals = result["currency_totals"]["USD"]
    assert totals["complete"] is False and totals["amount"] is None
    assert totals["known_subtotal_min"] == price()["amount"]
    assert totals["amount_max"] is None


def test_original_currencies_aggregate_separately(tmp_path):
    path = catalog_path(tmp_path, flat_entry(), flat_entry(model="usd-model", currency="USD"))
    result = cost_for_calls(
        [
            {"provider": "ollama", "model": "local", "usage": USAGE},
            {"provider": "ollama", "model": "usd-model", "usage": USAGE},
        ],
        price_path=path,
        billed_at=OFFPEAK,
    )
    assert result["status"] == "confirmed"
    assert set(result["currency_totals"]) == {"CNY", "USD"}
    assert "amount" not in result
    assert result["exchange_rate_applied"] is False


def test_unpriced_call_prevents_known_subtotal_being_displayed_as_total():
    result = cost_for_calls(
        [
            {"provider": "deepseek", "model": "deepseek-flash", "usage": USAGE},
            {"provider": "unknown", "model": "unknown", "usage": USAGE},
        ],
        billed_at=OFFPEAK,
    )
    assert result["status"] == "unknown" and result["unknown_calls"] == 1
    totals = result["currency_totals"]["USD"]
    assert totals["complete"] is False and totals["amount"] is None
    assert totals["known_subtotal_min"] == price()["amount"]


def test_no_calls_has_no_fabricated_currency_total():
    result = cost_for_calls([])
    assert result["status"] == "confirmed" and result["unique_calls"] == 0
    assert result["currency_totals"] == {}
