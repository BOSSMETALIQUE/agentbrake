"""Tests for the CometAPI provider: usage extraction, pricing, budget wiring.

Everything is mocked — no network calls, no real API key, no ``openai``
package required.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

import agentbrake
from agentbrake import AgentBrakeInterrupt, InterruptReason
from agentbrake.detectors import DEFAULT_PRICING, cost_from_tokens
from agentbrake.providers import cometapi


@pytest.fixture(autouse=True)
def _isolate_default_run():
    """Each test starts and ends with no process-wide default run."""
    agentbrake._default_run = None
    yield
    agentbrake._default_run = None


def _response(prompt_tokens=None, completion_tokens=None, with_usage=True):
    """An openai-SDK-shaped response object (attribute access)."""
    usage = (
        SimpleNamespace(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens)
        if with_usage
        else None
    )
    return SimpleNamespace(usage=usage, choices=[])


class _FakeClient:
    """Stands in for an openai.OpenAI client; records the kwargs it was given."""

    def __init__(self, response):
        self.kwargs = None
        outer = self

        class _Completions:
            def create(self, **kwargs):
                outer.kwargs = kwargs
                return response

        self.chat = SimpleNamespace(completions=_Completions())


# --- track: usage extraction ----------------------------------------------

def test_track_extracts_tokens_from_sdk_style_response():
    call = cometapi.track(_response(1000, 500), model="gpt-4o")
    assert call.prompt_tokens == 1000
    assert call.completion_tokens == 500
    assert call.model == "gpt-4o"


def test_track_extracts_tokens_from_dict_response():
    raw = {"usage": {"prompt_tokens": 42, "completion_tokens": 7}}
    call = cometapi.track(raw, model="gpt-4o-mini")
    assert call.prompt_tokens == 42
    assert call.completion_tokens == 7
    assert call.response is raw


def test_track_prices_via_cost_from_tokens():
    call = cometapi.track(_response(1_000_000, 1_000_000), model="gpt-4o")
    assert call.cost_usd == pytest.approx(cost_from_tokens("gpt-4o", 1_000_000, 1_000_000))
    assert call.cost_usd == pytest.approx(2.50 + 10.00)


def test_track_unknown_model_uses_default_pricing_not_zero():
    call = cometapi.track(_response(1_000_000, 1_000_000), model="some-exotic-model")
    assert call.cost_usd == pytest.approx(sum(DEFAULT_PRICING))
    assert call.cost_usd > 0


def test_track_missing_usage_falls_back_cleanly():
    call = cometapi.track(_response(with_usage=False), model="gpt-4o")
    assert call.prompt_tokens is None
    assert call.completion_tokens is None
    assert call.cost_usd == 0.0


# --- complete: call plumbing ----------------------------------------------

def test_complete_passes_model_messages_and_kwargs_through():
    client = _FakeClient(_response(10, 5))
    messages = [{"role": "user", "content": "hi"}]
    call = cometapi.complete("gpt-4o", messages, client=client, temperature=0.2)
    assert client.kwargs == {"model": "gpt-4o", "messages": messages, "temperature": 0.2}
    assert call.cost_usd == pytest.approx(cost_from_tokens("gpt-4o", 10, 5))


def test_complete_without_active_run_just_tracks():
    call = cometapi.complete("gpt-4o", [], client=_FakeClient(_response(1000, 500)))
    assert call.cost_usd > 0  # priced, but nowhere to record — and no error


# --- record: budget wiring with the active run ----------------------------

def test_complete_records_spend_into_active_run():
    with agentbrake.run(budget_usd=100.0) as r:
        cometapi.complete("gpt-4o", [], client=_FakeClient(_response(1000, 500)))
        assert r.state.total_cost_usd == pytest.approx(cost_from_tokens("gpt-4o", 1000, 500))
        assert [c.name for c in r.state.calls] == ["llm:cometapi:gpt-4o"]
        assert r.state.calls[0].outcome == "ok"
        assert r.state.calls[0].args["prompt_tokens"] == 1000


def test_complete_over_budget_raises_and_still_records_the_spend():
    # 200k in + 100k out on gpt-4o = $1.50 against a $1.00 ceiling.
    client = _FakeClient(_response(200_000, 100_000))
    with agentbrake.run(budget_usd=1.0) as r:
        with pytest.raises(AgentBrakeInterrupt) as ei:
            cometapi.complete("gpt-4o", [], client=client)
    assert ei.value.reason is InterruptReason.BUDGET
    assert ei.value.context["tool"] == "llm:cometapi:gpt-4o"
    # The tokens were already bought: the overrun call is in the ledger.
    assert r.state.total_cost_usd == pytest.approx(1.5)
    assert r.state.status == "interrupted"


def test_complete_under_budget_does_not_interrupt():
    with agentbrake.run(budget_usd=10.0) as r:
        cometapi.complete("gpt-4o", [], client=_FakeClient(_response(1000, 500)))
    assert r.state.status == "completed"


def test_complete_records_into_init_default_run():
    agentbrake.init(budget_usd=1.0)
    with pytest.raises(AgentBrakeInterrupt) as ei:
        cometapi.complete("gpt-4o", [], client=_FakeClient(_response(200_000, 100_000)))
    assert ei.value.reason is InterruptReason.BUDGET


def test_complete_record_false_leaves_run_untouched():
    with agentbrake.run(budget_usd=0.0001) as r:
        cometapi.complete("gpt-4o", [], client=_FakeClient(_response(200_000, 100_000)), record=False)
        assert r.state.total_cost_usd == 0.0
        assert r.state.calls == []


def test_record_without_active_run_is_a_noop():
    cometapi.record(cometapi.CometAPICall(model="gpt-4o", cost_usd=5.0))  # must not raise


def test_missing_usage_records_zero_cost_without_tripping_budget():
    with agentbrake.run(budget_usd=0.01) as r:
        cometapi.complete("gpt-4o", [], client=_FakeClient(_response(with_usage=False)))
        assert r.state.total_cost_usd == 0.0
        assert len(r.state.calls) == 1  # the call is still in the history


# --- client construction: key handling, no key in code anywhere -----------

def _fake_openai_module(created):
    class OpenAI:
        def __init__(self, api_key, base_url):
            created.append({"api_key": api_key, "base_url": base_url})
            self.chat = _FakeClient(_response(1, 1)).chat

    return SimpleNamespace(OpenAI=OpenAI)


def test_api_key_argument_wins_over_env(monkeypatch):
    created = []
    monkeypatch.setitem(sys.modules, "openai", _fake_openai_module(created))
    monkeypatch.setenv(cometapi.API_KEY_ENV_VAR, "env-key")
    cometapi.complete("gpt-4o", [], api_key="arg-key")
    assert created == [{"api_key": "arg-key", "base_url": cometapi.DEFAULT_BASE_URL}]


def test_api_key_read_from_env(monkeypatch):
    created = []
    monkeypatch.setitem(sys.modules, "openai", _fake_openai_module(created))
    monkeypatch.setenv(cometapi.API_KEY_ENV_VAR, "env-key")
    cometapi.complete("gpt-4o", [])
    assert created[0]["api_key"] == "env-key"


def test_missing_api_key_raises_clear_error(monkeypatch):
    monkeypatch.setitem(sys.modules, "openai", _fake_openai_module([]))
    monkeypatch.delenv(cometapi.API_KEY_ENV_VAR, raising=False)
    with pytest.raises(RuntimeError, match=cometapi.API_KEY_ENV_VAR):
        cometapi.complete("gpt-4o", [])


def test_missing_openai_package_raises_install_hint(monkeypatch):
    monkeypatch.setitem(sys.modules, "openai", None)  # import raises ImportError
    monkeypatch.setenv(cometapi.API_KEY_ENV_VAR, "some-key")
    with pytest.raises(ImportError, match=r"py-agentbrake\[cometapi\]"):
        cometapi.complete("gpt-4o", [])
