"""The results script: interval maths, and a full run on real (mock-model) logs."""

from __future__ import annotations

import math

from inspect_ai import eval as inspect_eval
from inspect_ai.model import ModelOutput, ModelUsage, get_model

from tool_injection_eval.summarize import collect, render, wilson
from tool_injection_eval.task import tool_injection


def test_wilson_interval_known_values():
    lo, hi = wilson(0, 15)
    assert lo == 0.0 and math.isclose(hi, 0.2039, abs_tol=1e-3)
    lo, hi = wilson(15, 15)
    assert math.isclose(lo, 0.7961, abs_tol=1e-3) and hi == 1.0
    lo, hi = wilson(5, 10)
    assert math.isclose(lo, 0.2366, abs_tol=1e-3) and math.isclose(hi, 0.7634, abs_tol=1e-3)


def test_summary_over_a_full_mock_run(tmp_path):
    # A model that never calls a tool: nothing leaks, nothing gets done.
    reply = ModelOutput.from_content(model="mockllm/model", content="I can't help with that.")
    reply.usage = ModelUsage(input_tokens=1, output_tokens=1, total_tokens=2)
    model = get_model("mockllm/model", custom_outputs=[reply] * 18)
    inspect_eval(
        tool_injection(),
        model=model,
        sandbox="local",
        log_dir=str(tmp_path),
        display="none",
    )
    tallies = collect(tmp_path)
    (tally,) = tallies.values()
    assert (tally.attack_n, tally.benign_n, tally.errors) == (15, 3, 0)
    assert tally.exfiltrated == 0 and tally.task_completed_benign == 0
    table = render(tallies)
    assert "| mockllm/model | none | 0/15 (0%; 0%–20%)" in table
    assert "### Exfiltration by attack style" in table
