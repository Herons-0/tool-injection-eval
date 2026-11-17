"""The round runner: model choice, quota handling, resuming and set-aside logs."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from inspect_ai.model import Model, ModelOutput, ModelUsage, get_model

from tool_injection_eval.run import (
    finished_runs,
    gemini_version,
    is_daily_quota,
    newest,
    rounds_finished,
    run_rounds,
)


def quiet_model(name: str = "mockllm/model") -> Model:
    """A mock agent that answers 'Done.' at once (no tool calls, no network)."""

    def outputs() -> Iterator[ModelOutput]:
        while True:
            output = ModelOutput.from_content(model=name, content="Done.")
            output.usage = ModelUsage(input_tokens=1, output_tokens=1, total_tokens=2)
            yield output

    return get_model(name, custom_outputs=outputs())


def always_ok(model: str) -> str:
    return "ok"


def test_gemini_versions_sort_numerically():
    assert gemini_version("gemini-3.10-flash") > gemini_version("gemini-3.8-flash")
    names = [
        "gemini-2.5-flash",
        "gemini-3.10-flash",
        "gemini-3.8-flash",
        "gemini-3.9-flash-preview",
        "gemini-3.6-flash-lite",
        "gemini-3.6-flash-001",
        "gemini-flash-latest",
    ]
    assert newest(names, "flash") == "gemini-3.10-flash"
    assert newest(names, "flash-lite") == "gemini-3.6-flash-lite"
    assert newest(["gemini-flash-latest"], "flash") is None


def test_daily_quota_is_told_apart_from_a_per_minute_limit():
    daily = "429 RESOURCE_EXHAUSTED. quotaId: GenerateRequestsPerDayPerProjectPerModel-FreeTier"
    minute = "429 RESOURCE_EXHAUSTED. quotaId: GenerateRequestsPerMinutePerProjectPerModel-FreeTier"
    assert is_daily_quota(daily)
    assert not is_daily_quota(minute)


def test_rounds_resume_and_never_count_unfinished_runs(tmp_path: Path):
    model = quiet_model()
    assert run_rounds([model], 1, tmp_path, display="none", check=always_ok) == "done"
    logs = tmp_path / "logs"
    assert finished_runs(logs) == {
        ("mockllm/model", "none", 1),
        ("mockllm/model", "warning", 1),
    }

    # A log cut short (say, the window was closed) is moved aside, not counted.
    (logs / "broken.eval").write_bytes(b"not a zip")
    assert run_rounds([model], 2, tmp_path, display="none", check=always_ok) == "done"
    assert (tmp_path / "logs_incomplete" / "broken.eval").exists()
    assert rounds_finished(logs, "mockllm/model") == 2
    assert len(list(logs.rglob("*.eval"))) == 4  # round 1 was not run again

    results = (tmp_path / "results" / "RESULTS.md").read_text(encoding="utf-8")
    assert "- mockllm/model: 2 round(s)" in results
    # The quiet agent never emails anyone: nothing leaks, no task gets done.
    assert "| mockllm/model | none | 0/30 (0%" in results
    status = (tmp_path / "STATUS.txt").read_text(encoding="utf-8")
    assert "Moved 1 unfinished run(s)" in status


def test_falls_back_when_the_first_model_is_out_of_daily_quota(tmp_path: Path):
    def check(model: str) -> str:
        return "daily-quota" if model == "mockllm/flash" else "ok"

    lite = quiet_model("mockllm/flash-lite")
    outcome = run_rounds(["mockllm/flash", lite], 1, tmp_path, display="none", check=check)
    assert outcome == "done"
    assert {m for m, _, _ in finished_runs(tmp_path / "logs")} == {"mockllm/flash-lite"}
    assert "Switching to mockllm/flash-lite" in (tmp_path / "STATUS.txt").read_text()


def test_stops_cleanly_when_no_model_has_quota(tmp_path: Path):
    outcome = run_rounds(
        ["mockllm/flash"], 1, tmp_path, display="none", check=lambda model: "daily-quota"
    )
    assert outcome == "nothing"
    results = (tmp_path / "results" / "RESULTS.md").read_text(encoding="utf-8")
    assert "No tool_injection logs found." in results
