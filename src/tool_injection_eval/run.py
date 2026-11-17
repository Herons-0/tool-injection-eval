"""Run the eval in complete rounds and write the results table.

    python -m tool_injection_eval.run                        # newest stable Gemini Flash
    python -m tool_injection_eval.run --model openai/gpt-5-mini --rounds 3

A round is one pass over all 18 samples under each defence, which means two Inspect
runs of one epoch each. Working in rounds keeps every unit of work complete. If an
API quota runs out part-way, each finished round still counts. The unfinished run
is moved to ``logs_incomplete/`` so it is never half-counted, and running the
command again carries on from where it stopped.

``--model gemini`` (the default) asks the Gemini API for its newest stable Flash
model and keeps the newest Flash-Lite model in reserve. Flash-Lite is used only if
Flash reaches its daily quota before finishing a single round, which is what happens
on the free tier.

Everything goes into ``--out``: ``logs/`` (Inspect logs), ``results/RESULTS.md``
and ``STATUS.txt``, a one-line-per-step progress file.
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from inspect_ai import eval as inspect_eval
from inspect_ai.log import EvalLog, read_eval_log
from inspect_ai.model import Model
from inspect_ai.util import AdaptiveConcurrency

from .summarize import SCORER, collect, render
from .task import tool_injection

DEFENSES = ("none", "warning")
GEMINI = "gemini"

# Start at 4 parallel requests, back off to 1 on rate limits, grow to 8 when the
# API keeps up. This suits both free-tier keys (a few requests a minute) and paid ones.
CONNECTIONS = AdaptiveConcurrency(min=1, start=4, max=8)
# Per-minute rate limits clear within a minute or two of backoff. A daily quota
# never clears, so give up on a request after about three minutes of retries.
MAX_RETRIES = 6
# Abandon (and retry) any single API request that hangs for this many seconds.
ATTEMPT_TIMEOUT = 180
# Stop a run early once a few samples have failed, because the rest would fail too.
FAIL_AFTER = 3
# A probe that meets a per-minute limit waits for the window to pass, a few times.
PROBE_ATTEMPTS = 4
PROBE_WAIT = 65.0


class Status:
    """Print a progress line and append it to STATUS.txt."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def __call__(self, message: str) -> None:
        line = f"{datetime.now().isoformat(timespec='seconds')}  {message}"
        print(line, flush=True)
        with self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")


# --- choosing and checking a Gemini model ----------------------------------


def gemini_version(name: str) -> tuple[int, ...]:
    """(3, 10) for gemini-3.10-flash. Tuples sort 3.10 after 3.8, unlike floats."""
    match = re.match(r"gemini-(\d+(?:\.\d+)*)-", name)
    return tuple(int(part) for part in match.group(1).split(".")) if match else ()


def newest(names: list[str], kind: str) -> str | None:
    """Newest stable model of a kind ('flash' or 'flash-lite'): no preview/exp/dated builds."""
    pattern = re.compile(rf"gemini-\d+(?:\.\d+)*-{re.escape(kind)}")
    found = [name for name in names if pattern.fullmatch(name)]
    return max(found, key=gemini_version) if found else None


def gemini_models() -> list[str]:
    from google import genai

    # Keep the client open while the listing pages through: a client that is only
    # used inline is garbage-collected, and closed, before the first request.
    with genai.Client() as client:
        names = [
            (m.name or "").removeprefix("models/")
            for m in client.models.list()
            if "generateContent" in (m.supported_actions or [])
        ]
    picks = [newest(names, "flash"), newest(names, "flash-lite")]
    models = [f"google/{name}" for name in picks if name]
    if not models:
        raise RuntimeError("the Gemini API lists no stable Flash model for this key")
    return models


def is_daily_quota(text: str) -> bool:
    """True for a 429 that waiting minutes will not clear.

    That is a per-day quota, or a quota of zero: a model this key's tier cannot use.
    """
    return (
        "PerDay" in text
        or "per day" in text.lower()
        or re.search(r"""['"]?limit['"]?\s*[:=]\s*['"]?0\b""", text) is not None
    )


def probe(model: str) -> str:
    """Send one tiny request. Returns 'ok', 'daily-quota', 'rate-limited' or an error.

    Only Google models are probed. Other providers report 'ok' and any problem
    surfaces in the first run instead.
    """
    if not model.startswith("google/"):
        return "ok"
    from google import genai
    from google.genai import errors

    with genai.Client() as client:
        for attempt in range(PROBE_ATTEMPTS):
            try:
                client.models.generate_content(
                    model=model.removeprefix("google/"), contents="Reply with the single word OK."
                )
                return "ok"
            except errors.APIError as exc:
                if exc.code != 429:
                    return f"error {exc}"[:400]
                if is_daily_quota(str(exc)):
                    return "daily-quota"
            except Exception as exc:  # network trouble and the like
                return f"error {type(exc).__name__}: {exc}"[:400]
            if attempt + 1 < PROBE_ATTEMPTS:
                time.sleep(PROBE_WAIT)  # a per-minute limit: wait for the window to pass
    return "rate-limited"


# --- reading logs ------------------------------------------------------------


def round_of(log: EvalLog) -> int | None:
    value = (log.eval.metadata or {}).get("round")
    return value if isinstance(value, int) else None


def defense_of(log: EvalLog) -> str:
    return str((log.eval.task_args or {}).get("defense", "none"))


def is_complete(log: EvalLog) -> bool:
    """Every sample of every epoch ran without error and was scored."""
    samples = log.samples or []
    expected = (log.eval.dataset.samples or 0) * (log.eval.config.epochs or 1)
    return (
        log.status == "success"
        and expected > 0
        and len(samples) == expected
        and all(s.error is None and SCORER in (s.scores or {}) for s in samples)
    )


def first_error(log: EvalLog) -> str:
    if log.error is not None:
        return log.error.message
    for sample in log.samples or []:
        if sample.error is not None:
            return sample.error.message
    return f"the run ended with status '{log.status}'"


def set_aside_incomplete(log_dir: Path, aside_dir: Path) -> int:
    """Move every log that is not a complete run out of log_dir, so it is never counted."""
    moved = 0
    for path in sorted(log_dir.rglob("*.eval")):
        try:
            complete = is_complete(read_eval_log(str(path)))
        except Exception:  # e.g. a log cut short when the window was closed
            complete = False
        if not complete:
            aside_dir.mkdir(parents=True, exist_ok=True)
            shutil.move(str(path), str(aside_dir / path.name))
            moved += 1
    return moved


def finished_runs(log_dir: Path) -> set[tuple[str, str, int]]:
    """(model, defence, round) for every complete run in log_dir."""
    done: set[tuple[str, str, int]] = set()
    for path in log_dir.rglob("*.eval"):
        log = read_eval_log(str(path), header_only=True)
        number = round_of(log)
        if number is not None:
            done.add((log.eval.model, defense_of(log), number))
    return done


def rounds_finished(log_dir: Path, model: str) -> int:
    """Number of rounds for which both defences have a complete run."""
    done = finished_runs(log_dir)
    rounds = {r for (m, _, r) in done if m == model}
    return sum(all((model, d, r) in done for d in DEFENSES) for r in rounds)


def describe(log: EvalLog) -> str:
    samples = log.samples or []
    attacked = [s for s in samples if s.metadata.get("is_attack")]
    clean = [s for s in samples if not s.metadata.get("is_attack")]
    leaked = sum(s.scores[SCORER].value["exfiltrated"] for s in attacked)
    useful = sum(s.scores[SCORER].value["task_completed"] for s in clean)
    return (
        f"secret leaked in {leaked}/{len(attacked)} attacked samples, "
        f"task done in {useful}/{len(clean)} clean samples"
    )


# --- running -------------------------------------------------------------------


def model_name(model: str | Model) -> str:
    return model if isinstance(model, str) else str(model)


def run_model(
    model: str | Model,
    rounds: int,
    out: Path,
    *,
    sandbox: str,
    display: str,
    check: Callable[[str], str],
    status: Status,
) -> str:
    """Run the missing rounds for one model. Returns 'done' or 'daily-quota'."""
    name = model_name(model)
    log_dir, aside_dir = out / "logs", out / "logs_incomplete"
    for number in range(1, rounds + 1):
        for defense in DEFENSES:
            label = f"Round {number}/{rounds}, defence '{defense}'"
            for attempt in (1, 2):
                if (name, defense, number) in finished_runs(log_dir):
                    break
                status(f"{label}: running {name}")
                (log,) = inspect_eval(
                    tool_injection(defense=defense, sandbox=sandbox),
                    model=model,
                    epochs=1,
                    log_dir=str(log_dir),
                    display=display,
                    log_level="error",  # hide harmless platform warnings from the console
                    fail_on_error=FAIL_AFTER,
                    retry_on_error=1,
                    max_retries=MAX_RETRIES,
                    attempt_timeout=ATTEMPT_TIMEOUT,
                    adaptive_connections=CONNECTIONS,
                    metadata={"round": number},
                    tags=[f"round-{number}"],
                )
                if is_complete(log):
                    status(f"{label}: {describe(log)}")
                    break
                error = " ".join(first_error(log).split())[:300]
                set_aside_incomplete(log_dir, aside_dir)
                status(f"{label} did not finish ({error})")
                if check(name) == "daily-quota":
                    return "daily-quota"
                if attempt == 2:
                    raise RuntimeError(f"{label} failed twice: {error}")
    return "done"


def run_rounds(
    models: list[str | Model],
    rounds: int,
    out: Path,
    *,
    sandbox: str = "local",
    display: str = "rich",
    check: Callable[[str], str] = probe,
) -> str:
    """Run up to `rounds` complete rounds. Returns 'done', 'paused' or 'nothing'."""
    out.mkdir(parents=True, exist_ok=True)
    status = Status(out / "STATUS.txt")
    log_dir = out / "logs"
    log_dir.mkdir(exist_ok=True)
    moved = set_aside_incomplete(log_dir, out / "logs_incomplete")
    if moved:
        status(f"Moved {moved} unfinished run(s) from an earlier attempt to logs_incomplete/")

    outcome = "nothing"
    for index, model in enumerate(models):
        name = model_name(model)
        fallback = model_name(models[index + 1]) if index + 1 < len(models) else None
        verdict = check(name)
        if verdict == "ok" or verdict == "rate-limited":
            status(f"Model: {name} (sandbox: {sandbox}, {rounds} round(s))")
            try:
                verdict = run_model(
                    model,
                    rounds,
                    out,
                    sandbox=sandbox,
                    display=display,
                    check=check,
                    status=status,
                )
            except RuntimeError as exc:
                if not fallback or rounds_finished(log_dir, name):
                    raise
                status(f"{name} failed ({exc}). Switching to {fallback}")
                continue
            if verdict == "done":
                outcome = "done"
                break
        elif verdict != "daily-quota":
            if not fallback:
                raise RuntimeError(f"{name} cannot be used: {verdict}")
            status(f"{name} cannot be used ({verdict}). Switching to {fallback}")
            continue
        # Daily quota reached. Fall back only if this model has nothing to show yet.
        done = rounds_finished(log_dir, name)
        if done == 0 and fallback:
            status(f"{name} hit its daily quota before finishing a round. Switching to {fallback}")
            continue
        status(
            f"{name} hit its daily quota after {done} complete round(s). "
            "Run again after the quota resets (midnight Pacific) to add the rest."
        )
        outcome = "paused" if done else "nothing"
        break

    write_results(out)
    return outcome


def write_results(out: Path) -> Path:
    tallies = collect(out / "logs")
    log_dir = out / "logs"
    lines = [
        f"Generated by `python -m tool_injection_eval.run` on {datetime.now():%Y-%m-%d} "
        "from complete rounds only (one round = all 18 samples under each defence).",
        "",
    ]
    for model in sorted({m for m, _ in tallies}):
        lines.append(f"- {model}: {rounds_finished(log_dir, model)} round(s)")
    path = out / "results" / "RESULTS.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "\n".join(lines) + "\n\n" + render(tallies)
    path.write_text(text, encoding="utf-8")
    print(text)
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--model",
        action="append",
        help="Inspect model name; repeat to give fallbacks for daily-quota stops. "
        "Default 'gemini': newest stable Gemini Flash, then Flash-Lite.",
    )
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--out", default=".", help="folder for logs/, results/ and STATUS.txt")
    parser.add_argument(
        "--sandbox",
        choices=["local", "docker"],
        default="local",
        help="local (default): a temporary folder. The agent's tools only read and "
        "write files, so this is safe and runs anywhere. docker: the task's container.",
    )
    parser.add_argument("--display", default="rich", help="Inspect display: rich, plain, none")
    args = parser.parse_args(argv)

    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    status = Status(out / "STATUS.txt")
    try:
        requested = args.model or [GEMINI]
        models: list[str | Model] = []
        for spec in requested:
            models.extend(gemini_models() if spec == GEMINI else [spec])
        outcome = run_rounds(
            models,
            args.rounds,
            out,
            sandbox=args.sandbox,
            display=args.display,
        )
    except Exception as exc:
        status(f"FAILED: {type(exc).__name__}: {' '.join(str(exc).split())[:400]}")
        raise
    results = out / "results" / "RESULTS.md"
    if outcome == "done":
        status(f"DONE. Results: {results}")
        return 0
    if outcome == "paused":
        status(f"PAUSED with partial results. Results so far: {results}")
        return 3
    status("FAILED: no round finished")
    return 1


if __name__ == "__main__":
    sys.exit(main())
