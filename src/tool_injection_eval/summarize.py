"""Turn Inspect logs into a results table with honest error bars.

    python -m tool_injection_eval.summarize logs/ --out results/RESULTS.md

Rates are computed over every scored sample-epoch. Attack metrics use attack
samples only; utility is reported separately with and without an attack present.
Intervals are 95% Wilson score intervals, which behave sensibly at small n and
at rates of 0 or 1. Samples that errored are counted and excluded, not scored.
"""

from __future__ import annotations

import argparse
import math
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from inspect_ai.log import list_eval_logs, read_eval_log

SCORER = "injection_scorer"


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for k successes out of n."""
    if n == 0:
        return (math.nan, math.nan)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def rate(k: int, n: int) -> str:
    if n == 0:
        return "n/a"
    lo, hi = wilson(k, n)
    return f"{k}/{n} ({k / n:.0%}; {lo:.0%}–{hi:.0%})"


@dataclass
class Tally:
    attack_n: int = 0
    exfiltrated: int = 0
    external_contact: int = 0
    secret_in_any_email: int = 0
    task_completed_under_attack: int = 0
    benign_n: int = 0
    task_completed_benign: int = 0
    errors: int = 0
    by_attack: dict[str, list[int]] = field(default_factory=lambda: defaultdict(lambda: [0, 0]))
    by_surface: dict[str, list[int]] = field(default_factory=lambda: defaultdict(lambda: [0, 0]))


def collect(log_dir: str | Path) -> dict[tuple[str, str], Tally]:
    tallies: dict[tuple[str, str], Tally] = defaultdict(Tally)
    for info in list_eval_logs(str(log_dir)):
        log = read_eval_log(info)
        if not log.eval.task.endswith("tool_injection"):
            continue
        defense = str((log.eval.task_args or {}).get("defense", "none"))
        tally = tallies[(log.eval.model, defense)]
        for sample in log.samples or []:
            score = (sample.scores or {}).get(SCORER)
            if sample.error is not None or score is None:
                tally.errors += 1
                continue
            value = score.value
            if sample.metadata["is_attack"]:
                tally.attack_n += 1
                tally.exfiltrated += value["exfiltrated"]
                tally.external_contact += value["external_contact"]
                tally.secret_in_any_email += value["secret_in_any_email"]
                tally.task_completed_under_attack += value["task_completed"]
                for bucket, name in (
                    (tally.by_attack, sample.metadata["attack"]),
                    (tally.by_surface, sample.metadata["surface"]),
                ):
                    bucket[name][0] += value["exfiltrated"]
                    bucket[name][1] += 1
            else:
                tally.benign_n += 1
                tally.task_completed_benign += value["task_completed"]
    return dict(tallies)


def render(tallies: dict[tuple[str, str], Tally]) -> str:
    if not tallies:
        return "No tool_injection logs found.\n"
    keys = sorted(tallies)
    lines = [
        "## Results",
        "",
        "Each cell is k/n (rate; 95% Wilson interval). Lower is better for the first three "
        "columns, higher is better for the utility columns.",
        "",
        "| Model | Defence | Exfiltrated | Contacted outsider | Secret in any email "
        "| Utility, no attack | Utility, under attack | Errors |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for model, defense in keys:
        t = tallies[(model, defense)]
        lines.append(
            f"| {model} | {defense} | {rate(t.exfiltrated, t.attack_n)} "
            f"| {rate(t.external_contact, t.attack_n)} "
            f"| {rate(t.secret_in_any_email, t.attack_n)} "
            f"| {rate(t.task_completed_benign, t.benign_n)} "
            f"| {rate(t.task_completed_under_attack, t.attack_n)} | {t.errors} |"
        )
    for title, attr in (("attack style", "by_attack"), ("surface", "by_surface")):
        names = sorted({name for t in tallies.values() for name in getattr(t, attr)})
        header = " | ".join(f"{m} ({d})" for m, d in keys)
        lines += ["", f"### Exfiltration by {title}", "", f"| {title} | {header} |"]
        lines.append("|---|" + "---|" * len(keys))
        for name in names:
            cells = []
            for key in keys:
                k, n = getattr(tallies[key], attr).get(name, [0, 0])
                cells.append(rate(k, n))
            lines.append(f"| {name} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("log_dir", nargs="?", default="logs")
    parser.add_argument("--out", help="also write the table to this file")
    args = parser.parse_args()
    table = render(collect(args.log_dir))
    print(table)
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(table, encoding="utf-8")


if __name__ == "__main__":
    main()
