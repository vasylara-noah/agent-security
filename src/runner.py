"""Experiment Runner.
Przykład: python -m src.runner --model openai:gpt-4o-mini --defense none --repeats 3
"""
import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

from dotenv import load_dotenv

from .agent import make_llm, run_session
from .config import RESULTS_DIR, SCENARIOS_DIR
from .defenses import Defense
from .evaluator import evaluate
from .memory import Memory


def load_scenarios(only: list[str] | None = None, split: str = "all") -> list[dict]:
    items = []
    for f in sorted(SCENARIOS_DIR.glob("*.json")):
        items += json.loads(f.read_text(encoding="utf-8"))
    for s in items:
        s.setdefault("split", "dev")  # dev = do projektowania zabezpieczeń, test = zbiór kontrolny
    if split != "all":
        items = [s for s in items if s["split"] == split]
    if only:
        items = [s for s in items if any(s["id"].startswith(o) for o in only)]
    return items


def run_scenario(scenario: dict, llm, defense_name: str, memory_mode: str = "long",
                 model_label: str = "?", repeat: int = 1) -> dict:
    defense = Defense(defense_name)
    tool_log: list[dict] = []
    with tempfile.TemporaryDirectory() as tmp:
        memory = Memory(Path(tmp) / "memory.json") if memory_mode == "long" else None
        sessions = scenario.get("sessions") or [{"user_task": scenario["user_task"],
                                                 "corpus": scenario.get("corpus", [])}]
        last, latency, tokens, error = {}, 0.0, 0, None
        for s in sessions:
            last = run_session(llm, s["user_task"], s.get("corpus", []), defense, memory, tool_log)
            latency += last["latency_s"]
            tokens += last["tokens"]
            error = error or last["error"]
        ctx = {"answer": last["answer"], "tool_log": tool_log,
               "memory": memory.all() if memory else []}
    res = evaluate(scenario, ctx)
    return {
        "id": scenario["id"], "attack_type": scenario["attack_type"],
        "subtype": scenario.get("attack_subtype"), "language": scenario.get("language"),
        "difficulty": scenario.get("difficulty"), "split": scenario.get("split", "dev"),
        "model": model_label, "defense": defense_name, "memory": memory_mode, "repeat": repeat,
        "answer": last["answer"], "tool_log": tool_log, "memory_final": ctx["memory"],
        "defense_events": defense.events, "latency_s": round(latency, 2), "tokens": tokens,
        "error": error, **res,
    }


def main():
    # Windows: konsola cp1250 nie wypisze rosyjskich znaków z odpowiedzi modelu
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    load_dotenv()
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--defense", default="none")
    ap.add_argument("--memory", default="long", choices=["long", "none"])
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--only", nargs="*", help="prefiksy id, np. PI TM-001")
    ap.add_argument("--split", default="all", choices=["all", "dev", "test"])
    ap.add_argument("--out")
    a = ap.parse_args()

    llm = make_llm(a.model)
    scenarios = load_scenarios(a.only, a.split)
    if not scenarios:
        sys.exit("Brak scenariuszy dla podanych filtrów.")
    RESULTS_DIR.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    out = Path(a.out) if a.out else RESULTS_DIR / f"{a.model.replace(':', '_').replace('/', '_')}__{a.defense}__mem-{a.memory}__{stamp}.jsonl"

    with out.open("w", encoding="utf-8") as f:
        for s in scenarios:
            for r in range(1, a.repeats + 1):
                rec = run_scenario(s, llm, a.defense, a.memory, a.model, r)
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                f.flush()
                print(f"{rec['id']:8} r{r}  attack={rec['attack_success']}  "
                      f"task={rec['task_success']}  {rec['latency_s']}s  {rec['error'] or ''}")
    print("Zapisano:", out)


if __name__ == "__main__":
    main()
