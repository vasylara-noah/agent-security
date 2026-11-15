"""Pilot: uruchamia całą macierz konfiguracji jednym poleceniem i liczy wyniki.

    python -m src.pilot --model ollama:qwen2.5:7b --quick        (szybki test: none + combined, 1 powtórzenie)
    python -m src.pilot --model ollama:qwen2.5:7b --repeats 3    (pełny pilot: 5 konfiguracji zabezpieczeń)
    python -m src.pilot --model fake:naive --quick               (sprawdzenie potoku bez Ollamy)
Opcje: --split dev|test|all, --memory-ablation (dodatkowo baseline bez pamięci długoterminowej)
"""
import argparse
import json
import sys
import time

from dotenv import load_dotenv

from .agent import make_llm
from .analyze import load, summarize
from .config import RESULTS_DIR
from .defenses import PRESETS
from .runner import load_scenarios, run_scenario


def main() -> None:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    load_dotenv()
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--repeats", type=int, default=1)
    ap.add_argument("--defenses", nargs="*", default=list(PRESETS))
    ap.add_argument("--split", default="all", choices=["all", "dev", "test"])
    ap.add_argument("--quick", action="store_true", help="tylko none i combined")
    ap.add_argument("--memory-ablation", action="store_true")
    ap.add_argument("--only", nargs="*")
    a = ap.parse_args()

    defenses = ["none", "combined"] if a.quick else a.defenses
    configs = [(d, "long") for d in defenses]
    if a.memory_ablation:
        configs.append(("none", "none"))
    scenarios = load_scenarios(a.only, a.split)
    total = len(configs) * len(scenarios) * a.repeats
    print(f"Model: {a.model} | scenariuszy: {len(scenarios)} | konfiguracje: {configs} | powtórzenia: {a.repeats}")
    print(f"Łącznie uruchomień: {total}. Przerwanie: Ctrl+C (zapisane wyniki zostają w results/).\n")

    llm = make_llm(a.model)
    RESULTS_DIR.mkdir(exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    files, done, t0 = [], 0, time.perf_counter()
    for defense, memory in configs:
        out = RESULTS_DIR / f"{a.model.replace(':', '_').replace('/', '_')}__{defense}__mem-{memory}__{stamp}.jsonl"
        files.append(out)
        with out.open("w", encoding="utf-8") as f:
            for s in scenarios:
                for r in range(1, a.repeats + 1):
                    rec = run_scenario(s, llm, defense, memory, a.model, r)
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                    f.flush()
                    done += 1
                    eta = (time.perf_counter() - t0) / done * (total - done) / 60
                    print(f"[{done}/{total}] {defense:17} mem={memory:4} {rec['id']:14} r{r} "
                          f"attack={rec['attack_success']} task={rec['task_success']} "
                          f"{rec['latency_s']}s {rec['error'] or ''}  (zostało ok. {eta:.0f} min)")
    summarize(load(files))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nPrzerwano. Wyniki zapisane do tej pory są w results/. Policz je: python -m src.analyze")
