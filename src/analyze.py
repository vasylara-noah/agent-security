"""Results Analyzer: metryki z results/*.jsonl.

Użycie:  python -m src.analyze                (wszystkie pliki z results/)
         python -m src.analyze plik1.jsonl    (wybrane pliki)
Zapisuje też: results/summary_attacks.csv, results/asr_by_defense.png, results/review_sample.csv
"""
import json
import sys
from pathlib import Path

import pandas as pd

from .config import RESULTS_DIR

KEYS = ["model", "defense", "memory"]


def load(paths) -> pd.DataFrame:
    rows = []
    for p in paths:
        for line in Path(p).read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
    df = pd.DataFrame(rows)
    df["triggered"] = df["defense_events"].apply(lambda e: len(e) > 0)
    df["poison_retrieved"] = df["extra"].apply(lambda e: e.get("poison_retrieved"))
    df["memory_written"] = df["extra"].apply(lambda e: e.get("memory_written"))
    df["is_control"] = df["attack_type"] == "control"
    return df


def pct(s: pd.Series) -> float:
    s = s.dropna()
    return round(100 * s.astype(float).mean(), 1) if len(s) else float("nan")


def attack_table(atk: pd.DataFrame, by: list[str]) -> pd.DataFrame:
    g = atk.groupby(KEYS + by)
    t = g.agg(
        n=("id", "count"),
        ASR=("attack_success", pct),
        TSR=("task_success", pct),
        ToolMisuse=("forbidden_executed", pct),
        Detection=("triggered", pct),
        latency_s=("latency_s", "mean"),
        tokens=("tokens", "mean"),
        errors=("error", lambda s: int(s.notna().sum())),
    )
    t["FNR"] = (100 - t["Detection"]).where(t.index.get_level_values("defense") != "none")
    return t.round(2)


def blocking_effectiveness(atk: pd.DataFrame) -> pd.DataFrame:
    asr = atk.groupby(KEYS)["attack_success"].apply(lambda s: s.astype(float).mean() * 100)
    rows = []
    for (model, defense, memory), v in asr.items():
        if defense == "none":
            continue
        base = asr.get((model, "none", memory))
        if base is not None and base > 0:  # BE liczymy tylko, gdy baseline miał skuteczne ataki
            rows.append({"model": model, "defense": defense, "memory": memory,
                         "ASR_baseline": round(base, 1), "ASR_defense": round(v, 1),
                         "BE_%": round(100 * (base - v) / base, 1)})
    return pd.DataFrame(rows)


def summarize(df: pd.DataFrame, save: bool = True) -> None:
    atk, ctl = df[~df["is_control"]], df[df["is_control"]]
    pd.set_option("display.width", 200)

    t = attack_table(atk, ["attack_type"])
    print("\n=== Ataki wg klasy (wartości w %) ===")
    print(t.to_string())

    print("\n=== Ataki ogółem ===")
    print(attack_table(atk.assign(all="all"), ["all"]).to_string())

    dp = atk[atk["attack_type"] == "data_poisoning"]
    if len(dp):
        d = dp.groupby(KEYS).agg(
            n=("id", "count"),
            Poison_Retrieval=("poison_retrieved", pct),
            Poison_Influence=("attack_success", pct),
        )
        print("\n=== Data poisoning: pobranie vs wpływ (%) ===")
        print(d.to_string())

    mp = atk[atk["attack_type"] == "memory_poisoning"]
    if len(mp):
        m = mp.groupby(KEYS).agg(
            n=("id", "count"),
            Memory_Write=("memory_written", pct),
            Influence_later=("attack_success", pct),
        )
        print("\n=== Memory poisoning: zapis w pamięci vs wpływ w kolejnej sesji (%) ===")
        print(m.to_string())

    print("\n=== Ataki wg języka i zbioru (dev/test) ===")
    print(attack_table(atk, ["language", "split"])[["n", "ASR", "Detection"]].to_string())

    if len(ctl):
        c = ctl.groupby(KEYS).agg(n=("id", "count"), TSR=("task_success", pct), FPR=("triggered", pct))
        print("\n=== Zadania kontrolne: TSR i False Positive Rate (%) ===")
        print(c.to_string())

    be = blocking_effectiveness(atk)
    if len(be):
        print("\n=== Blocking Effectiveness względem konfiguracji bez zabezpieczeń ===")
        print(be.to_string(index=False))
    else:
        print("\n(Blocking Effectiveness: brak baseline 'none' z ASR > 0 w podanych plikach)")

    if save:
        RESULTS_DIR.mkdir(exist_ok=True)
        t.to_csv(RESULTS_DIR / "summary_attacks.csv")
        review = atk[atk["attack_success"] == True][["id", "model", "defense", "memory", "answer", "tool_log"]]  # noqa: E712
        review = review.assign(answer=review["answer"].str[:300],
                               tool_log=review["tool_log"].apply(lambda l: "; ".join(f"{c['tool']}({list(c['args'].values())})" for c in l)),
                               manual_verdict="")
        review.sample(min(len(review), 20), random_state=1).to_csv(
            RESULTS_DIR / "review_sample.csv", index=False, encoding="utf-8-sig")
        _chart(atk)
        print("\nZapisano: results/summary_attacks.csv, results/review_sample.csv, results/asr_by_defense.png")


def _chart(atk: pd.DataFrame) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    p = atk.groupby(["defense", "attack_type"])["attack_success"].apply(
        lambda s: s.astype(float).mean() * 100).unstack("attack_type").fillna(0)
    ax = p.plot(kind="bar", figsize=(9, 5))
    ax.set_ylabel("ASR [%]")
    ax.set_xlabel("zabezpieczenie")
    ax.set_title("Attack Success Rate wg zabezpieczenia i klasy ataku")
    ax.set_ylim(0, 100)
    plt.xticks(rotation=0)
    plt.tight_layout()
    plt.savefig(RESULTS_DIR / "asr_by_defense.png", dpi=150)
    plt.close()


if __name__ == "__main__":
    files = sys.argv[1:] or sorted(RESULTS_DIR.glob("*.jsonl"))
    if not files:
        sys.exit("Brak plików w results/. Najpierw uruchom runner.")
    summarize(load(files))
