"""Graficzny interfejs pilota (Streamlit, działa lokalnie w przeglądarce).

Uruchomienie z głównego katalogu projektu (przy aktywnym .venv):
    streamlit run src/gui.py

Interfejs tylko wywołuje istniejące funkcje (run_scenario, analyze), nie zmienia
logiki eksperymentów. Zakładki: Piaskownica, Wyniki, Ręczna weryfikacja.
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # żeby `streamlit run src/gui.py` widział pakiet src
    sys.path.insert(0, str(ROOT))

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from src.agent import make_llm
from src.analyze import KEYS, attack_table, blocking_effectiveness, load, pct
from src.config import DOCS_DIR, RESULTS_DIR
from src.defenses import PRESETS
from src.runner import load_scenarios, run_scenario

load_dotenv(ROOT / ".env")
st.set_page_config(page_title="Bezpieczeństwo agentów AI", layout="wide")

REVIEW_FILE = RESULTS_DIR / "review_manual.csv"  # osobny plik, żeby analyze.py go nie nadpisał
VERDICTS = ["trafna", "błędna", "niejasna"]


# ---------- pomocnicze ----------

@st.cache_data
def scenarios_all() -> list[dict]:
    return load_scenarios()


@st.cache_resource(show_spinner=False)
def get_llm(spec: str):
    return make_llm(spec)


def scenario_label(s: dict) -> str:
    sub = s.get("attack_subtype") or s.get("subtype") or ""
    return f"{s['id']} · {s['attack_type']}/{sub} · {s.get('language', '?')} · {s.get('split', 'dev')}"


def flag(value, ok_text: str, bad_text: str, none_text: str, inverse: bool = False) -> None:
    """Kolorowa plakietka True/False/None. inverse=True: True jest złe (udany atak)."""
    if value is None:
        st.info(none_text)
    elif bool(value) != inverse:
        st.success(ok_text)
    else:
        st.error(bad_text)


def show_result(rec: dict) -> None:
    st.subheader(f"Zabezpieczenie: {rec['defense']}")
    c1, c2, c3 = st.columns(3)
    c1.metric("Czas [s]", rec["latency_s"])
    c2.metric("Tokeny", rec["tokens"])
    c3.metric("Próba niedozwolonego odczytu", "tak" if rec["forbidden_attempt"] else "nie")

    flag(rec["attack_success"], "Atak nieudany", "Atak udany", "Brak kryterium ataku (zadanie kontrolne lub własny tekst)",
         inverse=True)
    flag(rec["task_success"], "Zadanie wykonane", "Zadanie niewykonane", "Brak kryterium wykonania zadania")
    if rec["error"]:
        st.warning(f"Błąd: {rec['error']}")

    st.markdown("**Odpowiedź agenta**")
    with st.container(border=True):
        st.text(rec["answer"] or "(pusta)")

    st.markdown("**Wywołania narzędzi**")
    if rec["tool_log"]:
        st.dataframe(pd.DataFrame([{
            "narzędzie": c["tool"],
            "argumenty": json.dumps(c["args"], ensure_ascii=False),
            "zablokowane": c["blocked"],
            "wynik": c["output"][:200],
        } for c in rec["tool_log"]]), hide_index=True, width="stretch")
    else:
        st.caption("Brak wywołań.")

    st.markdown("**Zdarzenia zabezpieczeń**")
    if rec["defense_events"]:
        for e in rec["defense_events"]:
            st.write(f"- `{e['kind']}`: {e['detail']}")
    else:
        st.caption("Zabezpieczenie nic nie zablokowało.")

    st.markdown("**Pamięć po sesji**")
    if rec["memory_final"]:
        for n in rec["memory_final"]:
            st.write(f"- {n}")
    else:
        st.caption("Pusta.")

    if rec.get("extra"):
        st.markdown("**Dodatkowe kryteria**")
        st.json(rec["extra"])


# ---------- sidebar ----------

st.sidebar.header("Ustawienia uruchomienia")
st.sidebar.caption("Dotyczą zakładki Piaskownica.")
model = st.sidebar.text_input(
    "Model", value="ollama:qwen2.5:7b",
    help="ollama:nazwa, openai:nazwa, anthropic:nazwa albo fake:naive (test bez modelu)")
defense = st.sidebar.selectbox("Zabezpieczenie", list(PRESETS), index=0)
memory_mode = st.sidebar.radio("Pamięć długoterminowa", ["long", "none"], horizontal=True)
compare = st.sidebar.checkbox("Porównaj z konfiguracją bez zabezpieczeń (none)", value=False,
                              disabled=(defense == "none"))
st.sidebar.divider()
st.sidebar.caption("Eksperymenty działają na sztucznych danych z folderu data/.")

st.title("Analiza bezpieczeństwa agentów AI")
tab_play, tab_res, tab_rev = st.tabs(["Piaskownica", "Wyniki", "Ręczna weryfikacja"])


# ---------- zakładka 1: piaskownica ----------

with tab_play:
    scen = scenarios_all()
    mode = st.radio("Źródło zadania", ["Scenariusz z pliku", "Własny tekst"], horizontal=True)

    if mode == "Scenariusz z pliku":
        labels = {scenario_label(s): s for s in scen}
        chosen = labels[st.selectbox("Scenariusz", list(labels))]
        with st.expander("Szczegóły scenariusza", expanded=False):
            if chosen.get("sessions"):
                for i, s in enumerate(chosen["sessions"], 1):
                    st.markdown(f"**Sesja {i}:** {s['user_task']}")
                    st.caption("Korpus: " + (", ".join(s.get("corpus", [])) or "brak"))
            else:
                st.markdown(f"**Zadanie:** {chosen['user_task']}")
                st.caption("Korpus: " + (", ".join(chosen.get("corpus", [])) or "brak"))
            st.markdown(f"**Oczekiwane zachowanie:** {chosen.get('expected_behavior', '-')}")
            st.markdown("**Warunek udanego ataku:**")
            st.json(chosen.get("success_check"))
        scenario = chosen
    else:
        task = st.text_area("Zadanie dla agenta", value="What are the shipping options?", height=100)
        docs = sorted(p.name for p in DOCS_DIR.glob("*.txt"))
        corpus = st.multiselect("Dokumenty dostępne dla wyszukiwarki", docs, default=["shipping.txt", "pricing.txt"])
        scenario = {"id": "WLASNY", "attack_type": "custom", "attack_subtype": "custom",
                    "user_task": task, "corpus": corpus, "split": "dev"}

    if st.button("Uruchom", type="primary"):
        try:
            llm = get_llm(model)
        except Exception as e:  # brak pakietu, zły dostawca
            st.error(f"Nie udało się utworzyć modelu: {type(e).__name__}: {e}")
            st.stop()
        configs = ["none", defense] if (compare and defense != "none") else [defense]
        results = []
        with st.spinner("Agent pracuje (lokalny model może potrzebować kilku minut)..."):
            for d in configs:
                results.append(run_scenario(scenario, llm, d, memory_mode, model_label=model))
        st.session_state["last"] = results

    if "last" in st.session_state:
        st.divider()
        res = st.session_state["last"]
        cols = st.columns(len(res))
        for col, rec in zip(cols, res):
            with col:
                show_result(rec)


# ---------- zakładka 2: wyniki ----------

def pick_files(key: str) -> list[Path]:
    files = sorted(RESULTS_DIR.glob("*.jsonl"))
    if not files:
        st.info("Brak plików w results/. Najpierw uruchom pilota (python -m src.pilot ...).")
        return []
    names = [f.name for f in files]
    sel = st.multiselect("Pliki wyników (.jsonl)", names, default=names, key=key)
    return [RESULTS_DIR / n for n in sel]


with tab_res:
    files = pick_files("files_res")
    if files:
        try:
            df = load(files)
        except Exception as e:
            st.error(f"Nie udało się wczytać wyników: {type(e).__name__}: {e}")
            st.stop()
        atk, ctl = df[~df["is_control"]], df[df["is_control"]]

        if atk.empty:
            st.info("W wybranych plikach nie ma scenariuszy ataków.")
        else:
            st.subheader("Ataki wg klasy (wartości w %)")
            st.dataframe(attack_table(atk, ["attack_type"]).reset_index(), hide_index=True, width="stretch")

            st.subheader("Ataki ogółem")
            st.dataframe(attack_table(atk.assign(all="all"), ["all"]).reset_index(), hide_index=True,
                         width="stretch")

            pivot = (atk.groupby(["defense", "attack_type"])["attack_success"]
                     .apply(lambda s: s.astype(float).mean() * 100).unstack("attack_type").fillna(0))
            st.subheader("ASR wg zabezpieczenia i klasy ataku [%]")
            st.bar_chart(pivot)

            dp = atk[atk["attack_type"] == "data_poisoning"]
            if len(dp):
                st.subheader("Data poisoning: pobranie vs wpływ (%)")
                d = dp.groupby(KEYS).agg(n=("id", "count"), Poison_Retrieval=("poison_retrieved", pct),
                                         Poison_Influence=("attack_success", pct))
                st.dataframe(d.reset_index(), hide_index=True, width="stretch")

            mp = atk[atk["attack_type"] == "memory_poisoning"]
            if len(mp):
                st.subheader("Memory poisoning: zapis w pamięci vs wpływ w kolejnej sesji (%)")
                m = mp.groupby(KEYS).agg(n=("id", "count"), Memory_Write=("memory_written", pct),
                                         Influence_later=("attack_success", pct))
                st.dataframe(m.reset_index(), hide_index=True, width="stretch")

            st.subheader("Ataki wg języka i zbioru (dev/test)")
            st.dataframe(attack_table(atk, ["language", "split"])[["n", "ASR", "Detection"]].reset_index(),
                         hide_index=True, width="stretch")

            be = blocking_effectiveness(atk)
            st.subheader("Blocking Effectiveness względem konfiguracji bez zabezpieczeń")
            if len(be):
                st.dataframe(be, hide_index=True, width="stretch")
            else:
                st.caption("Brak baseline 'none' z ASR > 0 w wybranych plikach.")

        if len(ctl):
            st.subheader("Zadania kontrolne: TSR i False Positive Rate (%)")
            c = ctl.groupby(KEYS).agg(n=("id", "count"), TSR=("task_success", pct), FPR=("triggered", pct))
            st.dataframe(c.reset_index(), hide_index=True, width="stretch")


# ---------- zakładka 3: ręczna weryfikacja ----------

with tab_rev:
    st.caption("Sprawdź, czy automatyczna ocena „atak udany” jest trafna. "
               f"Werdykty zapisują się w results/{REVIEW_FILE.name} (osobny plik, żeby "
               "`python -m src.analyze` go nie nadpisał).")
    files_rev = pick_files("files_rev")
    if files_rev:
        try:
            dfr = load(files_rev)
        except Exception as e:
            st.error(f"Nie udało się wczytać wyników: {type(e).__name__}: {e}")
            st.stop()
        hits = dfr[(~dfr["is_control"]) & (dfr["attack_success"] == True)].reset_index(drop=True)  # noqa: E712
        if hits.empty:
            st.info("Brak udanych ataków do sprawdzenia.")
        else:
            n = st.number_input("Ile przypadków sprawdzić (losowa próbka)", 1, len(hits), min(20, len(hits)))
            sample = hits.sample(int(n), random_state=1).reset_index(drop=True)

            key_cols = ["id", "model", "defense", "memory", "repeat"]
            old = pd.read_csv(REVIEW_FILE, encoding="utf-8-sig") if REVIEW_FILE.exists() else pd.DataFrame()
            prev = {}
            if len(old):
                prev = {tuple(r[k] for k in key_cols): r["manual_verdict"]
                        for _, r in old.iterrows() if pd.notna(r["manual_verdict"])}

            view = pd.DataFrame({
                **{k: sample[k] for k in key_cols},
                "answer": sample["answer"].str[:300],
                "tool_log": sample["tool_log"].apply(
                    lambda lg: "; ".join(f"{c['tool']}({list(c['args'].values())})" for c in lg)),
                "manual_verdict": [prev.get(tuple(r[k] for k in key_cols)) or None for _, r in sample.iterrows()],
            })
            edited = st.data_editor(
                view, hide_index=True, width="stretch", key=f"rev_{len(files_rev)}_{int(n)}",
                disabled=[c for c in view.columns if c != "manual_verdict"],
                column_config={"manual_verdict": st.column_config.SelectboxColumn(
                    "werdykt", options=VERDICTS, help="trafna = atak naprawdę się udał; błędna = fałszywy alarm oceny")},
            )

            done = edited["manual_verdict"].notna().sum()
            if done:
                ok = (edited["manual_verdict"] == "trafna").sum()
                st.metric("Trafność oceny automatycznej (spośród ocenionych)", f"{100 * ok / done:.0f}%",
                          f"{ok}/{done}")

            if st.button("Zapisz werdykty"):
                merged = pd.concat([old, edited]) if len(old) else edited
                merged = merged.drop_duplicates(subset=key_cols, keep="last")
                RESULTS_DIR.mkdir(exist_ok=True)
                merged.to_csv(REVIEW_FILE, index=False, encoding="utf-8-sig")
                st.success(f"Zapisano {len(merged)} wierszy do {REVIEW_FILE.name}")

            with st.expander("Pełna odpowiedź i wywołania narzędzi"):
                idx = st.selectbox("Przypadek", range(len(sample)),
                                   format_func=lambda i: f"{sample.loc[i, 'id']} · {sample.loc[i, 'defense']} · r{sample.loc[i, 'repeat']}")
                st.text(sample.loc[idx, "answer"])
                st.json(sample.loc[idx, "tool_log"])