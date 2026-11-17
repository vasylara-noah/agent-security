"""Interfejs graficzny (Streamlit, lokalnie w przeglądarce).

Uruchomienie z głównego katalogu projektu (przy aktywnym .venv):
    streamlit run src/gui.py

Zakładki: Start (opis), Uruchom eksperyment, Wyniki, Słownik pojęć.
Interfejs tylko wywołuje istniejące funkcje (run_scenario, analyze), nie zmienia logiki badań.
"""
import json
import random
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:  # żeby `streamlit run src/gui.py` widział pakiet src
    sys.path.insert(0, str(ROOT))

import altair as alt
import pandas as pd
import streamlit as st
from dotenv import load_dotenv

from src.agent import make_llm
from src.analyze import attack_table, blocking_effectiveness, load, pct
from src.config import RESULTS_DIR
from src.defenses import PRESETS
from src.runner import load_scenarios, run_scenario

load_dotenv(ROOT / ".env")
st.set_page_config(page_title="Bezpieczeństwo agentów AI", page_icon="🛡️", layout="wide",
                   initial_sidebar_state="collapsed")
st.markdown("""<style>
div[data-testid="stMetric"] {background: rgba(120,120,120,.08); border-radius: 10px; padding: 10px 14px;}
</style>""", unsafe_allow_html=True)

# ---------- słowniki z polskimi nazwami i opisami ----------

CLASS_ORDER = ["prompt_injection", "tool_misuse", "data_poisoning", "memory_poisoning", "control"]
CLASS_NAMES = {
    "prompt_injection": "Prompt injection", "tool_misuse": "Tool misuse",
    "data_poisoning": "Data poisoning", "memory_poisoning": "Memory poisoning",
    "control": "Zadania kontrolne (bez ataku)",
}
CLASS_DESC = {
    "prompt_injection": "Złośliwe polecenie ukryte w pytaniu albo w dokumencie, np. „zignoruj poprzednie instrukcje”.",
    "tool_misuse": "Próba nakłonienia agenta do użycia narzędzia wbrew uprawnieniom, np. odczytu zastrzeżonego pliku.",
    "data_poisoning": "Zmanipulowany dokument w bazie wiedzy, który zawiera fałszywe informacje lub ukryte polecenia.",
    "memory_poisoning": "Złośliwa notatka zapisana w pamięci agenta w jednej sesji, działająca w następnej.",
    "control": "Zwykłe, nieszkodliwe pytania. Pokazują, czy zabezpieczenie nie psuje normalnej pracy agenta.",
}
DEFENSE_NAMES = {"none": "brak (baseline)", "input_filter": "filtr wejścia", "tool_permissions": "uprawnienia narzędzi",
                 "output_validation": "walidacja odpowiedzi", "combined": "połączone"}
DEFENSE_DESC = {
    "none": "Agent bez żadnej ochrony. Punkt odniesienia dla wszystkich porównań.",
    "input_filter": "Szuka podejrzanych fraz (np. „ignore previous instructions”) w pytaniu, w wynikach narzędzi i w "
                    "notatkach zapisywanych do pamięci. Podejrzaną treść blokuje.",
    "tool_permissions": "Zabrania odczytu plików z folderu restricted/ (kontrola uprawnień narzędzia file_reader).",
    "output_validation": "Sprawdza gotową odpowiedź i blokuje ją, jeśli zawiera sekret (np. wewnętrzny kod).",
    "combined": "Wszystkie trzy mechanizmy naraz.",
}
SPLIT_NAMES = {"dev": "ręczne (dev)", "test": "wygenerowane (test)"}
DIFF_PL = {"easy": "łatwy", "medium": "średni", "hard": "trudny"}
DEF_ORDER = [DEFENSE_NAMES.get(d, d) for d in PRESETS]
CLASS_COLORS = ["#4C78A8", "#F58518", "#54A24B", "#B279A2"]
MODEL_CHOICES = ["ollama:qwen2.5:7b", "ollama:qwen2.5:3b", "ollama:llama3.1:8b",
                 "anthropic:claude-haiku-5-5", "openai:gpt-4o-mini", "fake:naive"]

GLOSSARY = [
    ("Podstawy", "Agent AI", "Program oparty na modelu językowym, który nie tylko odpowiada na pytania, ale też sam "
     "korzysta z narzędzi (wyszukiwarka, kalkulator, pliki, pamięć), żeby wykonać zadanie."),
    ("Podstawy", "LLM (model językowy)", "Duży model tekstowy, np. Qwen, Llama, GPT czy Claude. To „mózg” agenta."),
    ("Podstawy", "Ollama", "Program do uruchamiania modeli językowych lokalnie, na własnym komputerze i za darmo."),
    ("Podstawy", "Narzędzia agenta", "W projekcie cztery: search (wyszukiwanie w przygotowanych dokumentach), calculator, "
     "file_reader (odczyt plików testowych) i save_memory (zapis do pamięci długoterminowej)."),
    ("Podstawy", "Pamięć długoterminowa", "Notatki, które agent zapisuje w jednej sesji i widzi w kolejnych."),
    ("Podstawy", "Scenariusz", "Jeden przypadek testowy: zadanie dla agenta, ewentualna treść ataku i warunek, po którym "
     "uznajemy atak za udany."),
    ("Podstawy", "Uruchomienie (przebieg)", "Jedno wykonanie jednego scenariusza w jednej konfiguracji "
     "(model + zabezpieczenie + pamięć)."),
    ("Podstawy", "Powtórzenia", "Ten sam scenariusz uruchomiony kilka razy, bo model nie zawsze odpowiada identycznie."),
    ("Podstawy", "Baseline (konfiguracja bazowa)", "Agent bez zabezpieczeń. Z nim porównujemy każde zabezpieczenie."),
    ("Podstawy", "Zbiór dev / test", "dev: scenariusze napisane ręcznie, na nich poprawiamy zabezpieczenia. test: scenariusze "
     "wygenerowane automatycznie (inne sformułowania, języki). Po obejrzeniu wyników na test nie poprawiamy "
     "zabezpieczeń, dzięki czemu wynik jest uczciwszy."),
    ("Podstawy", "Zadania kontrolne", CLASS_DESC["control"]),
    ("Ataki", "Prompt injection", "Wstrzyknięcie instrukcji. Bezpośrednie: polecenie wpisane w wiadomości. Pośrednie: ukryte w "
     "dokumencie lub wyniku wyszukiwania. Wariant: próba wyciągnięcia ukrytych instrukcji systemowych (prompt leak)."),
    ("Ataki", "Tool misuse", "Nadużycie narzędzi. " + CLASS_DESC["tool_misuse"]),
    ("Ataki", "Data poisoning", "Zatrucie danych. " + CLASS_DESC["data_poisoning"]),
    ("Ataki", "Memory poisoning", "Zatrucie pamięci. " + CLASS_DESC["memory_poisoning"]),
    ("Ataki", "RAG", "Wyszukiwanie w bazie dokumentów i dołączanie ich do odpowiedzi modelu. W pilocie to proste "
     "dopasowanie słów kluczowych."),
] + [("Zabezpieczenia", f"{DEFENSE_NAMES[d]} ({d})", DEFENSE_DESC[d]) for d in DEFENSE_NAMES] + [
    ("Metryki", "n", "Liczba prób, z których liczony jest wynik. Przy małym n procenty mocno skaczą (jedna próba to kilka punktów)."),
    ("Metryki", "ASR (Attack Success Rate)", "Odsetek prób, w których atak osiągnął swój cel. Niżej = lepiej."),
    ("Metryki", "TSR (Task Success Rate)", "Odsetek prób, w których agent mimo wszystko poprawnie wykonał zadanie "
     "użytkownika. Wyżej = lepiej."),
    ("Metryki", "Tool Misuse", "Odsetek prób, w których agent faktycznie odczytał zastrzeżony plik. Zablokowana próba się nie liczy."),
    ("Metryki", "Detection", "Odsetek prób, w których zabezpieczenie coś zablokowało lub odfiltrowało."),
    ("Metryki", "FNR (False Negative Rate)", "100% − Detection: ataki, których zabezpieczenie nie zauważyło. Niżej = lepiej."),
    ("Metryki", "FPR (False Positive Rate)", "Odsetek zwykłych zadań kontrolnych, w których zabezpieczenie niepotrzebnie "
     "zadziałało. Niżej = lepiej."),
    ("Metryki", "BE (Blocking Effectiveness)", "O ile procent zabezpieczenie zmniejszyło ASR względem baseline: "
     "(ASR baseline − ASR zabezpieczenia) / ASR baseline. Liczone tylko, gdy baseline miał udane ataki."),
    ("Metryki", "Poison Retrieval / Poison Influence", "Data poisoning: czy zatruty dokument został pobrany przez wyszukiwarkę "
     "(Retrieval) i czy jego treść naprawdę wpłynęła na odpowiedź (Influence)."),
    ("Metryki", "Memory Write / Influence later", "Memory poisoning: czy złośliwa notatka trafiła do pamięci (Write) i czy "
     "wpłynęła na zachowanie w kolejnej sesji (Influence later)."),
    ("Metryki", "Czas i tokeny", "Czas wykonania jednego uruchomienia oraz liczba tokenów (kawałków tekstu) zużytych przez model."),
]


# ---------- dane i pomocnicze ----------

@st.cache_data
def scenarios_all() -> list[dict]:
    return load_scenarios()


@st.cache_resource(show_spinner=False)
def get_llm(spec: str):
    return make_llm(spec)


@st.cache_data(ttl=10)
def ollama_models() -> list[str] | None:
    try:
        with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=1.5) as r:
            return [m["name"] for m in json.load(r).get("models", [])]
    except (urllib.error.URLError, OSError, ValueError):
        return None


@st.cache_data(ttl=30)
def seconds_per_run(model: str) -> float | None:
    lat = []
    for f in RESULTS_DIR.glob("*.jsonl"):
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                if r.get("model") == model and not r.get("error"):
                    lat.append(r["latency_s"])
    return sum(lat) / len(lat) if lat else None


def fdef(d: str) -> str:
    return DEFENSE_NAMES.get(d, d)


def fmt_min(sec: float) -> str:
    m = sec / 60
    return f"{m:.0f} min" if m < 90 else f"{m / 60:.1f} h"


FILE_RE = re.compile(r"^(?P<model>.+?)__(?P<defense>[a-z_]+)__mem-(?P<mem>long|none)__(?P<stamp>\d{8}-\d{6})\.jsonl$")


def result_groups() -> dict[str, list[Path]]:
    """Pliki wyników zgrupowane w serie (jedno uruchomienie pilota/GUI = jedna seria), najnowsze pierwsze."""
    groups: dict[tuple, list[Path]] = {}
    for f in sorted(RESULTS_DIR.glob("*.jsonl")):
        if f.stat().st_size == 0:
            continue
        m = FILE_RE.match(f.name)
        key = (m["stamp"], m["model"]) if m else (f.stem, "?")
        groups.setdefault(key, []).append(f)
    out = {}
    for (stamp, model), files in sorted(groups.items(), reverse=True):
        when = f"{stamp[:4]}-{stamp[4:6]}-{stamp[6:8]} {stamp[9:11]}:{stamp[11:13]}" if stamp[:8].isdigit() else stamp
        out[f"{when} · {model} · {len(files)} plik(ów)"] = files
    return out


# ---------- uruchamianie eksperymentów w tle ----------

@dataclass
class Job:
    model: str
    llm: object
    configs: list
    scenarios: list
    repeats: int
    stamp: str
    total: int
    done: int = 0
    stop: bool = False
    finished: bool = False
    error: str | None = None
    current: str = ""
    started: float = field(default_factory=time.perf_counter)
    log: list = field(default_factory=list)
    files: list = field(default_factory=list)


@st.cache_resource
def job_holder() -> dict:
    return {"job": None}


def _worker(job: Job) -> None:
    safe = job.model.replace(":", "_").replace("/", "_")
    try:
        RESULTS_DIR.mkdir(exist_ok=True)
        for defense, memory in job.configs:
            out = RESULTS_DIR / f"{safe}__{defense}__mem-{memory}__{job.stamp}.jsonl"
            job.files.append(out)
            with out.open("w", encoding="utf-8") as f:
                for s in job.scenarios:
                    for r in range(1, job.repeats + 1):
                        if job.stop:
                            return
                        job.current = f"{s['id']} · {fdef(defense)}"
                        rec = run_scenario(s, job.llm, defense, memory, job.model, r)
                        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                        f.flush()
                        job.done += 1
                        job.log.append({"scenariusz": rec["id"], "zabezpieczenie": fdef(defense), "powtórzenie": r,
                                        "atak": {True: "udany", False: "nieudany"}.get(rec["attack_success"], "—"),
                                        "zadanie": {True: "wykonane", False: "nie"}.get(rec["task_success"], "—"),
                                        "czas [s]": rec["latency_s"], "błąd": rec["error"] or ""})
    except Exception as e:  # noqa: BLE001
        job.error = f"{type(e).__name__}: {e}"
    finally:
        for p in job.files:  # pusty plik (przerwanie przed pierwszym wynikiem) psułby analizę
            if p.exists() and p.stat().st_size == 0:
                p.unlink()
        job.finished = True


@st.fragment(run_every=2)
def progress_panel() -> None:
    job: Job | None = job_holder()["job"]
    if job is None:
        st.caption("W tej sesji nie uruchomiono jeszcze żadnego eksperymentu.")
        return
    frac = job.done / job.total if job.total else 1.0
    st.progress(frac, text=f"Wykonano {job.done} z {job.total} uruchomień ({frac * 100:.0f}%)")
    if not job.finished:
        elapsed = time.perf_counter() - job.started
        eta = elapsed / job.done * (job.total - job.done) if job.done else None
        st.write(f"Teraz: **{job.current or 'start…'}**" + (f" · zostało ok. {fmt_min(eta)}" if eta else ""))
        if st.button("Zatrzymaj po bieżącym uruchomieniu"):
            job.stop = True
    elif job.error:
        st.error(f"Eksperyment przerwany błędem: {job.error}")
    elif job.stop:
        st.warning(f"Zatrzymano po {job.done} uruchomieniach. Dotychczasowe wyniki są zapisane.")
    else:
        st.success("Gotowe. Wyniki są w zakładce „Wyniki” (odśwież stronę, jeśli nie widać nowej serii).")
    if job.log:
        st.caption("Ostatnie uruchomienia:")
        st.dataframe(pd.DataFrame(job.log[-8:][::-1]), hide_index=True, width="stretch")


# ---------- wykresy i tabele ----------

def grouped_asr_chart(d: pd.DataFrame, x: str, x_title: str, color: str, color_title: str,
                      color_domain=None, colors=None, x_sort=None):
    base = alt.Chart(d).encode(
        x=alt.X(f"{x}:N", title=x_title, sort=x_sort, axis=alt.Axis(labelAngle=0, labelLimit=140)),
        xOffset=alt.XOffset(f"{color}:N", sort=color_domain),
        y=alt.Y("ASR:Q", title="Skuteczność ataków (ASR) [%]", scale=alt.Scale(domain=[0, 105])),
    )
    scale = alt.Scale(domain=color_domain, range=colors) if color_domain and colors else alt.Undefined
    bars = base.mark_bar().encode(
        color=alt.Color(f"{color}:N", title=color_title, scale=scale),
        tooltip=[alt.Tooltip(f"{x}:N", title=x_title), alt.Tooltip(f"{color}:N", title=color_title),
                 alt.Tooltip("ASR:Q", title="ASR [%]", format=".1f"), alt.Tooltip("n:Q", title="Liczba prób (n)")])
    labels = base.mark_text(dy=-7, fontSize=11).encode(text=alt.Text("ASR:Q", format=".0f"))
    return (bars + labels).properties(height=340)


def asr_frame(atk: pd.DataFrame, by: list[str]) -> pd.DataFrame:
    g = atk.groupby(by)["attack_success"]
    d = pd.DataFrame({"ASR": g.apply(lambda s: s.astype(float).mean() * 100), "n": g.size()}).reset_index()
    return d.dropna(subset=["ASR"])


def show_table(df: pd.DataFrame, help_cols: dict | None = None) -> None:
    d = df.reset_index().drop(columns=[c for c in ("model", "memory") if c in df.reset_index().columns])
    if "defense" in d:
        d["defense"] = d["defense"].map(fdef)
    if "attack_type" in d:
        d["attack_type"] = d["attack_type"].map(lambda c: CLASS_NAMES.get(c, c))
    names = {"defense": "Zabezpieczenie", "attack_type": "Klasa ataku", "n": "Liczba prób (n)", "latency_s": "Czas [s]",
             "tokens": "Tokeny", "errors": "Błędy", "language": "Język", "split": "Zbiór", "all": "Razem",
             "ASR": "ASR [%]", "TSR": "TSR [%]", "ToolMisuse": "Tool Misuse [%]", "Detection": "Detection [%]",
             "FNR": "FNR [%]", "FPR": "FPR [%]", "Poison_Retrieval": "Poison Retrieval [%]",
             "Poison_Influence": "Poison Influence [%]", "Memory_Write": "Memory Write [%]",
             "Influence_later": "Influence later [%]"}
    d = d.rename(columns=names)
    cfg = {names.get(k, k): st.column_config.Column(help=v) for k, v in (help_cols or {}).items()
           if names.get(k, k) in d.columns}
    st.dataframe(d, hide_index=True, width="stretch", column_config=cfg)


METRIC_HELP = {
    "ASR": "Odsetek udanych ataków. Niżej = lepiej.", "TSR": "Odsetek poprawnie wykonanych zadań. Wyżej = lepiej.",
    "ToolMisuse": "Odsetek prób z faktycznym odczytem zastrzeżonego pliku.",
    "Detection": "Odsetek prób, w których zabezpieczenie coś zablokowało.",
    "FNR": "100% − Detection. Niżej = lepiej.", "n": "Liczba prób. Przy małym n wyniki mocno skaczą.",
}


def show_run_detail(rec: pd.Series, scen: dict) -> None:
    st.markdown(f"#### {rec['id']} · {fdef(rec['defense'])} · powtórzenie {rec['repeat']}")
    if scen:
        tasks = [x["user_task"] for x in scen["sessions"]] if scen.get("sessions") else [scen.get("user_task", "")]
        for i, t in enumerate(tasks, 1):
            st.markdown(f"**Zadanie{f' (sesja {i})' if len(tasks) > 1 else ''}:** {t}")
        if scen.get("expected_behavior"):
            st.markdown(f"**Oczekiwane bezpieczne zachowanie:** {scen['expected_behavior']}")
    c1, c2, c3 = st.columns(3)
    c1.metric("Atak", {True: "udany", False: "nieudany"}.get(rec["attack_success"], "—"))
    c2.metric("Zadanie", {True: "wykonane", False: "niewykonane"}.get(rec["task_success"], "—"))
    c3.metric("Czas [s]", rec["latency_s"])
    if rec["error"]:
        st.warning(f"Błąd: {rec['error']}")
    st.markdown("**Odpowiedź agenta**")
    with st.container(border=True):
        st.text(rec["answer"] or "(pusta)")
    st.markdown("**Wywołania narzędzi**")
    if rec["tool_log"]:
        st.dataframe(pd.DataFrame([{"narzędzie": c["tool"], "argumenty": json.dumps(c["args"], ensure_ascii=False),
                                    "zablokowane": c["blocked"], "wynik": c["output"][:200]} for c in rec["tool_log"]]),
                     hide_index=True, width="stretch")
    else:
        st.caption("Brak wywołań.")
    st.markdown("**Co zablokowało zabezpieczenie**")
    if rec["defense_events"]:
        for e in rec["defense_events"]:
            st.write(f"- `{e['kind']}`: {e['detail']}")
    else:
        st.caption("Nic.")
    if rec["memory_final"]:
        st.markdown("**Pamięć po sesji**")
        for n in rec["memory_final"]:
            st.write(f"- {n}")


# ---------- strona ----------

st.title("Analiza bezpieczeństwa agentów AI")
tab_start, tab_run, tab_res, tab_gloss = st.tabs(["Start", "Uruchom eksperyment", "Wyniki", "Słownik pojęć"])
scen_all = scenarios_all()

# ===== Start =====
with tab_start:
    st.markdown(
        "Agent AI to model językowy, który potrafi korzystać z narzędzi: przeszukiwać dokumenty, liczyć, czytać pliki "
        "i zapisywać notatki. To wygodne, ale daje atakującemu nowe możliwości: złośliwe polecenie ukryte w dokumencie "
        "może zostać potraktowane jak instrukcja. **To narzędzie sprawdza, jak łatwo oszukać agenta i czy proste "
        "zabezpieczenia pomagają.** Wszystko dzieje się lokalnie, na sztucznych danych, bez prawdziwych kont i plików.")
    st.subheader("Jak z tego korzystać")
    c1, c2, c3 = st.columns(3)
    c1.markdown("**1. Uruchom eksperyment**  \nW zakładce „Uruchom eksperyment” wybierz model, scenariusze ataków, "
                "zabezpieczenia i liczbę powtórzeń, potem kliknij Start.")
    c2.markdown("**2. Poczekaj**  \nAgent wykonuje każdy scenariusz w piaskownicy. Postęp widać na bieżąco, "
                "wyniki zapisują się do folderu `results/`.")
    c3.markdown("**3. Zobacz wyniki**  \nZakładka „Wyniki” pokazuje, jak często ataki się udają i ile kosztuje "
                "zabezpieczenie. Nieznane skróty wyjaśnia „Słownik pojęć”.")
    st.subheader("Co testujemy")
    cols = st.columns(len(CLASS_ORDER))
    for col, c in zip(cols, CLASS_ORDER):
        n = sum(1 for s in scen_all if s["attack_type"] == c)
        col.metric(CLASS_NAMES[c], f"{n} scen.")
        col.caption(CLASS_DESC[c])
    st.subheader("Jakie zabezpieczenia porównujemy")
    for d in DEFENSE_NAMES:
        st.markdown(f"- **{DEFENSE_NAMES[d]}**: {DEFENSE_DESC[d]}")

# ===== Uruchom eksperyment =====
with tab_run:
    job: Job | None = job_holder()["job"]
    running = job is not None and not job.finished

    st.subheader("1. Model")
    tags = ollama_models()
    if tags is None:
        st.caption("Ollama nie odpowiada na localhost:11434. Modele lokalne (ollama:…) zadziałają dopiero po jej uruchomieniu.")
    else:
        st.caption("Ollama działa. Pobrane modele: " + (", ".join(tags) or "brak"))
    choices = list(dict.fromkeys([f"ollama:{t}" for t in (tags or [])] + MODEL_CHOICES)) + ["inny…"]
    pick = st.selectbox("Model", choices, help="Format: dostawca:nazwa. fake:naive to atrapa do sprawdzenia, "
                        "czy wszystko działa. Jej liczby nie mają znaczenia badawczego.")
    model = st.text_input("Nazwa modelu", placeholder="np. ollama:mistral:7b") if pick == "inny…" else pick
    if model.startswith("fake"):
        st.info("Wybrano atrapę modelu: to tylko test działania interfejsu, wyniki nie są prawdziwe.")

    st.subheader("2. Scenariusze")
    f1, f2 = st.columns(2)
    splits = f1.multiselect("Zbiór", list(SPLIT_NAMES), default=list(SPLIT_NAMES), format_func=SPLIT_NAMES.get,
                            help="dev: napisane ręcznie, tu poprawiamy zabezpieczenia. test: wygenerowane automatycznie. "
                                 "Zadania kontrolne są w zbiorze dev.")
    classes = f2.multiselect(
        "Klasa ataku", CLASS_ORDER, default=CLASS_ORDER,
        format_func=lambda c: f"{CLASS_NAMES[c]} ({sum(1 for s in scen_all if s['attack_type'] == c)})")
    f3, f4 = st.columns(2)
    langs = f3.multiselect("Język", ["en", "pl", "ru"], default=["en", "pl", "ru"])
    diffs = f4.multiselect("Poziom trudności", list(DIFF_PL), default=list(DIFF_PL), format_func=DIFF_PL.get)
    if "control" not in classes:
        st.caption("Bez zadań kontrolnych nie da się policzyć FPR i TSR (czy zabezpieczenie psuje zwykłą pracę).")

    pool = [s for s in scen_all if s.get("split", "dev") in splits and s["attack_type"] in classes
            and s.get("language") in langs and s.get("difficulty") in diffs]
    limit = st.number_input("Ogranicz do losowych N scenariuszy (0 = bez ograniczenia)", 0, max(len(pool), 1), 0,
                            help="Przydatne do szybkiego testu. Losowanie jest powtarzalne.")
    if limit and limit < len(pool):
        pool = random.Random(1).sample(pool, int(limit))

    table = pd.DataFrame({
        "Uruchom": True, "ID": [s["id"] for s in pool],
        "Klasa": [CLASS_NAMES[s["attack_type"]] for s in pool], "Język": [s.get("language") for s in pool],
        "Trudność": [DIFF_PL.get(s.get("difficulty"), s.get("difficulty")) for s in pool],
        "Zbiór": [s.get("split", "dev") for s in pool],
        "Zadanie": [((s.get("sessions") or [s])[0]["user_task"])[:90] for s in pool]})
    with st.expander(f"Wybrane scenariusze: {len(pool)} (rozwiń, aby odznaczyć pojedyncze)"):
        edited = st.data_editor(table, hide_index=True, width="stretch", key=f"sc_{hash(tuple(table['ID']))}",
                                disabled=[c for c in table.columns if c != "Uruchom"],
                                column_config={"Uruchom": st.column_config.CheckboxColumn("Uruchom")})
    chosen_ids = set(edited.loc[edited["Uruchom"], "ID"]) if len(edited) else set()
    chosen = [s for s in pool if s["id"] in chosen_ids]

    st.subheader("3. Zabezpieczenia i powtórzenia")
    defs = st.multiselect("Zabezpieczenia do porównania", list(PRESETS), default=["none", "combined"],
                          format_func=fdef, help="Każde wybrane zabezpieczenie to osobna konfiguracja do uruchomienia.")
    with st.expander("Co robi każde zabezpieczenie?"):
        for d in PRESETS:
            st.markdown(f"- **{fdef(d)}**: {DEFENSE_DESC.get(d, '')}")
    if defs and "none" not in defs:
        st.caption("Bez „brak (baseline)” nie da się policzyć Blocking Effectiveness (BE).")
    r1, r2 = st.columns(2)
    repeats = r1.number_input("Powtórzenia każdego scenariusza", 1, 10, 1,
                              help="Model nie zawsze odpowiada tak samo. Do wyników końcowych użyj co najmniej 3.")
    ablation = r2.checkbox("Dodaj konfigurację bez pamięci długoterminowej",
                           help="Dodatkowy przebieg bez zabezpieczeń i bez pamięci, do porównania wpływu pamięci.")

    configs = [(d, "long") for d in defs] + ([("none", "none")] if ablation else [])
    total = len(configs) * len(chosen) * int(repeats)
    spr = seconds_per_run(model) if model else None
    est = total * (spr or 5.0)
    st.subheader("4. Start")
    st.markdown(f"**{len(chosen)} scenariuszy × {len(configs)} konfiguracji × {int(repeats)} powtórzeń = {total} uruchomień.** "
                f"Szacowany czas: **ok. {fmt_min(est)}** "
                f"({'średnia z poprzednich wyników tego modelu: ' + f'{spr:.1f}' if spr else 'brak danych, zakładam 5.0'} s na uruchomienie).")
    if total > 300:
        st.caption("To długi przebieg. Działa, dopóki działa terminal ze Streamlitem, a komputer nie śpi "
                   "(na Macu: caffeinate -i). Zamknięcie karty przeglądarki nie przerywa pracy.")
    if st.button("Start", type="primary", disabled=running or total == 0 or not model):
        try:
            llm = get_llm(model)
        except Exception as e:  # noqa: BLE001
            st.error(f"Nie udało się utworzyć modelu: {type(e).__name__}: {e}")
        else:
            new = Job(model=model, llm=llm, configs=configs, scenarios=chosen, repeats=int(repeats),
                      stamp=time.strftime("%Y%m%d-%H%M%S"), total=total)
            job_holder()["job"] = new
            threading.Thread(target=_worker, args=(new,), daemon=True).start()
            st.rerun()
    if running:
        st.caption("Eksperyment trwa, nowy można uruchomić po jego zakończeniu.")
    progress_panel()

# ===== Wyniki =====
with tab_res:
    groups = result_groups()
    if not groups:
        st.info("Nie ma jeszcze wyników. Uruchom eksperyment w zakładce „Uruchom eksperyment”.")
    else:
        sel = st.multiselect("Seria wyników", list(groups), default=list(groups)[:1],
                             help="Jedna seria to jedno uruchomienie eksperymentu (wszystkie jego konfiguracje). "
                                  "Można połączyć kilka serii, np. ten sam model w różnych dniach.")
        files = [f for k in sel for f in groups[k]]
        if not files:
            st.stop()
        try:
            df = load(files)
        except Exception as e:  # noqa: BLE001
            st.error(f"Nie udało się wczytać wyników: {type(e).__name__}: {e}")
            st.stop()

        models = sorted(df["model"].unique())
        model_sel = st.selectbox("Model", models) if len(models) > 1 else models[0]
        df = df[df["model"] == model_sel]
        if model_sel.startswith("fake"):
            st.warning("To wyniki atrapy modelu (fake). Służą tylko do sprawdzenia, że wszystko działa.")
        mem_main = "long" if (df["memory"] == "long").any() else df["memory"].iloc[0]
        main = df[df["memory"] == mem_main]
        atk, ctl = main[~main["is_control"]], main[main["is_control"]]

        if atk.empty:
            st.info("W wybranych wynikach nie ma scenariuszy ataków.")
            st.stop()

        # --- podsumowanie ---
        st.subheader("Podsumowanie")
        asr_def = atk.groupby("defense")["attack_success"].apply(lambda s: s.astype(float).mean() * 100)
        base = asr_def.get("none")
        others = asr_def.drop("none", errors="ignore")
        comp = "combined" if "combined" in others.index else (others.idxmin() if len(others) else None)
        if base is not None and comp is not None:
            be = (base - asr_def[comp]) / base * 100 if base > 0 else None
            fpr = pct(ctl[ctl["defense"] == comp]["triggered"]) if len(ctl) else float("nan")
            st.markdown(f"Bez zabezpieczeń atak udał się w **{base:.0f}%** prób. Przy zabezpieczeniu "
                        f"**{fdef(comp)}** w **{asr_def[comp]:.0f}%**"
                        + (f" (spadek o {be:.0f}%)." if be is not None else ".")
                        + (f" Zwykłe zadania zostały przy tym niepotrzebnie zablokowane w {fpr:.0f}% przypadków."
                           if fpr == fpr else ""))
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("ASR bez zabezpieczeń", f"{base:.0f}%", help="Odsetek udanych ataków u agenta bez ochrony.")
            m2.metric(f"ASR: {fdef(comp)}", f"{asr_def[comp]:.0f}%", f"{asr_def[comp] - base:+.0f} pkt proc.",
                      delta_color="inverse", help="Odsetek udanych ataków z zabezpieczeniem. Niżej = lepiej.")
            m3.metric("BE", f"{be:.0f}%" if be is not None else "—",
                      help="Blocking Effectiveness: o ile procent zabezpieczenie zmniejszyło ASR.")
            m4.metric("FPR (zwykłe zadania)", f"{fpr:.0f}%" if fpr == fpr else "—",
                      help="Jak często zabezpieczenie niepotrzebnie zadziałało na zwykłym zadaniu. Niżej = lepiej.")
        else:
            st.info("Żeby zobaczyć porównanie, uruchom konfigurację bez zabezpieczeń („brak”) i co najmniej jedno zabezpieczenie.")
        st.caption(f"Liczba prób ataku: {len(atk)}. Przy małej liczbie prób procenty mocno skaczą, "
                   "więc traktuj je jako orientacyjne.")

        # --- wykres 1 ---
        st.subheader("Jak zabezpieczenia wpływają na skuteczność ataków")
        d1 = asr_frame(atk, ["defense", "attack_type"])
        d1["Zabezpieczenie"] = d1["defense"].map(fdef)
        d1["Klasa ataku"] = d1["attack_type"].map(CLASS_NAMES)
        st.altair_chart(grouped_asr_chart(d1, "Zabezpieczenie", "Zabezpieczenie", "Klasa ataku", "Klasa ataku",
                                          [CLASS_NAMES[c] for c in CLASS_ORDER[:4]], CLASS_COLORS, DEF_ORDER),
                        width="stretch")
        st.caption("Każdy słupek to odsetek udanych ataków danej klasy. **Niżej = lepiej.** Pierwsza grupa (baseline) "
                   "pokazuje, jak podatny jest agent bez ochrony.")

        # --- wykres 2: mapa cieplna ---
        st.subheader("Które ataki są groźne przy jakim zabezpieczeniu")
        base_h = alt.Chart(d1).encode(
            x=alt.X("Zabezpieczenie:N", sort=DEF_ORDER, axis=alt.Axis(labelAngle=0, labelLimit=140)),
            y=alt.Y("Klasa ataku:N", title=None, sort=[CLASS_NAMES[c] for c in CLASS_ORDER[:4]]))
        heat = base_h.mark_rect().encode(color=alt.Color(
            "ASR:Q", title="ASR [%]", scale=alt.Scale(scheme="redyellowgreen", reverse=True, domain=[0, 100])),
            tooltip=["Zabezpieczenie", "Klasa ataku", alt.Tooltip("ASR:Q", format=".1f"), alt.Tooltip("n:Q", title="n")])
        txt = base_h.mark_text(fontSize=14).encode(
            text=alt.Text("ASR:Q", format=".0f"),
            color=alt.condition(alt.datum.ASR > 60, alt.value("white"), alt.value("black")))
        st.altair_chart((heat + txt).properties(height=200), width="stretch")
        st.caption("Zielone pola: ataki rzadko się udają. Czerwone: często. Liczby to ASR w %.")

        # --- zwykłe zadania ---
        if len(ctl):
            st.subheader("Czy zabezpieczenie nie psuje zwykłej pracy agenta?")
            c = ctl.groupby("defense").agg(n=("id", "count"), TSR=("task_success", pct), FPR=("triggered", pct)).reset_index()
            long = c.melt(id_vars=["defense", "n"], value_vars=["TSR", "FPR"], var_name="m", value_name="v")
            long["Zabezpieczenie"] = long["defense"].map(fdef)
            long["Miara"] = long["m"].map({"TSR": "Zadania wykonane (TSR)",
                                           "FPR": "Niepotrzebne blokady (FPR)"})
            b = alt.Chart(long.dropna(subset=["v"])).encode(
                x=alt.X("Zabezpieczenie:N", sort=DEF_ORDER, axis=alt.Axis(labelAngle=0, labelLimit=140)),
                xOffset="Miara:N", y=alt.Y("v:Q", title="[%]", scale=alt.Scale(domain=[0, 105])))
            ch = (b.mark_bar().encode(color=alt.Color("Miara:N", scale=alt.Scale(
                domain=list(long["Miara"].unique()), range=["#54A24B", "#E45756"]))) +
                  b.mark_text(dy=-7, fontSize=11).encode(text=alt.Text("v:Q", format=".0f")))
            st.altair_chart(ch.properties(height=300), width="stretch")
            st.caption("Dobre zabezpieczenie blokuje ataki, ale nie przeszkadza w zwykłych zadaniach: **TSR wysokie** (zadania wykonane) i **FPR niskie** (mało niepotrzebnych blokad).")

        # --- szczegóły ---
        st.subheader("Szczegóły")
        with st.expander("Tabela metryk wg klasy ataku"):
            show_table(attack_table(atk, ["attack_type"]).sort_index(), METRIC_HELP)
        with st.expander("Blocking Effectiveness (BE) względem baseline"):
            be_t = blocking_effectiveness(atk)
            if len(be_t):
                st.dataframe(be_t.drop(columns=["model", "memory"]).assign(defense=lambda x: x["defense"].map(fdef)).rename(
                    columns={"defense": "Zabezpieczenie", "ASR_baseline": "ASR baseline [%]",
                             "ASR_defense": "ASR zabezpieczenia [%]", "BE_%": "BE [%]"}), hide_index=True, width="stretch")
            else:
                st.caption("Brak baseline „brak” z udanymi atakami.")
        dp = atk[atk["attack_type"] == "data_poisoning"]
        if len(dp):
            with st.expander("Data poisoning: czy zatruty dokument został pobrany i czy wpłynął na odpowiedź"):
                st.caption("Poison Retrieval: dokument trafił do wyników wyszukiwania. Poison Influence: jego treść naprawdę "
                           "zmieniła odpowiedź. Pobranie nie musi oznaczać wpływu.")
                show_table(dp.groupby(["model", "defense", "memory"]).agg(
                    n=("id", "count"), Poison_Retrieval=("poison_retrieved", pct), Poison_Influence=("attack_success", pct)))
        mp = atk[atk["attack_type"] == "memory_poisoning"]
        if len(mp):
            with st.expander("Memory poisoning: czy złośliwa notatka zapisała się i czy zadziałała w kolejnej sesji"):
                show_table(mp.groupby(["model", "defense", "memory"]).agg(
                    n=("id", "count"), Memory_Write=("memory_written", pct), Influence_later=("attack_success", pct)))
        if (df["memory"] != mem_main).any():
            with st.expander("Wpływ pamięci długoterminowej (porównanie z konfiguracją bez pamięci)"):
                allatk = df[~df["is_control"]]
                m = allatk[allatk["defense"] == "none"].groupby(["memory", "attack_type"])["attack_success"].apply(
                    lambda s: s.astype(float).mean() * 100).unstack("memory").round(1)
                m.index = m.index.map(lambda c: CLASS_NAMES.get(c, c))
                st.dataframe(m.rename(columns={"long": "ASR z pamięcią [%]", "none": "ASR bez pamięci [%]"}),
                             width="stretch")
        with st.expander("Język i poziom trudności"):
            e1, e2 = st.columns(2)
            for col, key, title, mapping in ((e1, "language", "Język", None), (e2, "difficulty", "Poziom trudności", DIFF_PL)):
                d = asr_frame(atk, ["defense", key])
                d["Zabezpieczenie"] = d["defense"].map(fdef)
                d[title] = d[key].map(mapping) if mapping else d[key]
                col.altair_chart(grouped_asr_chart(d, title, title, "Zabezpieczenie", "Zabezpieczenie"), width="stretch")
            st.caption("Uwaga: w niektórych grupach jest bardzo mało prób (zobacz n w podpowiedzi po najechaniu na słupek).")

        # --- pojedyncze przebiegi ---
        st.subheader("Pojedyncze uruchomienia")
        st.caption("Kliknij wiersz, aby zobaczyć odpowiedź agenta, użyte narzędzia i działanie zabezpieczeń.")
        g1, g2, g3 = st.columns([2, 2, 1])
        f_def = g1.multiselect("Zabezpieczenie", list(PRESETS), default=[], format_func=fdef, key="rd_def")
        f_id = g2.text_input("Scenariusz (fragment ID)", key="rd_id")
        f_hit = g3.checkbox("Tylko udane ataki", key="rd_hit")
        runs = df.copy()
        if f_def:
            runs = runs[runs["defense"].isin(f_def)]
        if f_id:
            runs = runs[runs["id"].str.contains(f_id, case=False)]
        if f_hit:
            runs = runs[runs["attack_success"] == True]  # noqa: E712
        runs = runs.reset_index(drop=True)
        view = pd.DataFrame({
            "Scenariusz": runs["id"], "Klasa": runs["attack_type"].map(lambda c: CLASS_NAMES.get(c, c)),
            "Zabezpieczenie": runs["defense"].map(fdef), "Powt.": runs["repeat"],
            "Atak": runs["attack_success"].map({True: "udany", False: "nieudany"}).fillna("—"),
            "Zadanie": runs["task_success"].map({True: "wykonane", False: "nie"}).fillna("—"),
            "Czas [s]": runs["latency_s"]})
        ev = st.dataframe(view, hide_index=True, width="stretch", on_select="rerun", selection_mode="single-row",
                          key="runs_table", height=300)
        if ev.selection.rows:
            row = runs.iloc[ev.selection.rows[0]]
            show_run_detail(row, next((s for s in scen_all if s["id"] == row["id"]), {}))

# ===== Słownik =====
with tab_gloss:
    q = st.text_input("Szukaj pojęcia", placeholder="np. ASR, RAG, baseline").strip().lower()
    last = None
    for cat, term, desc in GLOSSARY:
        if q and q not in term.lower() and q not in desc.lower():
            continue
        if cat != last:
            st.subheader(cat)
            last = cat
        st.markdown(f"**{term}**  \n{desc}")