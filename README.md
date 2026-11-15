# Analiza bezpieczeństwa agentów AI - etap pilotażowy

Prompt injection, tool misuse, data poisoning i memory poisoning na agencie LangGraph (ReAct) z lokalnym modelem (Ollama). Wszystko na sztucznych danych, w odizolowanym środowisku.

Szybki start: `INSTRUKCJA.md`. Zasady i kryteria sukcesu: `docs/PROTOCOL.md`. Model zagrożeń: `docs/THREAT_MODEL.md`.

    python -m venv .venv && .venv\Scripts\Activate.ps1 && pip install -r requirements.txt
    python -m pytest -q
    python -m src.check_setup
    python -m src.pilot --model ollama:qwen2.5:7b --quick --split dev
    python -m src.analyze

## Komponenty z planu (rozdz. 2.5 PDF) a pliki
| Komponent | Plik |
|---|---|
| Attack Dataset | `data/scenarios/*.json`, `data/docs/`, `data/files/` |
| Attack Generator | `src/generator.py` (szablony, walidacja, ziarno) |
| Agent | `src/agent.py`, `src/tools.py`, `src/memory.py` |
| Defense Layer | `src/defenses.py` (`input_filter`, `tool_permissions`, `output_validation`, `combined`) |
| Experiment Runner | `src/runner.py` (jedna konfiguracja), `src/pilot.py` (cała macierz) |
| Logger | jsonl w `results/` (odpowiedź, narzędzia, pamięć, zdarzenia obrony, czas, tokeny) |
| Evaluation Engine | `src/evaluator.py` (reguły programowe) |
| Results Analyzer | `src/analyze.py` |

## Czego pilot jeszcze nie obejmuje (etap właściwy)
LLM-as-a-Judge, wektorowy RAG (FAISS/Chroma), modele OpenAI/Claude (kod je wspiera przez `--model openai:...` i `anthropic:...`, wymaga kluczy), kilka frameworków, Docker. Wyszukiwarka w pilocie to dopasowanie słów kluczowych.

## Parametry
- `--defense`: none, input_filter, tool_permissions, output_validation, combined
- `--memory`: long (domyślnie) lub none
- `--split`: dev (ręczne), test (wygenerowane), all
- `--repeats`, `--only PI TM-001`, `--model ollama:...|openai:...|anthropic:...|fake:naive`
