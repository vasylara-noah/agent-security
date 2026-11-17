# Instrukcja: jak uruchomić pilota na swoim laptopie (Windows + PyCharm)

Wszystko działa lokalnie i za darmo (model przez Ollamę). Agent nie ma dostępu do niczego poza folderem `data/`, więc laptopowi nic nie grozi. Wirtualne środowisko `.venv` trzyma biblioteki osobno od reszty systemu.

## 1. Pobranie projektu
Rozpakuj `agent-security.zip`, np. do `C:\projekty\agent-security`. W PyCharmie: File -> Open -> wybierz ten folder.

## 2. Środowisko wirtualne
W PyCharmie otwórz Terminal (pasek na dole) i wpisz:

    python -m venv .venv
    .venv\Scripts\Activate.ps1
    pip install -r requirements.txt

Gdy PowerShell odmówi uruchomienia skryptu: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, potem jeszcze raz aktywacja. Na początku linii powinno pojawić się `(.venv)`.

Interpreter w PyCharmie: File -> Settings -> Project -> Python Interpreter -> Add Interpreter -> Add Local Interpreter -> Existing -> wskaż `.venv\Scripts\python.exe`.

## 3. Ollama i model
1. Zainstaluj Ollamę z ollama.com i zostaw ją uruchomioną (ikona w zasobniku).
2. W terminalu: `ollama pull qwen2.5:7b` (około 5 GB, potrzeba mniej więcej 8 GB wolnej RAM).
3. Słaby laptop: `ollama pull qwen2.5:3b` i wszędzie niżej wpisuj `ollama:qwen2.5:3b`. Wyniki będą gorsze, bo mały model słabiej wywołuje narzędzia.

## 4. Test bez modelu (30 sekund)
Sprawdza, że kod i scenariusze działają, jeszcze zanim ruszy Ollama:

    python -m pytest -q
    python -m src.pilot --model fake:naive --quick

Pierwsze polecenie powinno dać same zielone testy. Drugie przepuści scenariusze przez atrapę modelu i wypisze tabele. To tylko test potoku, liczby nie mają znaczenia badawczego (przykład w `docs/sample_output_fake.txt`).

## 5. Kontrola przed pierwszym prawdziwym uruchomieniem

    python -m src.check_setup

Skrypt sprawdza Pythona, pakiety, czy Ollama odpowiada, czy model jest pobrany i czy zadaje się mu pytanie "17*23" tak, że wywołuje kalkulator. Przy każdym błędzie podpowiada, co zrobić.

## 6. Pierwsze uruchomienie systemu
Najpierw jeden scenariusz, żeby zobaczyć, że wszystko się łączy:

    python -m src.runner --model ollama:qwen2.5:7b --defense none --only PI-001

W wyniku zobaczysz linię `attack=True/False task=True/False`. Pełny log (odpowiedź, wywołane narzędzia, pamięć, czas) jest w `results/*.jsonl`.

Potem szybki pilot: baseline i wszystkie zabezpieczenia naraz, tylko na ręcznych scenariuszach:

    python -m src.pilot --model ollama:qwen2.5:7b --quick --split dev

To 23 scenariusze razy 2 konfiguracje (bez zabezpieczeń i `combined`). Skrypt pokazuje postęp i szacowany czas. Na CPU liczcie od kilkunastu minut do paru godzin, na karcie graficznej dużo szybciej. Ctrl+C przerywa, zapisane wyniki zostają.

## 7. Pełny pilot
Wygenerowane warianty (zbiór `test`) są już w repozytorium. Gdy chcesz nowe: `python -m src.generator --per-family 6 --seed 42`.

    python -m src.pilot --model ollama:qwen2.5:7b --repeats 3 --memory-ablation

Uruchamia 5 konfiguracji zabezpieczeń (`none`, `input_filter`, `tool_permissions`, `output_validation`, `combined`) plus baseline bez pamięci długoterminowej (do hipotezy H3), po 3 powtórzenia każdego scenariusza. To już kilkaset uruchomień, więc zostaw na noc albo zacznij od `--repeats 1`.

## 8. Wyniki
`python -m src.analyze` liczy wszystko z `results/*.jsonl` i zapisuje:
- `results/summary_attacks.csv`: tabela ASR, TSR, Detection, FNR po klasach ataków,
- `results/asr_by_defense.png`: wykres,
- `results/review_sample.csv`: do 20 losowych "udanych" ataków do ręcznego sprawdzenia (wpisz werdykt w `manual_verdict`).

Jak czytać: ASR = jak często atak się udał, TSR = jak często agent mimo to wykonał zadanie, FPR (zadania kontrolne) = jak często zabezpieczenie zablokowało zwykłe pytanie, BE = o ile procent zabezpieczenie zmniejszyło ASR względem baseline. Zabezpieczenie, które blokuje wszystko, ale psuje TSR i podnosi FPR, nie jest dobre.

## 9. Interfejs graficzny (opcjonalnie)
Zamiast wiersza poleceń można uruchamiać scenariusze i oglądać wyniki w przeglądarce. Po `pip install -r requirements.txt` (doszedł pakiet `streamlit`), z głównego katalogu projektu i przy aktywnym `.venv`:

    streamlit run src/gui.py

Strona otworzy się pod adresem `http://localhost:8501`. Zakładki:
- **Piaskownica**: wybierz scenariusz z `data/scenarios/` albo wpisz własne zadanie, ustaw model, zabezpieczenie i pamięć w panelu po lewej, kliknij „Uruchom". Opcja „Porównaj z konfiguracją bez zabezpieczeń" pokazuje dwa przebiegi obok siebie. Model `fake:naive` pozwala sprawdzić interfejs bez Ollamy.
- **Wyniki**: tabele i wykres z `results/*.jsonl` (te same funkcje co `python -m src.analyze`).
- **Ręczna weryfikacja**: losowa próbka „udanych" ataków do oceny przez człowieka (werdykt: trafna / błędna / niejasna). Zapis idzie do `results/review_manual.csv`.

Pełny pilot (cała macierz konfiguracji) nadal uruchamiaj przez `python -m src.pilot`, bo w przeglądarce trwałoby to zbyt długo. Zamknięcie interfejsu: Ctrl+C w terminalu.

## 10. Git
    git init
    git add .
    git commit -m "pilot: srodowisko, scenariusze, runner"
Potem prywatne repo na GitHubie i `git remote add origin ...`, `git push`. `.gitignore` pomija `.venv`, `.env` i `results/`.

## Typowe problemy
- `ModuleNotFoundError`: nie jest aktywne `.venv` albo nie zrobiłeś `pip install -r requirements.txt`.
- W wynikach same `error` z "connection refused": Ollama nie działa, uruchom ją.
- Model "nie używa narzędzi" (`task=False` w CT-002): za mały model, użyj `qwen2.5:7b` albo `llama3.1:8b`.
- `GraphRecursionError` w kolumnie `error`: agent zapętlił się, przebieg jest policzony jako nieudany atak i nieudane zadanie.
- Polskie lub rosyjskie znaki jako `?` w konsoli: to tylko wyświetlanie, w plikach wyników jest poprawny UTF-8.
