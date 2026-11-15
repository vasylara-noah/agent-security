"""Kontrola środowiska przed pierwszym uruchomieniem.

    python -m src.check_setup                      (domyślnie model ollama:qwen2.5:7b)
    python -m src.check_setup --model ollama:qwen2.5:3b
"""
import argparse
import importlib
import json
import sys
import urllib.error
import urllib.request


def ok(msg):
    print(f"[ OK ] {msg}")


def fail(msg, hint=""):
    print(f"[BŁĄD] {msg}")
    if hint:
        print(f"       -> {hint}")
    return False


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="ollama:qwen2.5:7b")
    a = ap.parse_args()
    good = True

    if sys.version_info >= (3, 10):
        ok(f"Python {sys.version.split()[0]}")
    else:
        good = fail(f"Python {sys.version.split()[0]} jest za stary", "zainstaluj Python 3.12")

    for mod in ["langgraph", "langchain_core", "langchain_ollama", "pandas", "matplotlib", "dotenv"]:
        try:
            importlib.import_module(mod)
            ok(f"pakiet {mod}")
        except ImportError:
            good = fail(f"brak pakietu {mod}", "uruchom: pip install -r requirements.txt (w aktywnym .venv)")

    provider, _, name = a.model.partition(":")
    if provider == "ollama":
        try:
            with urllib.request.urlopen("http://localhost:11434/api/tags", timeout=5) as r:
                tags = json.load(r)
            names = [m["name"] for m in tags.get("models", [])]
            ok("serwer Ollama odpowiada")
            if name in names or f"{name}:latest" in names:
                ok(f"model {name} jest pobrany")
            else:
                good = fail(f"model {name} nie jest pobrany (jest: {names or 'brak'})", f"uruchom: ollama pull {name}")
        except (urllib.error.URLError, OSError):
            good = fail("serwer Ollama nie odpowiada na localhost:11434",
                        "uruchom aplikację Ollama (ikona w zasobniku) albo w osobnym terminalu: ollama serve")
    if not good:
        print("\nPopraw błędy powyżej i uruchom ponownie.")
        return 1

    print("\nTest agenta: pytanie '17*23' powinno wywołać kalkulator i dać 391 ...")
    from .agent import make_llm
    from .runner import load_scenarios, run_scenario

    sc = next(s for s in load_scenarios() if s["id"] == "CT-002")
    rec = run_scenario(sc, make_llm(a.model), "none", "long", a.model, 1)
    used_calc = any(c["tool"] == "calculator" for c in rec["tool_log"])
    print(f"       odpowiedź: {rec['answer'][:120]!r}  ({rec['latency_s']} s)")
    if rec["error"]:
        return 0 if fail(f"błąd podczas uruchomienia: {rec['error']}") else 1
    ok("agent odpowiedział") if rec["task_success"] else fail("odpowiedź nie zawiera 391")
    ok("model wywołał narzędzie (tool calling działa)") if used_calc else fail(
        "model nie wywołał kalkulatora", "ten model może nie wspierać tool callingu; użyj qwen2.5:7b albo llama3.1:8b")
    print("\nGotowe. Możesz uruchomić: python -m src.pilot --model", a.model, "--quick")
    return 0


if __name__ == "__main__":
    sys.exit(main())
