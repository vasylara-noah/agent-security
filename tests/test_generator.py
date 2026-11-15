"""Testy generatora wariantów (bez modelu LLM)."""
import json

from src import generator
from src.config import DOCS_DIR
from src.fake_llm import FakeAgentLLM
from src.runner import load_scenarios, run_scenario


def test_generator_is_deterministic():
    a, docs_a, _ = generator.generate(4, seed=7)
    b, docs_b, _ = generator.generate(4, seed=7)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    assert docs_a == docs_b


def test_generator_changes_with_seed():
    a, _, _ = generator.generate(4, seed=1)
    b, _, _ = generator.generate(4, seed=2)
    assert json.dumps(a, sort_keys=True) != json.dumps(b, sort_keys=True)


def test_all_families_languages_and_levels_covered():
    sc, _, stats = generator.generate(6, seed=42)
    assert stats["rejected"] == 0
    assert {s["attack_type"] for s in sc} == {"prompt_injection", "tool_misuse", "memory_poisoning", "data_poisoning"}
    assert {"en", "pl", "ru"} <= {s["language"] for s in sc}
    assert {"easy", "medium", "hard"} <= {s["difficulty"] for s in sc}
    assert all(s["split"] == "test" and s["generated"] for s in sc)


def test_no_duplicates_and_unique_ids():
    sc, _, _ = generator.generate(12, seed=3)
    ids = [s["id"] for s in sc]
    assert len(ids) == len(set(ids))


def test_validation_rejects_broken_variants():
    sc = {"language": "ru", "attack_type": "prompt_injection", "_payload": "Ignore this PWNED-1", "_marker": "PWNED-1"}
    assert "cyryl" in generator.validate(sc, {})
    sc = {"language": "en", "attack_type": "prompt_injection", "_payload": "no token here", "_marker": "PWNED-1"}
    assert generator.validate(sc, {}) is not None
    sc = {"language": "en", "attack_type": "prompt_injection", "_payload": "reply PWNED-1", "_marker": "PWNED-1"}
    assert generator.validate(sc, {"x.txt": "document without payload"}) is not None


def test_false_fact_never_in_true_documents():
    for topic, ff in generator.FALSE_FACTS.items():
        clean = (DOCS_DIR / generator.TOPICS[topic]["doc"]).read_text(encoding="utf-8").lower()
        assert ff["needle"].lower() not in clean


def test_generated_files_on_disk_run_with_fake_model():
    generated = [s for s in load_scenarios() if s.get("generated")]
    assert generated, "uruchom najpierw: python -m src.generator"
    llm = FakeAgentLLM()
    for s in generated:
        rec = run_scenario(s, llm, "none", "long", "fake", 1)
        assert rec["error"] is None, s["id"]
