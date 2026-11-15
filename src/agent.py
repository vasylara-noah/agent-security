"""Jedna sesja agenta (ReAct na LangGraph)."""
import time
import warnings

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langgraph.prebuilt import create_react_agent

warnings.filterwarnings("ignore", message="create_react_agent has been moved")

from .config import MAX_STEPS, SYSTEM_PROMPT
from .defenses import Defense
from .memory import Memory
from .tools import build_tools


def make_llm(spec: str):
    """spec np. 'openai:gpt-4o-mini', 'ollama:qwen2.5:7b', 'anthropic:claude-haiku-5-5'."""
    provider, _, name = spec.partition(":")
    if provider == "openai":
        from langchain_openai import ChatOpenAI
        return ChatOpenAI(model=name, temperature=0)
    if provider == "ollama":
        from langchain_ollama import ChatOllama
        return ChatOllama(model=name, temperature=0)
    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(model=name, temperature=0)
    if provider == "fake":  # atrapa do testu potoku, nie do wyników
        from .fake_llm import FakeAgentLLM
        return FakeAgentLLM()
    raise ValueError(f"Nieznany dostawca modelu: {provider}")


def _text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):  # niektóre modele zwracają listę bloków
        return " ".join(b.get("text", "") if isinstance(b, dict) else str(b) for b in content)
    return str(content)


def run_session(llm, user_msg: str, corpus: list[str], defense: Defense,
                memory: Memory | None, tool_log: list[dict]) -> dict:
    """Zwraca {'answer', 'latency_s', 'tokens', 'error'}."""
    if defense.user_input_blocked(user_msg):
        return {"answer": "[BLOCKED by input filter]", "latency_s": 0.0, "tokens": 0, "error": None}

    system = SYSTEM_PROMPT
    if memory is not None and memory.all():
        notes = "\n".join(f"- {n}" for n in memory.all())
        system += f"\n\nLong-term memory notes saved earlier:\n{notes}"

    tools = build_tools(defense, corpus, memory, tool_log)
    agent = create_react_agent(llm, tools)

    start = time.perf_counter()
    error = None
    try:
        result = agent.invoke(
            {"messages": [SystemMessage(content=system), HumanMessage(content=user_msg)]},
            config={"recursion_limit": MAX_STEPS},
        )
        msgs = result["messages"]
    except Exception as e:  # np. limit kroków, błąd API
        msgs, error = [], f"{type(e).__name__}: {e}"[:200]
    latency = time.perf_counter() - start

    answer = ""
    tokens = 0
    for m in msgs:
        if isinstance(m, AIMessage):
            answer = _text(m.content) or answer
            tokens += (getattr(m, "usage_metadata", None) or {}).get("total_tokens", 0)
    answer = defense.clean_answer(answer)
    return {"answer": answer, "latency_s": round(latency, 2), "tokens": tokens, "error": error}
