"""Trzy narzędzia agenta + zapis do pamięci. Każde wywołanie trafia do tool_log."""
import ast
import operator
import re

from langchain_core.tools import StructuredTool

from .config import DOCS_DIR, FILES_DIR
from .defenses import Defense
from .memory import Memory

_OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul,
        ast.Div: operator.truediv, ast.Pow: operator.pow, ast.USub: operator.neg,
        ast.Mod: operator.mod}


def _calc(node):
    if isinstance(node, ast.Expression):
        return _calc(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_calc(node.left), _calc(node.right))
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](_calc(node.operand))
    raise ValueError("unsupported expression")


def _words(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z0-9]+", text.lower()) if len(w) > 2}


def build_tools(defense: Defense, corpus: list[str], memory: Memory | None,
                tool_log: list[dict]) -> list[StructuredTool]:
    """corpus = nazwy plików z data/docs dostępnych dla wyszukiwarki w tym scenariuszu."""

    def record(name, args, result, blocked=False, raw=None):
        """output = to, co zobaczył agent; raw_output = treść przed filtrem (do pomiaru Poison Retrieval)."""
        tool_log.append({"tool": name, "args": args, "output": str(result)[:500],
                         "raw_output": str(result if raw is None else raw)[:1500],
                         "blocked": blocked})

    def search(query: str) -> str:
        """Search the Acme knowledge base. Returns the two most relevant documents."""
        q = _words(query)
        scored = []
        for name in corpus:
            text = (DOCS_DIR / name).read_text(encoding="utf-8")
            scored.append((len(q & _words(text)), name, text))
        scored.sort(key=lambda x: -x[0])
        hits = [f"[{n}]\n{t}" for s, n, t in scored[:2] if s > 0]
        raw = "\n\n".join(hits) if hits else "No documents found."
        out = defense.clean_tool_output("search", raw)
        record("search", {"query": query}, out, raw=raw)
        return out

    def calculator(expression: str) -> str:
        """Evaluate a simple arithmetic expression, e.g. '17*23'."""
        try:
            out = str(_calc(ast.parse(expression, mode="eval")))
        except Exception:
            out = "error: unsupported expression"
        record("calculator", {"expression": expression}, out)
        return out

    def file_reader(path: str) -> str:
        """Read a text file from the shared files folder, e.g. 'report_q3.txt'."""
        if not defense.file_allowed(path):
            out = "Permission denied."
            record("file_reader", {"path": path}, out, blocked=True)
            return out
        target = (FILES_DIR / path).resolve()
        raw = None
        if FILES_DIR.resolve() not in target.parents or not target.is_file():
            out = "File not found."
        else:
            raw = target.read_text(encoding="utf-8")
            out = defense.clean_tool_output("file_reader", raw)
        record("file_reader", {"path": path}, out, raw=raw)
        return out

    tools = [StructuredTool.from_function(search),
             StructuredTool.from_function(calculator),
             StructuredTool.from_function(file_reader)]

    if memory is not None:
        def save_memory(note: str) -> str:
            """Save a short note to long-term memory so it is available in future sessions."""
            if not defense.memory_write_allowed(note):
                out = "Memory write rejected."
                record("save_memory", {"note": note}, out, blocked=True)
                return out
            memory.add(note)
            record("save_memory", {"note": note}, "saved")
            return "saved"

        tools.append(StructuredTool.from_function(save_memory))
    return tools
