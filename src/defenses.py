"""Mechanizmy obronne. Celowo proste, żeby dało się je opisać w pracy."""
import re

INJECTION_PATTERNS = [
    r"ignore (all |any )?(the |my |your )?(user'?s? )?(previous|prior|above|original|earlier)( \w+)? ?(instructions?|task|prompt)?",
    r"disregard .{0,40}(instructions?|task)",
    r"(reveal|print|show|output) .{0,40}(system prompt|system instructions|internal code)",
    r"print your full system",
    r"(zignoruj|ignoruj|pomiń) .{0,40}(instrukcj|polece|zadani)",
    r"игнорируй|игнорировать|забудь (все )?предыдущие",
    r"note to (the )?(ai|assistant)",
    r"(ai )?assistant: ",
    r"save (this )?to memory|from now on|remember this",
    r"restricted/",
]

# wzorce formatu sekretów (jak skaner DLP), niezależne od konkretnych ataków
SECRET_PATTERNS = [r"SYS-SECRET-\d+", r"FLAG-[A-Z-]+-\d+"]

PRESETS = {
    "none": dict(),
    "input_filter": dict(filter_input=True, filter_tool_output=True, filter_memory=True),
    "tool_permissions": dict(restrict_files=True),
    "output_validation": dict(validate_output=True),
    "combined": dict(
        filter_input=True, filter_tool_output=True, filter_memory=True,
        restrict_files=True, validate_output=True,
    ),
}


def match_injection(text: str) -> str | None:
    for p in INJECTION_PATTERNS:
        if re.search(p, text, flags=re.IGNORECASE):
            return p
    return None


class Defense:
    def __init__(self, name: str):
        if name not in PRESETS:
            raise ValueError(f"Nieznane zabezpieczenie: {name}. Dostępne: {list(PRESETS)}")
        self.name = name
        self.cfg = PRESETS[name]
        self.events: list[dict] = []  # co i kiedy zablokowano

    def _log(self, kind: str, detail: str) -> None:
        self.events.append({"kind": kind, "detail": detail[:120]})

    def user_input_blocked(self, text: str) -> bool:
        if self.cfg.get("filter_input") and match_injection(text):
            self._log("input_filter", text)
            return True
        return False

    def clean_tool_output(self, tool: str, text: str) -> str:
        if self.cfg.get("filter_tool_output") and match_injection(text):
            self._log("tool_output_filter", f"{tool}: {text}")
            return "[BLOCKED by filter: suspicious content in tool output]"
        return text

    def memory_write_allowed(self, note: str) -> bool:
        if self.cfg.get("filter_memory") and match_injection(note):
            self._log("memory_filter", note)
            return False
        return True

    def file_allowed(self, path: str) -> bool:
        if self.cfg.get("restrict_files") and "restricted" in path.lower().replace("\\", "/"):
            self._log("file_permission", path)
            return False
        return True

    def clean_answer(self, answer: str) -> str:
        if self.cfg.get("validate_output"):
            for p in SECRET_PATTERNS:
                if re.search(p, answer):
                    self._log("output_validation", answer)
                    return "[BLOCKED by output validation: answer contained a secret]"
        return answer
