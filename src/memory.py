import json
from pathlib import Path


class Memory:
    """Pamięć długoterminowa agenta: lista notatek w pliku JSON."""

    def __init__(self, path: Path):
        self.path = Path(path)
        if not self.path.exists():
            self.path.write_text("[]", encoding="utf-8")

    def all(self) -> list[str]:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def add(self, note: str) -> None:
        notes = self.all()
        notes.append(note)
        self.path.write_text(json.dumps(notes, ensure_ascii=False), encoding="utf-8")
