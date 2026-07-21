import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from .utils import json_dumps, safe_name


class Collector:
    def __init__(self, root: Path, target: str):
        self.root = root
        self.target = target
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        self.manifest_path = self.root / "manifest.jsonl"

    def resolve(self, category: str, name: str, suffix: str = "") -> Path:
        directory = self.root / safe_name(category)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
        filename = safe_name(name)
        if suffix and not filename.endswith(suffix):
            filename += suffix
        return directory / filename

    def record(self, entry: Dict[str, Any]) -> None:
        with self.manifest_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=True, default=str) + "\n")
        os.chmod(self.manifest_path, 0o600)

    def write_bytes(
        self,
        category: str,
        name: str,
        content: bytes,
        suffix: str = ".bin",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        path = self.resolve(category, name, suffix)
        path.write_bytes(content)
        os.chmod(path, 0o600)
        entry = {"category": category, "name": name, "path": str(path), "size": len(content)}
        if metadata:
            entry.update(metadata)
        self.record(entry)
        return str(path)

    def write_text(
        self,
        category: str,
        name: str,
        content: str,
        suffix: str = ".txt",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        return self.write_bytes(
            category,
            name,
            content.encode("utf-8", errors="replace"),
            suffix=suffix,
            metadata=metadata,
        )

    def write_json(self, category: str, name: str, content: Any) -> str:
        return self.write_text(category, name, json_dumps(content), suffix=".json")

    def stream_path(self, category: str, name: str, suffix: str = ".txt") -> Path:
        return self.resolve(category, name, suffix)

    def finalize_stream(self, path: Path, metadata: Dict[str, Any]) -> str:
        os.chmod(path, 0o600)
        entry = {"path": str(path), "size": path.stat().st_size}
        entry.update(metadata)
        self.record(entry)
        return str(path)
