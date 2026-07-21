import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import quote, urlsplit, urlunsplit


SENSITIVE_REQUEST_HEADERS = {"authorization", "cookie", "proxy-authorization"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def get_data_dir() -> Path:
    path = Path.home() / ".local" / "pajarori" / "jenknums"
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return path


def get_cache_dir() -> Path:
    path = get_data_dir() / ".cache"
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return path


def safe_name(value: str, max_length: int = 96) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "item"
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:10]
    return f"{cleaned[:max_length]}-{digest}"


def target_slug(url: str) -> str:
    parsed = urlsplit(url)
    raw = f"{parsed.hostname or 'target'}-{parsed.port or ''}{parsed.path or '/'}"
    return safe_name(raw)


def normalize_target(value: str, default_scheme: str = "https") -> str:
    value = value.strip()
    if not value:
        raise ValueError("empty target")
    if "://" not in value:
        value = f"{default_scheme}://{value}"
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"invalid HTTP(S) target: {value}")
    path = parsed.path or "/"
    if not path.endswith("/"):
        path += "/"
    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def same_origin(left: str, right: str) -> bool:
    a, b = urlsplit(left), urlsplit(right)
    a_port = a.port or (443 if a.scheme == "https" else 80)
    b_port = b.port or (443 if b.scheme == "https" else 80)
    return (a.scheme, a.hostname, a_port) == (b.scheme, b.hostname, b_port)


def pin_to_origin(base_url: str, candidate: str) -> str:
    base = urlsplit(base_url)
    parsed = urlsplit(candidate)
    if parsed.scheme and parsed.netloc:
        path, query = parsed.path, parsed.query
    else:
        path, query = parsed.path, parsed.query
    if not path.startswith("/"):
        base_path = base.path if base.path.endswith("/") else base.path + "/"
        path = base_path + path
    return urlunsplit((base.scheme, base.netloc, path, query, ""))


def api_path(url: str) -> str:
    parsed = urlsplit(url)
    return parsed.path + (f"?{parsed.query}" if parsed.query else "")


def quote_jenkins_path(value: str) -> str:
    return quote(value, safe="/@:[](),?=&%+-._~")


def headers_for_report(headers: Iterable) -> Dict[str, str]:
    output: Dict[str, str] = {}
    for key, value in headers:
        if key.lower() not in SENSITIVE_REQUEST_HEADERS:
            output[key] = value
    return output


def read_secret(value: Optional[str], file_path: Optional[str], env_name: str) -> Optional[str]:
    if value:
        return value.strip()
    if file_path:
        return Path(file_path).read_text(encoding="utf-8").strip()
    env_value = os.getenv(env_name)
    return env_value.strip() if env_value else None


def unique(values: Iterable[str]) -> List[str]:
    seen = set()
    result = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=True, indent=2, default=str)
