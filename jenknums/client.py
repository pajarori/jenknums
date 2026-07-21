import asyncio
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urljoin, urlsplit

import httpx

from .collector import Collector
from .utils import SAFE_METHODS, headers_for_report, pin_to_origin, same_origin


@dataclass
class AuthConfig:
    username: Optional[str] = None
    token: Optional[str] = None
    cookie: Optional[str] = None

    @property
    def enabled(self) -> bool:
        return bool((self.username and self.token) or self.cookie)

    @property
    def mode(self) -> str:
        if self.cookie:
            return "cookie"
        if self.username and self.token:
            return "basic-token"
        return "anonymous"


class JenkinsClient:
    def __init__(
        self,
        base_url: str,
        collector: Collector,
        auth: Optional[AuthConfig] = None,
        verify_tls: bool = True,
        timeout: float = 20.0,
        concurrency: int = 6,
        retries: int = 2,
        sleep_time: float = 0.0,
    ):
        self.base_url = base_url.rstrip("/") + "/"
        self.collector = collector
        self.auth = auth or AuthConfig()
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.retries = retries
        self.sleep_time = sleep_time
        self.semaphore = asyncio.Semaphore(max(1, concurrency))
        self.request_log = []
        self._clients: Dict[str, httpx.AsyncClient] = {}

    async def __aenter__(self):
        common = {
            "verify": self.verify_tls,
            "follow_redirects": False,
            "timeout": httpx.Timeout(self.timeout, connect=min(8.0, self.timeout)),
            "limits": httpx.Limits(max_keepalive_connections=10, max_connections=20),
            "headers": {"User-Agent": "jenknums/0.1.0"},
        }
        self._clients["anonymous"] = httpx.AsyncClient(**common)

        auth = None
        headers = dict(common["headers"])
        if self.auth.username and self.auth.token:
            auth = httpx.BasicAuth(self.auth.username, self.auth.token)
        if self.auth.cookie:
            headers["Cookie"] = self.auth.cookie
        self._clients["authenticated"] = httpx.AsyncClient(
            verify=common["verify"],
            follow_redirects=False,
            timeout=common["timeout"],
            limits=common["limits"],
            headers=headers,
            auth=auth,
        )
        return self

    async def __aexit__(self, exc_type, exc, tb):
        await asyncio.gather(*(client.aclose() for client in self._clients.values()))

    def url(self, path_or_url: str) -> str:
        if urlsplit(path_or_url).scheme:
            return pin_to_origin(self.base_url, path_or_url)
        return urljoin(self.base_url, path_or_url.lstrip("/"))

    def _client(self, context: str) -> httpx.AsyncClient:
        if context == "authenticated" and self.auth.enabled:
            return self._clients["authenticated"]
        return self._clients["anonymous"]

    async def request(
        self,
        method: str,
        path_or_url: str,
        context: str = "anonymous",
        follow: bool = False,
        headers: Optional[Dict[str, str]] = None,
        save_as: Optional[Tuple[str, str]] = None,
        retries: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> httpx.Response:
        method = method.upper()
        if method not in SAFE_METHODS:
            raise ValueError(f"unsafe HTTP method blocked: {method}")

        current_url = self.url(path_or_url)
        client = self._client(context)
        last_error: Optional[Exception] = None

        retry_count = self.retries if retries is None else max(0, retries)
        for attempt in range(retry_count + 1):
            try:
                async with self.semaphore:
                    started = time.monotonic()
                    response = await client.request(
                        method, current_url, headers=headers, timeout=timeout
                    )
                    elapsed = time.monotonic() - started
                self.request_log.append(
                    {
                        "method": method,
                        "url": current_url,
                        "status": response.status_code,
                        "elapsed": round(elapsed, 4),
                        "auth_context": context if self.auth.enabled else "anonymous",
                        "response_headers": headers_for_report(response.headers.multi_items()),
                    }
                )

                redirects = 0
                while follow and response.is_redirect and redirects < 5:
                    location = response.headers.get("location")
                    if not location:
                        break
                    next_url = urljoin(current_url, location)
                    if not same_origin(self.base_url, next_url):
                        break
                    current_url = pin_to_origin(self.base_url, next_url)
                    async with self.semaphore:
                        response = await client.request(
                            method, current_url, headers=headers, timeout=timeout
                        )
                    redirects += 1

                if save_as:
                    self._save_response(response, save_as[0], save_as[1], context)
                if self.sleep_time > 0:
                    await asyncio.sleep(self.sleep_time)
                return response
            except (httpx.HTTPError, OSError) as exc:
                last_error = exc
                if attempt >= retry_count:
                    raise
                await asyncio.sleep(min(0.25 * (2**attempt), 2.0))
        raise last_error or RuntimeError("request failed")

    def _save_response(self, response: httpx.Response, category: str, name: str, context: str) -> None:
        content_type = response.headers.get("content-type", "")
        suffix = ".json" if "json" in content_type else ".xml" if "xml" in content_type else ".html" if "html" in content_type else ".txt"
        metadata = {
            "url": str(response.url),
            "status": response.status_code,
            "auth_context": context if self.auth.enabled else "anonymous",
            "content_type": content_type,
            "headers": headers_for_report(response.headers.multi_items()),
        }
        self.collector.write_bytes(category, name, response.content, suffix=suffix, metadata=metadata)

    async def get_json(
        self,
        path_or_url: str,
        context: str = "anonymous",
        save_as: Optional[Tuple[str, str]] = None,
        retries: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> Tuple[httpx.Response, Optional[Any]]:
        response = await self.request(
            "GET",
            path_or_url,
            context=context,
            save_as=save_as,
            retries=retries,
            timeout=timeout,
        )
        try:
            return response, response.json()
        except (json.JSONDecodeError, ValueError):
            return response, None

    async def stream_to_file(
        self,
        path_or_url: str,
        category: str,
        name: str,
        context: str = "authenticated",
        suffix: str = ".txt",
    ) -> Dict[str, Any]:
        url = self.url(path_or_url)
        client = self._client(context)
        path = self.collector.stream_path(category, name, suffix=suffix)
        async with self.semaphore:
            async with client.stream("GET", url) as response:
                metadata = {
                    "category": category,
                    "name": name,
                    "url": str(response.url),
                    "status": response.status_code,
                    "auth_context": context if self.auth.enabled else "anonymous",
                    "content_type": response.headers.get("content-type", ""),
                    "headers": headers_for_report(response.headers.multi_items()),
                }
                if response.status_code == 200:
                    with path.open("wb") as handle:
                        async for chunk in response.aiter_bytes():
                            handle.write(chunk)
                    metadata["path"] = self.collector.finalize_stream(path, metadata)
                    metadata["size"] = path.stat().st_size
                else:
                    body = await response.aread()
                    metadata["path"] = self.collector.write_bytes(
                        category, name, body, suffix=suffix, metadata=metadata
                    )
                    metadata["size"] = len(body)
                self.request_log.append(
                    {
                        "method": "GET",
                        "url": url,
                        "status": response.status_code,
                        "auth_context": context if self.auth.enabled else "anonymous",
                    }
                )
                return metadata
