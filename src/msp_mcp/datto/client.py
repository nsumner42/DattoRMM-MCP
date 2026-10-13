"""Datto RMM API v2 client: OAuth token, rate limiting, pagination, retries."""

from __future__ import annotations

from mcp.server.mcpserver.exceptions import ToolError

import asyncio
import os
import time
from typing import Any

import httpx

from msp_mcp.core.credentials import load_machine_credential
from msp_mcp.core.ratelimit import RateLimiter

DEFAULT_API_URL = "https://pinotage-api.centrastage.net"
PAGE_SIZE = 250


class DattoError(ToolError, RuntimeError):  # ToolError: the message reaches the model
    pass


class DattoClient:
    def __init__(self, api_url: str | None = None, credential_prefix: str = "DattoRmmApi"):
        self.base = (api_url or os.environ.get("DATTO_API_URL") or DEFAULT_API_URL).rstrip("/")
        self._key, self._secret = load_machine_credential(credential_prefix)
        self._token: str | None = None
        self._token_expires = 0.0
        # Datto allows 600 reads/min per account; stay well under it.
        self._limiter = RateLimiter(per_second=6, burst=20)
        self._http = httpx.AsyncClient(timeout=60)

    async def _get_token(self, force: bool = False) -> str:
        if self._token and not force and time.monotonic() < self._token_expires:
            return self._token
        r = await self._http.post(
            f"{self.base}/auth/oauth/token",
            auth=("public-client", "public"),
            data={"grant_type": "password", "username": self._key, "password": self._secret},
        )
        if r.status_code != 200:
            raise DattoError(f"Datto sign-in failed: HTTP {r.status_code}")
        body = r.json()
        self._token = body["access_token"]
        self._token_expires = time.monotonic() + int(body.get("expires_in", 3600)) - 300
        return self._token

    async def request(self, method: str, path: str, *, params: dict | None = None,
                      json: Any = None) -> Any:
        url = path if path.startswith("http") else f"{self.base}/api{path}"
        refreshed = False
        for attempt in range(5):
            await self._limiter.acquire()
            token = await self._get_token()
            r = await self._http.request(method, url, params=params, json=json,
                                         headers={"Authorization": f"Bearer {token}"})
            if r.status_code == 401 and not refreshed:
                await self._get_token(force=True)
                refreshed = True
                continue
            if r.status_code == 429 or r.status_code >= 500:
                await asyncio.sleep(float(r.headers.get("Retry-After", 2 ** attempt)))
                continue
            if r.status_code >= 400:
                try:
                    msg = r.json().get("error") or r.json().get("message") or r.text
                except ValueError:
                    msg = r.text
                raise DattoError(f"{method} {path}: HTTP {r.status_code} {msg}")
            if not r.content:
                return None
            try:
                return r.json()
            except ValueError:
                return r.text
        raise DattoError(f"{method} {path}: gave up after repeated 429/5xx responses")

    async def get(self, path: str, params: dict | None = None) -> Any:
        return await self.request("GET", path, params=params)

    async def get_all(self, path: str, key: str, params: dict | None = None,
                      limit: int | None = None) -> list[dict]:
        """Follow pageDetails.nextPageUrl and return the concatenated `key` lists."""
        items: list[dict] = []
        body = await self.get(path, {**(params or {}), "max": PAGE_SIZE})
        while True:
            items.extend(body.get(key) or [])
            nxt = (body.get("pageDetails") or {}).get("nextPageUrl")
            if not nxt or (limit and len(items) >= limit):
                return items[:limit] if limit else items
            body = await self.get(nxt)

    async def aclose(self) -> None:
        await self._http.aclose()
