"""Asset Panda v2 API client: sign-in, rate limiting, 429 back-off, search paging.

Sign-in needs two credentials: the company API app (client ID + secret, made by a company admin
on the API page) and an Asset Panda user (email + password). The user's rights decide what the
API can see and change.

API facts (tested 2026-10-12):
- POST /session/token -> access_token (no expires_in; re-sign-in on 401).
- GET /entities = collections with their field schema; GET /statuses = all statuses.
- POST /entities/{id}/search_objects?limit&offset, body {"search": text} and/or
  {"field_filters": {field_key: value}}: text fields match case-insensitive "contains";
  linked (EntityListField) and Status fields match by object/status ID only. Max 100 per page.
- GET /entity_objects/{id} = one object.
- Limit ~400 calls / 3 min per IP; over it a plain-text 429 "Retry later", no Retry-After.
"""

from __future__ import annotations

from mcp.server.mcpserver.exceptions import ToolError

import asyncio
import os
import random
from typing import Any

import httpx

from msp_mcp.core.credentials import load_machine_credential
from msp_mcp.core.ratelimit import RateLimiter

DEFAULT_API_URL = "https://login.assetpanda.com/v2"
PAGE_SIZE = 100


class AssetPandaError(ToolError, RuntimeError):  # ToolError: the message reaches the model
    pass


class AssetPandaClient:
    def __init__(self, api_url: str | None = None):
        self.base = (api_url or os.environ.get("ASSETPANDA_API_URL") or DEFAULT_API_URL).rstrip("/")
        self._client_id, self._client_secret = load_machine_credential("AssetPanda")
        self._email, self._password = load_machine_credential("AssetPanda-ApiUser")
        self._token: str | None = None
        # 400 calls / 3 min = 2.2/s; leave room for other users of the same IP.
        self._limiter = RateLimiter(per_second=1.8, burst=10)
        self._http = httpx.AsyncClient(timeout=60)
        self._entities: list[dict] | None = None
        self._statuses: list[dict] | None = None

    @property
    def user(self) -> str:
        return self._email

    async def _sign_in(self) -> str:
        await self._limiter.acquire()
        r = await self._http.post(f"{self.base}/session/token", data={
            "client_id": self._client_id, "client_secret": self._client_secret,
            "email": self._email, "password": self._password,
            "device": "Desktop", "app_version": "2",
        })
        if r.status_code != 200:
            raise AssetPandaError(f"Asset Panda sign-in failed: HTTP {r.status_code} {r.text[:200]}")
        self._token = r.json()["access_token"]
        return self._token

    async def request(self, method: str, path: str, *, params: dict | None = None,
                      json: Any = None) -> Any:
        url = path if path.startswith("http") else f"{self.base}{path}"
        refreshed = False
        for attempt in range(1, 5):
            await self._limiter.acquire()
            token = self._token or await self._sign_in()
            r = await self._http.request(method, url, params=params, json=json,
                                         headers={"Authorization": f"Bearer {token}"})
            if r.status_code == 401 and not refreshed:
                await self._sign_in()
                refreshed = True
                continue
            if r.status_code == 429 and attempt < 4:
                # No Retry-After; the limit window is 3 min but clears within ~15 s of quiet.
                await asyncio.sleep(15 * attempt + random.uniform(0, 5))
                continue
            if r.status_code >= 500 and attempt < 4:
                await asyncio.sleep(2 ** attempt)
                continue
            if r.status_code >= 400:
                try:
                    body = r.json()
                    msg = body.get("message") or body.get("errors") or r.text
                except ValueError:
                    msg = r.text
                raise AssetPandaError(f"{method} {path}: HTTP {r.status_code} {str(msg)[:300]}")
            if not r.content:
                return None
            try:
                return r.json()
            except ValueError:
                return r.text
        raise AssetPandaError(f"{method} {path}: gave up after repeated 429/5xx responses")

    # ------------------------------------------------------------ schema

    async def entities(self, refresh: bool = False) -> list[dict]:
        if self._entities is None or refresh:
            self._entities = await self.request("GET", "/entities")
        return self._entities

    async def statuses(self, refresh: bool = False) -> list[dict]:
        if self._statuses is None or refresh:
            self._statuses = await self.request("GET", "/statuses")
        return self._statuses

    # ------------------------------------------------------------ objects

    async def search(self, entity_id: str, *, text: str | None = None,
                     field_filters: dict[str, str] | None = None,
                     limit: int = PAGE_SIZE, offset: int = 0) -> tuple[list[dict], int]:
        """One page of search_objects. Returns (objects, total matching)."""
        body: dict[str, Any] = {}
        if text:
            body["search"] = text
        if field_filters:
            body["field_filters"] = field_filters
        j = await self.request("POST", f"/entities/{entity_id}/search_objects",
                               params={"limit": min(limit, PAGE_SIZE), "offset": offset}, json=body)
        return j.get("objects") or [], int((j.get("totals") or {}).get("objects") or 0)

    async def search_all(self, entity_id: str, *, text: str | None = None,
                         field_filters: dict[str, str] | None = None,
                         max_items: int | None = None) -> tuple[list[dict], int]:
        """Page through search_objects. Returns (objects, total matching)."""
        items: list[dict] = []
        offset = 0
        while True:
            page, total = await self.search(entity_id, text=text, field_filters=field_filters,
                                            offset=offset)
            items.extend(page)
            offset += len(page)
            if not page or offset >= total or (max_items and len(items) >= max_items):
                return (items[:max_items] if max_items else items), total

    async def get_object(self, object_id: str) -> dict:
        return await self.request("GET", f"/entity_objects/{object_id}")

    async def aclose(self) -> None:
        await self._http.aclose()
