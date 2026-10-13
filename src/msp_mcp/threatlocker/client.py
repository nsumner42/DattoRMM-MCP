"""ThreatLocker Portal API client.

Auth: the raw API token in the Authorization header (no "Bearer"). The token belongs to an
organization and sees its child organizations; ManagedOrganizationId scopes a call to one child.

API facts (tested 2026-10-12, instance "f"):
- No usable OpenAPI on the instance (/swagger/v1/swagger.json has no paths, even with the token);
  request shapes come from the community spec (jentic/jentic-public-apis) and tests.
- Lists are POST ...GetByParameters with pageNumber/pageSize; totals come in the `pagination`
  response header (JSON: totalItems, totalPages).
- ActionLog/ActionLogGetByParametersV2 needs the header `usenewsearch: true` (HTTP 500 without it)
  and startDate/endDate. actionId 1 = permit, 2 = deny (includes monitor/learning-mode
  "would deny"), 99 + paramsFieldsDto MonitorOnly=false = real blocks only.
- A revoked token answers HTTP 440 {"error": "TOKEN_REVOKED", ..., "token": <the token>}: the
  token is echoed, so error text is redacted before it is raised.
"""

from __future__ import annotations

from mcp.server.mcpserver.exceptions import ToolError

import asyncio
import json
import os
import re
from typing import Any

import httpx

from msp_mcp.core.credentials import load_machine_credential
from msp_mcp.core.ratelimit import RateLimiter

DEFAULT_API_URL = "https://portalapi.f.threatlocker.com/portalApi"
_TOKEN_IN_BODY = re.compile(r'"token"\s*:\s*"[^"]*"', re.I)


class ThreatLockerError(ToolError, RuntimeError):  # ToolError: the message reaches the model
    pass


class ThreatLockerClient:
    def __init__(self, api_url: str | None = None):
        self.base = (api_url or os.environ.get("THREATLOCKER_API_URL") or DEFAULT_API_URL).rstrip("/")
        _, self._token = load_machine_credential("ThreatLockerApi")
        self._token = self._token.strip()
        self._limiter = RateLimiter(per_second=5, burst=10)
        self._http = httpx.AsyncClient(timeout=120)

    def _clean(self, text: str) -> str:
        text = _TOKEN_IN_BODY.sub('"token":"<redacted>"', text or "")
        return text.replace(self._token, "<redacted>")

    async def request(self, method: str, path: str, *, params: dict | None = None, json_body: Any = None,
                      headers: dict | None = None, org_id: str | None = None) -> tuple[Any, dict | None]:
        """Returns (body, pagination header dict or None)."""
        h = {"Authorization": self._token, "Content-Type": "application/json", **(headers or {})}
        if org_id:
            h["ManagedOrganizationId"] = org_id
        url = f"{self.base}/{path.lstrip('/')}"
        for attempt in range(1, 5):
            await self._limiter.acquire()
            r = await self._http.request(method, url, params=params, json=json_body, headers=h)
            if (r.status_code == 429 or r.status_code >= 502) and attempt < 4:
                await asyncio.sleep(float(r.headers.get("Retry-After", 2 ** attempt)))
                continue
            if r.status_code >= 400:
                raise ThreatLockerError(f"{method} {path}: HTTP {r.status_code} {self._clean(r.text)[:400]}")
            page = None
            if r.headers.get("pagination"):
                try:
                    page = json.loads(r.headers["pagination"])
                except ValueError:
                    page = None
            if not r.content:
                return None, page
            try:
                return r.json(), page
            except ValueError:
                return r.text, page
        raise ThreatLockerError(f"{method} {path}: gave up after repeated 429/5xx responses")

    async def get(self, path: str, params: dict | None = None, **kw) -> Any:
        body, _ = await self.request("GET", path, params=params, **kw)
        return body

    async def post_page(self, path: str, body: dict, **kw) -> tuple[list[dict], int]:
        """One page of a ...GetByParameters list. Returns (rows, totalItems)."""
        rows, page = await self.request("POST", path, json_body=body, **kw)
        rows = rows if isinstance(rows, list) else []
        total = int((page or {}).get("totalItems") or len(rows))
        return rows, total

    async def post_all(self, path: str, body: dict, *, max_items: int, page_size: int = 100,
                       **kw) -> tuple[list[dict], int]:
        """Page through a list until max_items or the end. Returns (rows, totalItems)."""
        items: list[dict] = []
        page_no, total = 1, 0
        size = max(1, min(page_size, max_items))   # constant per run: pageNumber depends on it
        while len(items) < max_items:
            rows, total = await self.post_page(path, {**body, "pageNumber": page_no, "pageSize": size}, **kw)
            items.extend(rows)
            if not rows or len(items) >= total:
                break
            page_no += 1
        return items[:max_items], total

    async def aclose(self) -> None:
        await self._http.aclose()
