"""Mimecast API 2.0 client: OAuth client-credentials token, rate limiting, envelope, paging.

API facts (from Mimecast's API 1.0/2.0 docs and wyre-technology/node-mimecast, Apache-2.0;
not yet checked against our tenant):
- One global gateway for API 2.0: https://api.services.mimecast.com. Regional hosts
  (eu-api.mimecast.com, ...) are API 1.0 (HMAC keys) only.
- POST /oauth/token, form body grant_type=client_credentials + client_id + client_secret
  -> access_token, expires_in (~30 min).
- Every call is a POST with {"meta": {"pagination": {"pageSize", "pageToken"}}, "data": [{...}]}.
  The reply is {"meta": {"status", "pagination": {"next", "pageSize", "totalCount"}},
  "data": [...], "fail": [{"errors": [{"code", "message", "retryable"}]}]}; errors can come
  back as HTTP 200 with a non-empty "fail".
- Log endpoints wrap their rows one level deeper: data[0].clickLogs / attachmentLogs /
  impersonationLogs / trackedEmails.
- The API application's role decides what it can read (e.g. Gateway | Tracking | Read).
"""

from __future__ import annotations

from mcp.server.mcpserver.exceptions import ToolError

import asyncio
import os
import random
import time
from typing import Any

import httpx

from msp_mcp.core.credentials import load_machine_credential
from msp_mcp.core.ratelimit import RateLimiter

DEFAULT_API_URL = "https://api.services.mimecast.com"
PAGE_SIZE = 100


class MimecastError(ToolError, RuntimeError):  # ToolError: the message reaches the model
    pass


def _fail_text(fail: Any) -> str:
    msgs = []
    for f in fail or []:
        for e in (f.get("errors") or []) if isinstance(f, dict) else []:
            msgs.append(f"{e.get('code')}: {e.get('message')}")
    return "; ".join(msgs) or str(fail)[:300]


class MimecastClient:
    def __init__(self, api_url: str | None = None):
        self.base = (api_url or os.environ.get("MIMECAST_API_URL") or DEFAULT_API_URL).rstrip("/")
        self._client_id, self._client_secret = load_machine_credential("MimecastApi")
        self._token: str | None = None
        self._token_expires = 0.0
        # Mimecast limits per endpoint per hour; keep a modest steady rate.
        self._limiter = RateLimiter(per_second=2, burst=5)
        self._http = httpx.AsyncClient(timeout=60)

    async def _sign_in(self) -> str:
        await self._limiter.acquire()
        r = await self._http.post(f"{self.base}/oauth/token", data={
            "grant_type": "client_credentials",
            "client_id": self._client_id, "client_secret": self._client_secret,
        })
        if r.status_code != 200:
            raise MimecastError(f"Mimecast sign-in failed: HTTP {r.status_code} {r.text[:200]}")
        j = r.json()
        self._token = j["access_token"]
        # Refresh a minute early.
        self._token_expires = time.monotonic() + max(60, int(j.get("expires_in") or 1800) - 60)
        return self._token

    async def _bearer(self) -> str:
        if self._token and time.monotonic() < self._token_expires:
            return self._token
        return await self._sign_in()

    async def call(self, path: str, data: dict | list | None = None, *,
                   page_size: int | None = None, page_token: str | None = None) -> dict:
        """One POST. Returns the whole reply ({meta, data, fail}); raises on HTTP or fail[] errors."""
        # No filter = "data": [] (get-account rejects [{}] with err_validation_null).
        body: dict[str, Any] = {"data": data if isinstance(data, list) else ([data] if data else [])}
        if page_size or page_token:
            pag: dict[str, Any] = {"pageSize": min(page_size or PAGE_SIZE, 500)}
            if page_token:
                pag["pageToken"] = page_token
            body["meta"] = {"pagination": pag}
        refreshed = False
        for attempt in range(1, 5):
            await self._limiter.acquire()
            token = await self._bearer()
            r = await self._http.post(f"{self.base}{path}", json=body, headers={
                "Authorization": f"Bearer {token}", "Accept": "application/json"})
            if r.status_code == 401 and not refreshed:
                self._token = None
                refreshed = True
                continue
            if r.status_code == 429 and attempt < 4:
                # X-RateLimit-Reset is in milliseconds (API 1.0 convention).
                try:
                    wait = int(r.headers.get("X-RateLimit-Reset", "0")) / 1000
                except ValueError:
                    wait = 0
                await asyncio.sleep(min(max(wait, 5 * attempt), 60) + random.uniform(0, 2))
                continue
            if r.status_code >= 500 and attempt < 4:
                await asyncio.sleep(2 ** attempt)
                continue
            try:
                j = r.json()
            except ValueError:
                j = None
            if r.status_code >= 400:
                detail = _fail_text(j.get("fail")) if isinstance(j, dict) and j.get("fail") else r.text[:300]
                hint = ""
                if r.status_code == 403:
                    hint = " (the API application's role is missing the permission for this endpoint)"
                raise MimecastError(f"POST {path}: HTTP {r.status_code} {detail}{hint}")
            if not isinstance(j, dict):
                raise MimecastError(f"POST {path}: unexpected reply {r.text[:200]}")
            if j.get("fail"):
                raise MimecastError(f"POST {path}: {_fail_text(j['fail'])}")
            return j
        raise MimecastError(f"POST {path}: gave up after repeated 429/5xx responses")

    async def call_all(self, path: str, data: dict | None = None, *, rows_key: str | None = None,
                       max_items: int = 500) -> tuple[list[dict], dict]:
        """Follow meta.pagination.next. Rows are reply.data, or reply.data[0][rows_key] for log
        endpoints. Returns (rows, last meta.pagination)."""
        rows: list[dict] = []
        token: str | None = None
        pag: dict = {}
        while True:
            j = await self.call(path, data, page_size=min(PAGE_SIZE, max_items), page_token=token)
            d = j.get("data") or []
            if rows_key:
                page = []
                for item in d:
                    page.extend((item or {}).get(rows_key) or [])
            else:
                page = d
            rows.extend(page)
            pag = (j.get("meta") or {}).get("pagination") or {}
            token = pag.get("next")
            if not page or not token or len(rows) >= max_items:
                return rows[:max_items], pag

    async def aclose(self) -> None:
        await self._http.aclose()
