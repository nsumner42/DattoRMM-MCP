"""Load credentials from the shared store in C:\\AIProjects\\secrets.

Primary: the root Credential.ps1's Get-SharedCredential, run in Windows PowerShell. It reads
the shared keys (cms_<Name>.txt, encrypted to every computer's certificate) and falls back to
the old per-computer cred_<Name>.xml; asking for 'X-<COMPUTERNAME>' also finds shared 'X'.
Fallback when PowerShell can't be run: read cred_<Name>.xml directly (a PSCredential written
by Export-Clixml, whose password is a DPAPI blob only the saving user on that machine can
decrypt). Nothing is ever written back; secrets stay in memory only.
"""

from __future__ import annotations

from mcp.server.mcpserver.exceptions import ToolError

import ctypes
import ctypes.wintypes as wt
import json
import os
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

_PS_NS = "{http://schemas.microsoft.com/powershell/2004/04}"

# The name travels in an environment variable, never in the command text.
_PS_SCRIPT = (
    "$ErrorActionPreference = 'Stop'; "
    ". (Join-Path $env:MSP_MCP_ROOT 'Credential.ps1'); "
    "$c = Get-SharedCredential -Name $env:MSP_MCP_CRED_NAME -Root $env:MSP_MCP_ROOT; "
    "if (-not $c) { exit 3 }; "
    "[Console]::Out.Write((@{ u = $c.UserName; p = $c.GetNetworkCredential().Password } | ConvertTo-Json -Compress))"
)

_cache: dict[str, tuple[str, str]] = {}


class CredentialError(ToolError, RuntimeError):  # ToolError: the message reaches the model
    pass


def secrets_dir() -> Path:
    """MSP_MCP_SECRETS_DIR, else the `secrets` folder next to this repo (C:\\AIProjects\\secrets)."""
    env = os.environ.get("MSP_MCP_SECRETS_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parents[4] / "secrets"


class _Blob(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


def _dpapi_decrypt(data: bytes) -> bytes:
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))
    blob_out = _Blob()
    if not crypt32.CryptUnprotectData(
        ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
    ):
        raise CredentialError(
            "DPAPI decrypt failed: the credential was saved by another Windows user or machine"
        )
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def _load_shared(name: str) -> tuple[str, str] | None:
    """Get-SharedCredential via Windows PowerShell; None if not found or PowerShell failed."""
    root = secrets_dir().parent
    if not (root / "Credential.ps1").exists():
        return None
    env = dict(os.environ, MSP_MCP_ROOT=str(root), MSP_MCP_CRED_NAME=name)
    try:
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
             "-Command", _PS_SCRIPT],
            env=env, capture_output=True, text=True, timeout=60,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0 or not r.stdout.strip():
        return None
    try:
        d = json.loads(r.stdout)
    except ValueError:
        return None
    return d.get("u") or "", d.get("p") or ""


def _load_legacy(name: str) -> tuple[str, str] | None:
    """The old per-computer cred_<name>.xml, read directly; None if there is no such file."""
    path = secrets_dir() / f"cred_{name}.xml"
    if not path.exists():
        return None
    root = ET.parse(path).getroot()
    user = root.find(f".//{_PS_NS}S[@N='UserName']")
    pwd = root.find(f".//{_PS_NS}SS[@N='Password']")
    if user is None or pwd is None or not pwd.text:
        raise CredentialError(f"{path} is not a PSCredential Export-Clixml file")
    password = _dpapi_decrypt(bytes.fromhex(pwd.text)).decode("utf-16-le")
    return user.text or "", password


def load_credential(name: str) -> tuple[str, str]:
    """Return (username, password) for store name `name` (shared key first, then the old file)."""
    if name not in _cache:
        found = _load_shared(name) or _load_legacy(name)
        if found is None:
            raise CredentialError(f"Credential '{name}' not found in {secrets_dir()}")
        _cache[name] = found
    return _cache[name]


def load_machine_credential(prefix: str) -> tuple[str, str]:
    """Load `<prefix>-<COMPUTERNAME>` (finds the shared `<prefix>` too), falling back to `<prefix>`.

    An explicit store name in MSP_MCP_<PREFIX>_CRED (e.g. MSP_MCP_DATTORMMAPI_CRED) wins.
    """
    override = os.environ.get(f"MSP_MCP_{prefix.upper().replace('-', '_')}_CRED")
    if override:
        return load_credential(override)
    machine = os.environ.get("COMPUTERNAME", "")
    for name in (f"{prefix}-{machine}", prefix):
        try:
            return load_credential(name)
        except CredentialError:
            continue
    raise CredentialError(
        f"No credential '{prefix}' (shared) or '{prefix}-{machine}' in {secrets_dir()}. Save one "
        f"with Save-SharedCredential -Name '{prefix}' in your own PowerShell window."
    )
