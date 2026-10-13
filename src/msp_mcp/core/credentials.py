"""Load credentials from the shared DPAPI store (C:\\AIProjects\\secrets\\cred_<Name>.xml).

The files are PSCredential objects written by PowerShell's Export-Clixml. The password is a
DPAPI blob that only the Windows account that saved it, on the same machine, can decrypt.
Nothing is ever written back; secrets stay in memory only.
"""

from __future__ import annotations

from mcp.server.mcpserver.exceptions import ToolError

import ctypes
import ctypes.wintypes as wt
import os
import xml.etree.ElementTree as ET
from pathlib import Path

_PS_NS = "{http://schemas.microsoft.com/powershell/2004/04}"


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


def load_credential(name: str) -> tuple[str, str]:
    """Return (username, password) for store name `name`."""
    path = secrets_dir() / f"cred_{name}.xml"
    if not path.exists():
        raise CredentialError(f"Credential '{name}' not found ({path})")
    root = ET.parse(path).getroot()
    user = root.find(f".//{_PS_NS}S[@N='UserName']")
    pwd = root.find(f".//{_PS_NS}SS[@N='Password']")
    if user is None or pwd is None or not pwd.text:
        raise CredentialError(f"{path} is not a PSCredential Export-Clixml file")
    password = _dpapi_decrypt(bytes.fromhex(pwd.text)).decode("utf-16-le")
    return user.text or "", password


def load_machine_credential(prefix: str) -> tuple[str, str]:
    """Load `<prefix>-<COMPUTERNAME>` (one copy per computer), falling back to `<prefix>`.

    An explicit store name in MSP_MCP_<PREFIX>_CRED (e.g. MSP_MCP_DATTORMMAPI_CRED) wins.
    """
    override = os.environ.get(f"MSP_MCP_{prefix.upper().replace('-', '_')}_CRED")
    if override:
        return load_credential(override)
    machine = os.environ.get("COMPUTERNAME", "")
    for name in (f"{prefix}-{machine}", prefix):
        if (secrets_dir() / f"cred_{name}.xml").exists():
            return load_credential(name)
    raise CredentialError(
        f"No credential '{prefix}-{machine}' or '{prefix}' in {secrets_dir()}. Save one with "
        f"Save-SharedCredential -Name '{prefix}-{machine}' in your own PowerShell window."
    )
