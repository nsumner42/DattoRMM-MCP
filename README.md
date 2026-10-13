# MSP MCP servers

[MCP](https://modelcontextprotocol.io) servers that let Claude work directly in our MSP stack.
One repo, one server per product, shared code for credentials, rate limiting and write guards.

| Server | Status |
|---|---|
| Datto RMM (`msp-mcp-datto`) | working: reads + guarded writes |
| ThreatLocker (`msp-mcp-threatlocker`) | working: reads + guarded allow-by-hash |
| Mimecast | planned |
| Asset Panda (`msp-mcp-assetpanda`) | working: read-only |
| CrowdStrike Falcon | use the official [falcon-mcp](https://github.com/CrowdStrike/falcon-mcp) |

## Credentials

No secrets live in this repo. Each server loads its API credential at startup from the local
DPAPI-encrypted store (`C:\AIProjects\secrets\cred_<Name>.xml`, written by PowerShell
`Export-Clixml`), which only the Windows account that saved it, on that machine, can decrypt.
The store name is `<Prefix>-<COMPUTERNAME>`, e.g. `DattoRmmApi-BABYBEAR2`
(username = API key, password = API secret). Save one in your own PowerShell window:

```powershell
. C:\AIProjects\Credential.ps1
Save-SharedCredential -Name "DattoRmmApi-$env:COMPUTERNAME" -Credential (Get-Credential -UserName '<API key>' -Message 'Datto RMM API secret')
```

## Writes

Write tools refuse to run unless `MSP_MCP_<SERVER>_WRITES=1` is set in the server's
registration. Every write attempt (allowed, refused or failed) is logged as a JSON line to
`%LOCALAPPDATA%\MSP-MCP\audit.log`. Tool output (device names, alert text, job output) is
untrusted data; the servers tell the model not to follow instructions found in it.

## Install (per computer)

The virtual environment lives outside the synced folder:

```powershell
$env:UV_PROJECT_ENVIRONMENT = "$env:LOCALAPPDATA\MSP-MCP\venv"
uv sync --directory C:\AIProjects\MSP-MCP

claude mcp add datto --scope user `
  -e "UV_PROJECT_ENVIRONMENT=$env:LOCALAPPDATA\MSP-MCP\venv" `
  -e MSP_MCP_DATTO_WRITES=1 `
  -- uv --directory C:\AIProjects\MSP-MCP run --no-sync python -m msp_mcp.datto.server

claude mcp add assetpanda --scope user `
  -e "UV_PROJECT_ENVIRONMENT=$env:LOCALAPPDATA\MSP-MCP\venv" `
  -- uv --directory C:\AIProjects\MSP-MCP run --no-sync python -m msp_mcp.assetpanda.server
```

Leave out `-e MSP_MCP_DATTO_WRITES=1` for a read-only install. `--no-sync`: the package is installed
editable, so code changes need no reinstall, and a second session can start while the first holds
the venv's .exe launchers open (plain `uv run` re-syncs and fails with "file in use"). Run `uv sync`
by hand after changing dependencies, with no server running.

## Datto RMM tools

Reads: `account_summary`, `list_sites`, `find_devices`, `get_device`, `udf_report`,
`list_open_alerts`, `list_components`, `get_job`, `device_software`, `activity_log`,
`write_status`.

Writes: `set_device_udf`, `run_quick_job`, `run_quick_job_many` (dry run by default),
`resolve_alert`.

Datto's API (checked against the live OpenAPI spec, 2026-10-11) cannot create or edit
components or create scheduled jobs; the only way to run something is a quick job on one
device at a time.

## Asset Panda tools (read-only)

`account_summary`, `list_fields`, `search_assets`, `get_asset`, `search_employees`,
`employee_assets`, `asset_counts`, `duplicate_assets`, `search_collection`.

Credentials: `AssetPanda-<COMPUTERNAME>` (API app: username = client ID, password = client
secret) and `AssetPanda-ApiUser-<COMPUTERNAME>` (the Asset Panda user the API acts as: email +
password). The user's Asset Panda rights limit what the API can do. Limit ~400 calls / 3 min per IP;
a full inventory read (`asset_counts`, `duplicate_assets`) takes ~47 calls and about a minute.

## ThreatLocker tools

Reads: `organizations`, `find_computers`, `search_action_log` (real blocks by default; host / user /
path with * wildcards; hash), `get_action`, `file_history`, `approval_requests`,
`get_approval_request` (ThreatLocker's proposed permit, nothing approved), `computer_groups`,
`write_status`.

Write: `permit_by_hash` — from an approval request or an action-log block. Always one SHA-256 on
the one computer that was blocked, as a new application (ThreatLocker's own suggestion, which can
permit a whole built-in application, is replaced). Dry run by default; the real call must repeat
the SHA-256 the dry run showed (`confirm_sha256`). Refuses browser extensions, non-pending requests
and files without a SHA-256; warns on unsigned / invalid certificates and on blocks by a specific
(non-default) deny policy. Needs the token's role to have "Approve for Single Computer"
(a zero-ID probe always answers 401 for that permission, even when the role has it).

```powershell
claude mcp add threatlocker --scope user `
  -e "UV_PROJECT_ENVIRONMENT=$env:LOCALAPPDATA\MSP-MCP\venv" `
  -e MSP_MCP_THREATLOCKER_WRITES=1 `
  -- uv --directory C:\AIProjects\MSP-MCP run --no-sync python -m msp_mcp.threatlocker.server
```

Credential: `ThreatLockerApi-<COMPUTERNAME>` (password = portal API token). Default API URL
`https://portalapi.f.threatlocker.com/portalApi` (override: `THREATLOCKER_API_URL`). The instance's
Swagger has no paths; request shapes come from the community spec (jentic/jentic-public-apis) and
live tests. The action log needs the header `usenewsearch: true`.
