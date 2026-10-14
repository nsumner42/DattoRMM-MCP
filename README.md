# MSP MCP servers

[MCP](https://modelcontextprotocol.io) servers that let Claude work directly in our MSP stack.
One repo, one server per product, shared code for credentials, rate limiting and write guards.

| Server | Status |
|---|---|
| Datto RMM (`msp-mcp-datto`) | working: reads + guarded writes |
| ThreatLocker (`msp-mcp-threatlocker`) | working: reads + guarded allow-by-hash |
| Mimecast (`msp-mcp-mimecast`) | working: reads; guarded release / permit / greylisting bypass |
| Asset Panda (`msp-mcp-assetpanda`) | working: read-only |
| CrowdStrike Falcon | use the official [falcon-mcp](https://github.com/CrowdStrike/falcon-mcp) |

## Credentials

No secrets live in this repo. Each server loads its API credential from the encrypted store in
`C:\AIProjects\secrets` through `Get-SharedCredential` (root `Credential.ps1`, run in Windows
PowerShell): shared keys (`cms_<Name>.txt`, encrypted to each computer's own certificate, so
every computer can read them), falling back to an old per-computer DPAPI `cred_<Name>.xml`.
The store name is the prefix, e.g. `DattoRmmApi` (username = API key, password = API secret);
`<Prefix>-<COMPUTERNAME>` still works. Save one in your own PowerShell window:

```powershell
. C:\AIProjects\Credential.ps1
Save-SharedCredential -Name 'DattoRmmApi' -Credential (Get-Credential -UserName '<API key>' -Message 'Datto RMM API secret')
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

claude mcp add mimecast --scope user `
  -e "UV_PROJECT_ENVIRONMENT=$env:LOCALAPPDATA\MSP-MCP\venv" `
  -- uv --directory C:\AIProjects\MSP-MCP run --no-sync python -m msp_mcp.mimecast.server

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

## Mimecast tools

Reads: `account_summary`, `search_messages` (message tracking), `get_message`, `held_messages`,
`url_clicks`, `attachment_logs`, `impersonation_logs`, `audit_events`, `greylisting_policies`,
`greylist_report` (who is delayed or lost by greylisting, per sender domain, with any existing
bypass, IP-restricted ones included), `write_status`.

Writes (all dry run by default, need `MSP_MCP_MIMECAST_WRITES=1`):
- `release_held_messages`: by search (sender / recipient / subject) or ids, max 10 at a time.
- `permit_sender`: managed sender permit/block for one recipient (skips spam checks,
  greylisting and IP reputation for that pair).
- `bypass_greylisting`: greylisting policy `no_action` for one sender domain or address, to
  everyone, no end date (same shape as the hand-made ones). Refuses free-mail domains and
  duplicates.
- `delete_greylisting_policy`.

Credential: `MimecastApi`, an API 2.0 application (username = client ID, password = client
secret). API 1.0 keys (access key + secret key, HMAC) do not work. All calls go to
`https://api.services.mimecast.com` whatever the account's region. The application's role
decides what works. Reads: Gateway | Tracking, Monitoring | Held / URL / Attachment /
Impersonation Protection, Account | Logs, Gateway | Policies (Read). Writes add
Account | Monitoring | Held | Edit, Gateway | Managed Senders | Edit, Gateway | Policies | Edit.
Official OpenAPI specs: the developer portal's data API,
`https://developer.services.mimecast.com/portals/api/sites/mimecast-prod-apigee-developer/liveportal/apis/<apiId>/download_spec`
(`cloudgateway`, `policymanagement`, ...).

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
