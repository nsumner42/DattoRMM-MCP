# Datto RMM MCP

An [MCP](https://modelcontextprotocol.io) server that lets Claude query Datto RMM:
sites, devices, user-defined fields (UDFs) and job/component output.

Status: just started. Read-only first; write actions (running jobs, setting UDFs) later, if ever.

The Datto RMM API key and secret are never stored in this repo. They're loaded at startup
from a local encrypted store.
