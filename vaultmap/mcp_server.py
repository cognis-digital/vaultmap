"""VAULTMAP MCP server — exposes scan as an MCP tool for Cognis.Studio."""
from cognis_core.mcp import build_mcp_server
from vaultmap.core import scan, TOOL_NAME

run_mcp_server = build_mcp_server(
    tool_name=TOOL_NAME,
    description="Personal asset & account inventory — estate-planning grade encrypted",
    scan_fn=scan,
)

if __name__ == "__main__":
    run_mcp_server()
