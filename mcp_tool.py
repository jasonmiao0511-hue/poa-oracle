# SPDX-License-Identifier: MIT
"""rustchain_verify_hardware — MCP tool client for the PoA-Attest oracle.

Drop into rustchain-mcp (or any FastMCP server). Lets an external agent ask
"is this peer real silicon or a VM/emulation?" — returning the oracle's scoped,
signed verdict. The tool docstring repeats the scope so a calling LLM cannot
mistake authenticity for work-legitimacy.
"""
import json
import urllib.request

ORACLE_URL = "https://rustchain.org"  # or wherever the oracle sidecar is exposed


def verify_hardware(identity: str, oracle_url: str = ORACLE_URL) -> str:
    """Check whether a RustChain peer is attested as real, non-emulated hardware.

    Returns the oracle's signed verdict. SCOPE: this attests only that the
    hardware is physically present and non-emulated, plus its architecture
    class. It does NOT attest work quality, output authenticity, operator
    intent, or that any specific computation occurred — a real machine running
    a scam still passes. Verify `oracle_signature` (Ed25519) before trusting.

    Args:
        identity: miner-id, RTC address, or signing pubkey to look up.
        oracle_url: PoA-Attest oracle base URL.
    """
    url = oracle_url.rstrip("/") + "/oracle/attest/" + identity
    try:
        with urllib.request.urlopen(url, timeout=15) as r:
            return r.read().decode()
    except Exception as e:
        return json.dumps({"error": str(e), "identity": identity})


# --- FastMCP registration snippet (paste into rustchain-mcp's server.py) ---------
# from mcp.server.fastmcp import FastMCP
# mcp = FastMCP("rustchain")
#
# @mcp.tool()
# def rustchain_verify_hardware(identity: str) -> str:
#     """Check if a RustChain peer is attested real, non-emulated hardware.
#     SCOPE: attests physical/non-emulated hardware + arch class ONLY — NOT work
#     quality, output authenticity, or intent. Verify the Ed25519 signature."""
#     return verify_hardware(identity)

if __name__ == "__main__":
    import sys
    print(verify_hardware(sys.argv[1] if len(sys.argv) > 1 else "g4-powerbook-115"))
