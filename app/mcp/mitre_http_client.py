from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

MCP_URL = "http://localhost:8000/mcp"


async def _call_tool_http(tool_name: str, arguments: Dict[str, Any]) -> Any:
    async with streamable_http_client(MCP_URL) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            return await session.call_tool(tool_name, arguments)


def get_technique_by_id(technique_id: str) -> Optional[Dict[str, Any]]:
    try:
        result = asyncio.run(_call_tool_http("get_technique_by_id", {"technique_id": technique_id}))
    except Exception as e:
        print(f"[MCP] error get_technique_by_id({technique_id}): {e!r}")
        return None

    # Normalización típica del SDK (puede venir en result.content)
    content = getattr(result, "content", None)

    if isinstance(content, list) and content and isinstance(content[0], dict):
        return content[0]
    if isinstance(content, dict):
        return content

    return None