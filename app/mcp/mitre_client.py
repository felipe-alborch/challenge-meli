from __future__ import annotations

import asyncio
import json
import os
import logging
from typing import Any, Dict, Optional

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

logger = logging.getLogger(__name__)

# Configurable por entorno (más pro que hardcodear)
MCP_URL = os.getenv("MCP_URL", "http://localhost:8000/mcp")


async def _call_tool_async(tool_name: str, arguments: Dict[str, Any]) -> Any:
    async with streamable_http_client(MCP_URL) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            return await session.call_tool(tool_name, arguments)


def get_technique_by_id(technique_id: str) -> Optional[Dict[str, Any]]:
    """
    Devuelve un dict con la técnica (ej: {"name": "...", "mitre_id": "T1078", ...})
    o None si el MCP no está disponible o la respuesta no se puede parsear.
    """
    try:
        result = asyncio.run(_call_tool_async("get_technique_by_id", {"technique_id": technique_id}))
    except Exception as e:
        # No rompemos el pipeline: devolvemos None y el Classifier usa fallback.
        # Log a nivel DEBUG para no ensuciar salida normal.
        logger.debug("MCP call_tool failed for %s (%s): %r", technique_id, MCP_URL, e)
        return None

    content = getattr(result, "content", None)

    # El server devuelve: [TextContent(type='text', text='{...json...}')]
    if isinstance(content, list) and content:
        first = content[0]
        text = getattr(first, "text", None)

        if isinstance(text, str) and text.strip():
            try:
                obj = json.loads(text)

                # Formato observado: {"technique": {...}}
                if isinstance(obj, dict):
                    technique = obj.get("technique")
                    if isinstance(technique, dict):
                        return technique
                    return obj

            except json.JSONDecodeError:
                logger.debug("MCP returned non-JSON text for %s: %r", technique_id, text[:200])
                return None

        # Fallback si en algún caso viene dict directo
        if isinstance(first, dict):
            return first

    if isinstance(content, dict):
        return content

    return None
