"""OSINT Graph Mapper: AI-attached entity graph for passive-source
investigations. Core package — persistence, resolution, gaps, cross-case
linking. The MCP surface lives in ~/tools/osint-mcp/server.py; the web
board in osint_map.web."""
from .core import Graph
from .store import Store

__version__ = "0.1.0"

__all__ = ["Graph", "Store", "__version__"]