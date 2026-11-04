"""Cloud audit-log normalizers (AWS, Azure / Entra ID, Google Workspace, Microsoft 365)."""
from .base import ParseResult, ParserError
from .registry import PARSERS, parse_auto, select

__all__ = ["ParseResult", "ParserError", "PARSERS", "parse_auto", "select"]
