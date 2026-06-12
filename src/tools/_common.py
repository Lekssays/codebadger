"""Shared helpers for MCP tool implementations.

The taint, browsing, and custom tools all repeat the same two steps: confirm a
CPG is ready for a codebase hash, and turn a QueryExecutor result into the
string the tool returns. These were copy-pasted ~20+ times across the tool
modules (and had drifted), so they live here as single sources of truth.
"""

import logging
# (no typing imports needed)

from ..exceptions import ValidationError
from ..utils.validators import validate_codebase_hash

logger = logging.getLogger(__name__)


def require_cpg(services: dict, codebase_hash: str):
    """Validate the hash and return its CodebaseInfo, or raise ValidationError.

    Raises ValidationError if the hash is malformed or no built CPG exists yet —
    the standard precondition for every analysis tool.
    """
    validate_codebase_hash(codebase_hash)
    info = services["codebase_tracker"].get_codebase(codebase_hash)
    if not info or not info.cpg_path:
        raise ValidationError(
            f"CPG not found for codebase {codebase_hash}. Generate it first using generate_cpg."
        )
    return info


def unwrap_result(result) -> str:
    """Turn a QueryExecutor result into the tool's string output.

    Returns an ``Error: ...`` string on failure (the taint/browsing tools'
    existing string-error contract) and otherwise extracts the text payload from
    ``result.data`` (which may be a str, a single-element list, or other).
    """
    if not result.success:
        return f"Error: {result.error}"
    data = result.data
    if isinstance(data, str):
        return data.strip()
    if isinstance(data, list) and len(data) > 0:
        first = data[0]
        return first.strip() if isinstance(first, str) else str(first)
    return f"Query returned unexpected format: {type(data)}"
