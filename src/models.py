"""
Data models for CodeBadger Server
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class SourceType(str, Enum):
    """Source type enumeration"""

    LOCAL = "local"
    GITHUB = "github"


class SessionStatus(str, Enum):
    """Status enumeration for CPG operations (kept for backward compatibility)"""

    INITIALIZING = "initializing"
    GENERATING = "generating"
    READY = "ready"
    ERROR = "error"

@dataclass
class CodebaseInfo:

    codebase_hash: str  # The codebase hash (cpg_cache_key)
    source_type: str  # "local" or "github"
    source_path: str  # Original path or GitHub URL
    language: str  # Programming language
    cpg_path: Optional[str] = None  # Path to CPG file
    joern_port: Optional[int] = None  # Port for Joern server instance
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_accessed: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert codebase info to dictionary"""
        import json
        return {
            "hash": self.codebase_hash,
            "source_type": self.source_type,
            "source_path": self.source_path,
            "language": self.language,
            "cpg_path": self.cpg_path,
            "joern_port": self.joern_port,
            "created_at": self.created_at.isoformat(),
            "last_accessed": self.last_accessed.isoformat(),
            "metadata": json.dumps(self.metadata) if self.metadata else "{}",
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CodebaseInfo":
        """Create codebase info from dictionary"""
        import json
        # Parse metadata if it's a JSON string
        metadata = data.get("metadata", {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except:
                metadata = {}
        
        return cls(
            codebase_hash=data["hash"],
            source_type=data.get("source_type", ""),
            source_path=data.get("source_path", ""),
            language=data.get("language", ""),
            cpg_path=data.get("cpg_path"),
            joern_port=int(data["joern_port"]) if data.get("joern_port") else None,
            created_at=datetime.fromisoformat(data["created_at"]),
            last_accessed=datetime.fromisoformat(data["last_accessed"]),
            metadata=metadata,
        )


@dataclass
class QueryResult:
    """Query execution result"""

    success: bool
    data: Optional[List[Dict[str, Any]]] = None
    error: Optional[str] = None
    execution_time: float = 0.0
    row_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary"""
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "execution_time": self.execution_time,
            "row_count": self.row_count,
        }


@dataclass
class JoernConfig:
    """Joern configuration"""

    binary_path: str = "joern"
    memory_limit: str = "4g"
    java_opts: str = "-Xmx4G -Xms2G -XX:+UseG1GC -Dfile.encoding=UTF-8"
    server_host: str = "localhost"
    server_port: int = 8080
    server_auth_username: Optional[str] = None
    server_auth_password: Optional[str] = None


@dataclass
class ServerConfig:
    """Server configuration"""

    host: str = "0.0.0.0"
    port: int = 4242
    log_level: str = "INFO"


@dataclass
class CPGConfig:
    """CPG generation configuration"""

    generation_timeout: int = 600  # 10 minutes
    max_repo_size_mb: int = 500
    supported_languages: Optional[List[str]] = None
    exclusion_patterns: Optional[List[str]] = None
    languages_with_exclusions: Optional[List[str]] = None
    taint_sources: Optional[Dict[str, List[str]]] = None
    taint_sinks: Optional[Dict[str, List[str]]] = None


@dataclass
class QueryConfig:
    """Query execution configuration"""

    timeout: int = 300  # 5 minutes - accounts for large CPG loading time (~2-3 min) + query execution
    cache_enabled: bool = True
    cache_ttl: int = 300  # 5 minutes


@dataclass
class StorageConfig:
    """Storage configuration"""

    workspace_root: str = "/tmp/codebadger"
    cleanup_on_shutdown: bool = True


@dataclass
class Config:
    """Main configuration"""

    server: ServerConfig = field(default_factory=ServerConfig)
    joern: JoernConfig = field(default_factory=JoernConfig)
    cpg: CPGConfig = field(default_factory=CPGConfig)
    query: QueryConfig = field(default_factory=QueryConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
