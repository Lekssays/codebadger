"""
Data models for CodeBadger Server
"""

import json
import logging
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
        logger = logging.getLogger(__name__)
        # Parse metadata if it's a JSON string
        metadata = data.get("metadata", {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse metadata JSON: {e}. Using empty dict.")
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
    port_min: int = 13371
    port_max: int = 13399
    server_init_sleep_time: float = 3.0
    # HTTP Connection Pooling
    http_pool_connections: int = 10
    http_pool_maxsize: int = 10
    http_connect_timeout: float = 5.0
    http_read_timeout: float = 300.0
    http_max_retries: int = 3
    http_backoff_factor: float = 0.3


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
    min_cpg_file_size: int = 1024  # 1KB minimum
    output_truncation_length: int = 2000  # Max characters for output logging


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
class TelemetryConfig:
    """OpenTelemetry configuration"""

    enabled: bool = False
    service_name: str = "codebadger"
    otlp_endpoint: str = "http://localhost:4317"
    otlp_protocol: str = "grpc"  # "grpc" or "http/protobuf"


@dataclass
class Config:
    """Main configuration"""

    server: ServerConfig = field(default_factory=ServerConfig)
    joern: JoernConfig = field(default_factory=JoernConfig)
    cpg: CPGConfig = field(default_factory=CPGConfig)
    query: QueryConfig = field(default_factory=QueryConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    telemetry: TelemetryConfig = field(default_factory=TelemetryConfig)


@dataclass
class Finding:
    """Security finding/vulnerability"""

    codebase_hash: str
    finding_type: str  # "taint_flow", "use_after_free", "double_free"
    severity: str  # "critical", "high", "medium", "low"
    confidence: str  # "high", "medium", "low"
    filename: str
    line_number: int
    message: str
    description: Optional[str] = None
    cwe_id: Optional[int] = None
    rule_id: Optional[str] = None
    flow_data: Optional[Dict[str, Any]] = None
    metadata: Optional[Dict[str, Any]] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            "id": self.id,
            "codebase_hash": self.codebase_hash,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "filename": self.filename,
            "line_number": self.line_number,
            "message": self.message,
            "description": self.description,
            "cwe_id": self.cwe_id,
            "rule_id": self.rule_id,
            "flow_data": json.dumps(self.flow_data) if self.flow_data else None,
            "metadata": json.dumps(self.metadata) if self.metadata else None,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        """Create finding from dictionary"""
        # Parse metadata if it's a JSON string
        metadata = data.get("metadata", {})
        if isinstance(metadata, str):
            try:
                metadata = json.loads(metadata)
            except json.JSONDecodeError:
                metadata = {}

        # Parse flow_data if it's a JSON string
        flow_data = data.get("flow_data")
        if isinstance(flow_data, str):
            try:
                flow_data = json.loads(flow_data)
            except json.JSONDecodeError:
                flow_data = {}

        return cls(
            id=data.get("id"),
            codebase_hash=data.get("codebase_hash", ""),
            finding_type=data.get("finding_type", ""),
            severity=data.get("severity", "medium"),
            confidence=data.get("confidence", "medium"),
            filename=data.get("filename", ""),
            line_number=data.get("line_number", 0),
            message=data.get("message", ""),
            description=data.get("description"),
            cwe_id=data.get("cwe_id"),
            rule_id=data.get("rule_id"),
            flow_data=flow_data,
            metadata=metadata,
            created_at=datetime.fromisoformat(data["created_at"])
            if data.get("created_at")
            else datetime.now(timezone.utc),
        )
