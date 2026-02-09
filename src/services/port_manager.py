"""
Port manager for assigning unique ports to Joern server instances
"""

import logging
import threading
from typing import Dict, Optional, Set

logger = logging.getLogger(__name__)


class PortManager:
    """Manages port allocation for Joern server instances (2000-2999)"""

    PORT_MIN = 2000
    PORT_MAX = 2999

    def __init__(self):
        self._session_to_port: Dict[str, int] = {}  # session_id -> port
        self._port_to_session: Dict[int, str] = {}  # port -> session_id
        self._available_ports: Set[int] = set(range(self.PORT_MIN, self.PORT_MAX + 1))
        self._lock = threading.Lock()

    def allocate_port(self, session_id: str) -> int:
        """Allocate a port for a session"""
        with self._lock:
            # Check if session already has a port
            if session_id in self._session_to_port:
                port = self._session_to_port[session_id]
                logger.info(f"Session {session_id} already has port {port}")
                return port

            # Allocate a new port
            if not self._available_ports:
                raise RuntimeError("No available ports in range 2000-2999")

            port = min(self._available_ports)
            self._available_ports.remove(port)
            self._session_to_port[session_id] = port
            self._port_to_session[port] = session_id

            logger.info(f"Allocated port {port} for session {session_id}")
            return port

    def get_port(self, session_id: str) -> Optional[int]:
        """Get the port assigned to a session"""
        with self._lock:
            return self._session_to_port.get(session_id)

    def release_port(self, session_id: str) -> bool:
        """Release the port assigned to a session"""
        with self._lock:
            if session_id not in self._session_to_port:
                logger.warning(f"Session {session_id} has no allocated port")
                return False

            port = self._session_to_port[session_id]
            del self._session_to_port[session_id]
            del self._port_to_session[port]
            self._available_ports.add(port)

            logger.info(f"Released port {port} from session {session_id}")
            return True

    def get_session_by_port(self, port: int) -> Optional[str]:
        """Get the session ID for a given port"""
        with self._lock:
            return self._port_to_session.get(port)

    def get_all_allocations(self) -> Dict[str, int]:
        """Get all current port allocations"""
        with self._lock:
            return self._session_to_port.copy()

    def available_count(self) -> int:
        """Get the count of available ports"""
        with self._lock:
            return len(self._available_ports)

    def release_all_ports(self) -> None:
        """Release all allocated ports - used during graceful shutdown"""
        with self._lock:
            released_count = len(self._session_to_port)
            self._available_ports.update(self._session_to_port.values())
            self._session_to_port.clear()
            self._port_to_session.clear()
            logger.info(f"Released all {released_count} allocated ports")
