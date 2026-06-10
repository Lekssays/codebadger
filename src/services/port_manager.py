"""
Port manager for assigning unique ports to Joern server instances
"""

import logging
import threading
from typing import Dict, Optional, Set

logger = logging.getLogger(__name__)


class PortManager:
    """Manages port allocation for Joern server instances"""

    def __init__(self, port_min: int = 13371, port_max: int = 13870):
        self.port_min = port_min
        self.port_max = port_max
        self._session_to_port: Dict[str, int] = {}  # session_id -> port
        self._port_to_session: Dict[int, str] = {}  # port -> session_id
        self._available_ports: Set[int] = set(range(self.port_min, self.port_max + 1))
        # Rotating cursor so allocation sweeps the whole range instead of always
        # handing back the lowest free port (see allocate_port for why).
        self._cursor = self.port_min
        self._lock = threading.Lock()

    def _next_available_from(self, cursor: int) -> int:
        """Smallest available port >= cursor, wrapping to the lowest otherwise."""
        ahead = [p for p in self._available_ports if p >= cursor]
        return min(ahead) if ahead else min(self._available_ports)

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
                raise RuntimeError(f"No available ports in range {self.port_min}-{self.port_max}")

            # Rotate across the range rather than always reusing the lowest free
            # port. Always picking min() means a just-released host port is
            # republished by the very next spawn, racing Docker's teardown of the
            # old port mapping (docker-proxy/iptables DNAT) and the kernel's
            # TIME_WAIT on the socket — which surfaces as "failed to become ready
            # / connection refused" concentrated on the first port (14000).
            # Advancing a cursor gives the OS/Docker time to fully free a port
            # before it comes round again.
            port = self._next_available_from(self._cursor)
            self._available_ports.remove(port)
            self._cursor = port + 1 if port < self.port_max else self.port_min
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
