"""
VPN Engineer - Base Protocol Adapter Interface
Enables modular addition of new VPN protocols without altering core engine.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple
from vpn_engineer.core.ssh_client import RemoteSSHClient

class BaseProtocolAdapter(ABC):
    """Abstract base class for all protocol handlers (Xray, Hysteria2, Nginx, etc.)."""

    def __init__(self, ssh: RemoteSSHClient):
        self.ssh = ssh

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the protocol."""
        pass

    @abstractmethod
    def is_installed(self) -> bool:
        """Checks if the component binary and service exist."""
        pass

    @abstractmethod
    def audit(self) -> Dict[str, Any]:
        """Audits current configuration, active listening sockets, and service state."""
        pass

    @abstractmethod
    def validate_config(self) -> Tuple[bool, str]:
        """Checks syntax of configuration files."""
        pass

    @abstractmethod
    def generate_client_uri(self, **kwargs) -> str:
        """Generates client shareable URI (vless://, hysteria2://, etc.)."""
        pass
