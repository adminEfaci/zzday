"""
IP Address Value Object

Immutable representation of an IP address with validation and utilities.
"""

import ipaddress
from dataclasses import dataclass

from .base import ValueObject


@dataclass(frozen=True)
class IpAddress(ValueObject):
    """Value object representing an IP address (IPv4 or IPv6)."""
    
    value: str
    
    def __post_init__(self):
        """Validate IP address."""
        if not self.value:
            raise ValueError("IP address cannot be empty")
        
        # Normalize the value
        normalized = self.value.strip()
        
        # Validate IP address
        try:
            ip_obj = ipaddress.ip_address(normalized)
            # Store normalized form
            object.__setattr__(self, 'value', str(ip_obj))
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {self.value}") from e
    
    @property
    def version(self) -> int:
        """Get IP version (4 or 6)."""
        return ipaddress.ip_address(self.value).version
    
    @property
    def is_ipv4(self) -> bool:
        """Check if this is an IPv4 address."""
        return self.version == 4
    
    @property
    def is_ipv6(self) -> bool:
        """Check if this is an IPv6 address."""
        return self.version == 6
    
    @property
    def is_private(self) -> bool:
        """Check if this is a private IP address."""
        return ipaddress.ip_address(self.value).is_private
    
    @property
    def is_public(self) -> bool:
        """Check if this is a public IP address."""
        ip = ipaddress.ip_address(self.value)
        return not (ip.is_private or ip.is_reserved or ip.is_loopback or 
                   ip.is_link_local or ip.is_multicast)
    
    @property
    def is_loopback(self) -> bool:
        """Check if this is a loopback address."""
        return ipaddress.ip_address(self.value).is_loopback
    
    @property
    def is_multicast(self) -> bool:
        """Check if this is a multicast address."""
        return ipaddress.ip_address(self.value).is_multicast
    
    @property
    def is_reserved(self) -> bool:
        """Check if this is a reserved address."""
        return ipaddress.ip_address(self.value).is_reserved
    
    @property
    def is_link_local(self) -> bool:
        """Check if this is a link-local address."""
        return ipaddress.ip_address(self.value).is_link_local
    
    def is_in_range(self, cidr: str) -> bool:
        """Check if IP is in a given CIDR range."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            ip = ipaddress.ip_address(self.value)
            return ip in network
        except ValueError:
            return False
    
    def is_in_ranges(self, cidrs: list[str]) -> bool:
        """Check if IP is in any of the given CIDR ranges."""
        return any(self.is_in_range(cidr) for cidr in cidrs)
    
    def get_network(self, prefix_length: int) -> str:
        """Get the network address for a given prefix length."""
        ip = ipaddress.ip_address(self.value)
        if self.is_ipv4:
            network = ipaddress.IPv4Network(f"{self.value}/{prefix_length}", strict=False)
        else:
            network = ipaddress.IPv6Network(f"{self.value}/{prefix_length}", strict=False)
        return str(network)
    
    def anonymize(self) -> 'IpAddress':
        """Anonymize IP address by zeroing last octet/group."""
        if self.is_ipv4:
            parts = self.value.split('.')
            parts[-1] = '0'
            return IpAddress('.'.join(parts))
        # For IPv6, zero out the last 64 bits
        try:
            ipv6_addr = ipaddress.IPv6Address(self.value)
            network = ipaddress.IPv6Network(f"{self.value}/64", strict=False)
            return IpAddress(str(network.network_address))
        except ValueError:
            # Fallback for invalid addresses
            return self
    
    def get_geolocation_data(self) -> dict:
        """Get basic geolocation indicators (would integrate with GeoIP service)."""
        # This is a placeholder - in production would use MaxMind or similar
        return {
            "is_public": self.is_public,
            "is_vpn": self._is_likely_vpn(),
            "is_tor": self._is_tor_exit_node(),
            "is_proxy": self._is_known_proxy(),
            "risk_indicators": self._get_risk_indicators()
        }
    
    def _is_likely_vpn(self) -> bool:
        """Check if IP is likely a VPN (simplified check)."""
        # In production, would check against VPN provider IP ranges
        vpn_indicators = [
            self.is_in_range("10.0.0.0/8"),  # Common VPN internal range
        ]
        
        try:
            reverse_dns = self.get_reverse_dns().lower()
            vpn_indicators.extend([
                "vpn" in reverse_dns,
                "tunnel" in reverse_dns
            ])
        except (ValueError, AttributeError, OSError):
            # Ignore reverse DNS lookup failures
            pass
        
        return any(vpn_indicators)
    
    def _is_tor_exit_node(self) -> bool:
        """Check if IP is a known Tor exit node."""
        # In production, would check against Tor exit node list
        return False
    
    def _is_known_proxy(self) -> bool:
        """Check if IP is a known proxy."""
        # In production, would check against proxy lists
        return False
    
    def _get_risk_indicators(self) -> list[str]:
        """Get risk indicators for this IP."""
        indicators = []
        
        if self.is_private:
            indicators.append("private_ip")
        if self.is_loopback:
            indicators.append("loopback")
        if self._is_likely_vpn():
            indicators.append("likely_vpn")
        if self.is_multicast:
            indicators.append("multicast")
        if self.is_reserved:
            indicators.append("reserved")
        
        return indicators
    
    def get_reverse_dns(self) -> str:
        """Get reverse DNS for the IP (placeholder)."""
        # In production, would perform actual reverse DNS lookup
        return f"reverse.{self.value}.example.com"
    
    def to_int(self) -> int:
        """Convert IP address to integer."""
        return int(ipaddress.ip_address(self.value))
    
    @classmethod
    def from_int(cls, value: int, version: int = 4) -> 'IpAddress':
        """Create IP address from integer."""
        if version == 4:
            ip = ipaddress.IPv4Address(value)
        else:
            ip = ipaddress.IPv6Address(value)
        return cls(str(ip))
    
    def __str__(self) -> str:
        """String representation."""
        return self.value
    
    def __repr__(self) -> str:
        """Debug representation."""
        return f"IpAddress(value='{self.value}', version={self.version})"