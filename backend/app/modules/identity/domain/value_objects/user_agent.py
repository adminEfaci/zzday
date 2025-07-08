"""
User Agent Value Object

Immutable representation of a user agent string with parsing capabilities.
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from app.core.domain.base import ValueObject


class BrowserType(Enum):
    """Known browser types."""
    
    CHROME = "Chrome"
    FIREFOX = "Firefox"
    SAFARI = "Safari"
    EDGE = "Edge"
    OPERA = "Opera"
    IE = "Internet Explorer"
    BRAVE = "Brave"
    VIVALDI = "Vivaldi"
    SAMSUNG = "Samsung Internet"
    UC = "UC Browser"
    MOBILE_SAFARI = "Mobile Safari"
    CHROME_MOBILE = "Chrome Mobile"
    FIREFOX_MOBILE = "Firefox Mobile"
    WEBVIEW = "WebView"
    BOT = "Bot"
    UNKNOWN = "Unknown"


class OperatingSystem(Enum):
    """Known operating systems."""
    
    WINDOWS = "Windows"
    MACOS = "macOS"
    LINUX = "Linux"
    ANDROID = "Android"
    IOS = "iOS"
    CHROME_OS = "Chrome OS"
    UBUNTU = "Ubuntu"
    DEBIAN = "Debian"
    FEDORA = "Fedora"
    WINDOWS_PHONE = "Windows Phone"
    BLACKBERRY = "BlackBerry"
    BOT = "Bot"
    UNKNOWN = "Unknown"


class DeviceCategory(Enum):
    """Device categories."""
    
    DESKTOP = "Desktop"
    MOBILE = "Mobile"
    TABLET = "Tablet"
    TV = "TV"
    CONSOLE = "Console"
    WEARABLE = "Wearable"
    BOT = "Bot"
    UNKNOWN = "Unknown"


@dataclass(frozen=True)
class UserAgent(ValueObject):
    """
    Value object representing a parsed user agent string.
    
    Provides browser, OS, and device information extracted from the user agent.
    """
    
    raw_string: str
    browser_type: BrowserType
    browser_version: str | None
    operating_system: OperatingSystem
    os_version: str | None
    device_category: DeviceCategory
    device_model: str | None
    is_bot: bool
    
    def __post_init__(self):
        """Validate user agent."""
        if not self.raw_string:
            raise ValueError("User agent string is required")
        
        # Truncate extremely long user agents
        if len(self.raw_string) > 1000:
            object.__setattr__(self, 'raw_string', self.raw_string[:1000])
    
    @classmethod
    def parse(cls, user_agent_string: str) -> 'UserAgent':
        """Parse a user agent string into components."""
        if not user_agent_string:
            return cls._create_unknown()
        
        # Detect bots first
        is_bot = cls._is_bot(user_agent_string)
        if is_bot:
            return cls(
                raw_string=user_agent_string,
                browser_type=BrowserType.BOT,
                browser_version=None,
                operating_system=OperatingSystem.BOT,
                os_version=None,
                device_category=DeviceCategory.BOT,
                device_model=None,
                is_bot=True
            )
        
        # Parse components
        browser_info = cls._parse_browser(user_agent_string)
        os_info = cls._parse_operating_system(user_agent_string)
        device_info = cls._parse_device(user_agent_string, os_info['os'])
        
        return cls(
            raw_string=user_agent_string,
            browser_type=browser_info['type'],
            browser_version=browser_info['version'],
            operating_system=os_info['os'],
            os_version=os_info['version'],
            device_category=device_info['category'],
            device_model=device_info['model'],
            is_bot=False
        )
    
    @classmethod
    def _create_unknown(cls) -> 'UserAgent':
        """Create an unknown user agent."""
        return cls(
            raw_string='',
            browser_type=BrowserType.UNKNOWN,
            browser_version=None,
            operating_system=OperatingSystem.UNKNOWN,
            os_version=None,
            device_category=DeviceCategory.UNKNOWN,
            device_model=None,
            is_bot=False
        )
    
    @staticmethod
    def _is_bot(user_agent: str) -> bool:
        """Check if user agent is a bot."""
        bot_patterns = [
            r'bot', r'crawler', r'spider', r'scraper', r'curl', r'wget',
            r'python', r'java', r'ruby', r'perl', r'php',
            r'googlebot', r'bingbot', r'slurp', r'duckduckbot',
            r'baiduspider', r'yandexbot', r'facebookexternalhit',
            r'twitterbot', r'linkedinbot', r'whatsapp', r'slackbot'
        ]
        
        user_agent_lower = user_agent.lower()
        return any(re.search(pattern, user_agent_lower) for pattern in bot_patterns)
    
    @staticmethod
    def _parse_browser(user_agent: str) -> dict[str, Any]:
        """Parse browser information from user agent."""
        # Order matters - check more specific patterns first
        browser_patterns = [
            # Edge
            (r'Edg/(\d+\.[\d.]+)', BrowserType.EDGE),
            (r'Edge/(\d+\.[\d.]+)', BrowserType.EDGE),
            
            # Opera
            (r'OPR/(\d+\.[\d.]+)', BrowserType.OPERA),
            (r'Opera/(\d+\.[\d.]+)', BrowserType.OPERA),
            
            # Samsung Internet
            (r'SamsungBrowser/(\d+\.[\d.]+)', BrowserType.SAMSUNG),
            
            # UC Browser
            (r'UCBrowser/(\d+\.[\d.]+)', BrowserType.UC),
            
            # Chrome (and Chrome-based)
            (r'Chrome/(\d+\.[\d.]+)', BrowserType.CHROME),
            (r'CriOS/(\d+\.[\d.]+)', BrowserType.CHROME_MOBILE),
            
            # Firefox
            (r'Firefox/(\d+\.[\d.]+)', BrowserType.FIREFOX),
            (r'FxiOS/(\d+\.[\d.]+)', BrowserType.FIREFOX_MOBILE),
            
            # Safari
            (r'Version/(\d+\.[\d.]+).*Safari', BrowserType.SAFARI),
            (r'Safari/(\d+\.[\d.]+)', BrowserType.SAFARI),
            
            # Mobile Safari
            (r'Mobile.*Safari', BrowserType.MOBILE_SAFARI),
            
            # Internet Explorer
            (r'MSIE (\d+\.[\d.]+)', BrowserType.IE),
            (r'Trident.*rv:(\d+\.[\d.]+)', BrowserType.IE),
            
            # WebView
            (r'wv\)', BrowserType.WEBVIEW),
        ]
        
        for pattern, browser_type in browser_patterns:
            match = re.search(pattern, user_agent)
            if match:
                return {
                    'type': browser_type,
                    'version': match.group(1) if match.lastindex else None
                }
        
        return {'type': BrowserType.UNKNOWN, 'version': None}
    
    @staticmethod
    def _parse_operating_system(user_agent: str) -> dict[str, Any]:
        """Parse operating system information from user agent."""
        os_patterns = [
            # Mobile OS first
            (r'Android (\d+\.[\d.]*)', OperatingSystem.ANDROID),
            (r'Android', OperatingSystem.ANDROID),
            
            (r'iPhone OS (\d+[_\d]*)', OperatingSystem.IOS),
            (r'iOS (\d+\.[\d.]*)', OperatingSystem.IOS),
            (r'iPad.*OS (\d+[_\d]*)', OperatingSystem.IOS),
            (r'iPhone|iPad|iPod', OperatingSystem.IOS),
            
            # Windows
            (r'Windows NT 10\.0', OperatingSystem.WINDOWS, '10'),
            (r'Windows NT 6\.3', OperatingSystem.WINDOWS, '8.1'),
            (r'Windows NT 6\.2', OperatingSystem.WINDOWS, '8'),
            (r'Windows NT 6\.1', OperatingSystem.WINDOWS, '7'),
            (r'Windows NT 6\.0', OperatingSystem.WINDOWS, 'Vista'),
            (r'Windows NT 5\.1', OperatingSystem.WINDOWS, 'XP'),
            (r'Windows Phone (\d+\.[\d.]*)', OperatingSystem.WINDOWS_PHONE),
            (r'Windows', OperatingSystem.WINDOWS),
            
            # macOS
            (r'Mac OS X (\d+[_\d]*)', OperatingSystem.MACOS),
            (r'Macintosh', OperatingSystem.MACOS),
            
            # Linux distributions
            (r'Ubuntu', OperatingSystem.UBUNTU),
            (r'Debian', OperatingSystem.DEBIAN),
            (r'Fedora', OperatingSystem.FEDORA),
            (r'Linux', OperatingSystem.LINUX),
            
            # Chrome OS
            (r'CrOS', OperatingSystem.CHROME_OS),
            
            # BlackBerry
            (r'BlackBerry|BB10', OperatingSystem.BLACKBERRY),
        ]
        
        for pattern_info in os_patterns:
            if len(pattern_info) == 2:
                pattern, os_type = pattern_info
                version_override = None
            else:
                pattern, os_type, version_override = pattern_info
            
            match = re.search(pattern, user_agent)
            if match:
                version = version_override
                if not version and match.lastindex:
                    version = match.group(1).replace('_', '.')
                
                return {'os': os_type, 'version': version}
        
        return {'os': OperatingSystem.UNKNOWN, 'version': None}
    
    @staticmethod
    def _parse_device(user_agent: str, operating_system: OperatingSystem) -> dict[str, Any]:
        """Parse device information from user agent."""
        # Check for tablet indicators
        tablet_indicators = [
            'iPad', 'tablet', 'Tab', 'GT-P', 'SM-T', 'Nexus 7', 'Nexus 10'
        ]
        
        if any(indicator in user_agent for indicator in tablet_indicators):
            return {'category': DeviceCategory.TABLET, 'model': None}
        
        # Check for mobile
        if operating_system in [OperatingSystem.ANDROID, OperatingSystem.IOS, 
                                OperatingSystem.WINDOWS_PHONE, OperatingSystem.BLACKBERRY]:
            return {'category': DeviceCategory.MOBILE, 'model': None}
        
        # Check for TV
        if any(tv in user_agent for tv in ['TV', 'Smart-TV', 'GoogleTV', 'AppleTV']):
            return {'category': DeviceCategory.TV, 'model': None}
        
        # Check for game console
        if any(console in user_agent for console in ['PlayStation', 'Xbox', 'Nintendo']):
            return {'category': DeviceCategory.CONSOLE, 'model': None}
        
        # Default to desktop for desktop OS
        if operating_system in [OperatingSystem.WINDOWS, OperatingSystem.MACOS, 
                               OperatingSystem.LINUX, OperatingSystem.CHROME_OS]:
            return {'category': DeviceCategory.DESKTOP, 'model': None}
        
        return {'category': DeviceCategory.UNKNOWN, 'model': None}
    
    @property
    def is_mobile(self) -> bool:
        """Check if user agent represents a mobile device."""
        return self.device_category in [DeviceCategory.MOBILE, DeviceCategory.TABLET]
    
    @property
    def is_desktop(self) -> bool:
        """Check if user agent represents a desktop device."""
        return self.device_category == DeviceCategory.DESKTOP
    
    @property
    def is_modern_browser(self) -> bool:
        """Check if browser is considered modern (supports modern web features)."""
        if self.browser_type == BrowserType.IE:
            return False
        
        # Check version for major browsers
        if self.browser_version:
            try:
                major_version = int(self.browser_version.split('.')[0])
                
                min_versions = {
                    BrowserType.CHROME: 80,
                    BrowserType.FIREFOX: 75,
                    BrowserType.SAFARI: 13,
                    BrowserType.EDGE: 80,
                    BrowserType.OPERA: 65
                }
                
                min_version = min_versions.get(self.browser_type)
                if min_version:
                    return major_version >= min_version
            except:
                pass
        
        # Unknown browsers assumed not modern
        return self.browser_type not in [BrowserType.UNKNOWN, BrowserType.BOT]
    
    @property
    def browser_family(self) -> str:
        """Get browser family name."""
        chromium_based = [
            BrowserType.CHROME, BrowserType.EDGE, BrowserType.OPERA,
            BrowserType.BRAVE, BrowserType.VIVALDI, BrowserType.SAMSUNG
        ]
        
        if self.browser_type in chromium_based:
            return "Chromium"
        if self.browser_type in [BrowserType.FIREFOX, BrowserType.FIREFOX_MOBILE]:
            return "Firefox"
        if self.browser_type in [BrowserType.SAFARI, BrowserType.MOBILE_SAFARI]:
            return "Safari"
        if self.browser_type == BrowserType.IE:
            return "Internet Explorer"
        return self.browser_type.value
    
    def to_analytics_data(self) -> dict[str, str]:
        """Get data suitable for analytics."""
        return {
            'browser': self.browser_type.value,
            'browser_version': self.browser_version or 'unknown',
            'browser_family': self.browser_family,
            'os': self.operating_system.value,
            'os_version': self.os_version or 'unknown',
            'device_category': self.device_category.value,
            'is_mobile': self.is_mobile,
            'is_bot': self.is_bot,
            'is_modern': self.is_modern_browser
        }
    
    def get_display_name(self) -> str:
        """Get human-readable display name."""
        parts = []
        
        # Browser
        if self.browser_type != BrowserType.UNKNOWN:
            browser = self.browser_type.value
            if self.browser_version:
                # Just major version for display
                major_version = self.browser_version.split('.')[0]
                browser += f" {major_version}"
            parts.append(browser)
        
        # OS
        if self.operating_system != OperatingSystem.UNKNOWN:
            os = self.operating_system.value
            if self.os_version:
                os += f" {self.os_version}"
            parts.append(f"on {os}")
        
        # Device
        if self.device_category not in [DeviceCategory.UNKNOWN, DeviceCategory.DESKTOP]:
            parts.append(f"({self.device_category.value})")
        
        return ' '.join(parts) if parts else 'Unknown Browser'
    
    def __str__(self) -> str:
        """String representation."""
        return self.get_display_name()
    
    def __repr__(self) -> str:
        """Debug representation."""
        return f"UserAgent(browser={self.browser_type.value}, os={self.operating_system.value}, device={self.device_category.value})"
