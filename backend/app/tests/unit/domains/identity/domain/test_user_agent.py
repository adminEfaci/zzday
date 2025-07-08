"""
Test cases for UserAgent value object.

Tests all aspects of user agent parsing including browser detection,
OS detection, device categorization, and analytics features.
"""

from dataclasses import FrozenInstanceError

import pytest

from app.modules.identity.domain.value_objects.user_agent import (
    BrowserType,
    DeviceCategory,
    OperatingSystem,
    UserAgent,
)


class TestUserAgentCreation:
    """Test UserAgent creation and validation."""

    def test_create_valid_user_agent(self):
        """Test creating a valid user agent."""
        user_agent = UserAgent(
            raw_string="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            browser_type=BrowserType.CHROME,
            browser_version="91.0.4472.124",
            operating_system=OperatingSystem.WINDOWS,
            os_version="10",
            device_category=DeviceCategory.DESKTOP,
            device_model=None,
            is_bot=False,
        )

        assert (
            user_agent.raw_string
            == "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )
        assert user_agent.browser_type == BrowserType.CHROME
        assert user_agent.operating_system == OperatingSystem.WINDOWS
        assert user_agent.device_category == DeviceCategory.DESKTOP
        assert user_agent.is_bot is False

    def test_empty_user_agent_string_raises_error(self):
        """Test that empty user agent string raises ValueError."""
        with pytest.raises(ValueError, match="User agent string is required"):
            UserAgent(
                raw_string="",
                browser_type=BrowserType.UNKNOWN,
                browser_version=None,
                operating_system=OperatingSystem.UNKNOWN,
                os_version=None,
                device_category=DeviceCategory.UNKNOWN,
                device_model=None,
                is_bot=False,
            )

    def test_very_long_user_agent_truncated(self):
        """Test that very long user agent strings are truncated."""
        long_string = "x" * 1500  # Longer than 1000 chars

        user_agent = UserAgent(
            raw_string=long_string,
            browser_type=BrowserType.UNKNOWN,
            browser_version=None,
            operating_system=OperatingSystem.UNKNOWN,
            os_version=None,
            device_category=DeviceCategory.UNKNOWN,
            device_model=None,
            is_bot=False,
        )

        assert len(user_agent.raw_string) == 1000


class TestUserAgentParsing:
    """Test UserAgent parsing from strings."""

    def test_parse_chrome_windows(self):
        """Test parsing Chrome on Windows."""
        ua_string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        user_agent = UserAgent.parse(ua_string)

        assert user_agent.browser_type == BrowserType.CHROME
        assert user_agent.browser_version == "91.0.4472.124"
        assert user_agent.operating_system == OperatingSystem.WINDOWS
        assert user_agent.os_version == "10"
        assert user_agent.device_category == DeviceCategory.DESKTOP
        assert user_agent.is_bot is False

    def test_parse_firefox_macos(self):
        """Test parsing Firefox on macOS."""
        ua_string = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0"
        user_agent = UserAgent.parse(ua_string)

        assert user_agent.browser_type == BrowserType.FIREFOX
        assert user_agent.browser_version == "89.0"
        assert user_agent.operating_system == OperatingSystem.MACOS
        assert "10.15" in (user_agent.os_version or "")
        assert user_agent.device_category == DeviceCategory.DESKTOP

    def test_parse_safari_ios(self):
        """Test parsing Safari on iOS."""
        ua_string = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
        user_agent = UserAgent.parse(ua_string)

        assert user_agent.browser_type == BrowserType.SAFARI
        assert user_agent.operating_system == OperatingSystem.IOS
        assert user_agent.device_category == DeviceCategory.MOBILE

    def test_parse_chrome_android(self):
        """Test parsing Chrome on Android."""
        ua_string = "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36"
        user_agent = UserAgent.parse(ua_string)

        assert user_agent.browser_type == BrowserType.CHROME
        assert user_agent.operating_system == OperatingSystem.ANDROID
        assert user_agent.os_version == "11"
        assert user_agent.device_category == DeviceCategory.MOBILE

    def test_parse_edge_browser(self):
        """Test parsing Microsoft Edge."""
        ua_string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59"
        user_agent = UserAgent.parse(ua_string)

        assert user_agent.browser_type == BrowserType.EDGE
        assert user_agent.browser_version == "91.0.864.59"
        assert user_agent.operating_system == OperatingSystem.WINDOWS

    def test_parse_opera_browser(self):
        """Test parsing Opera browser."""
        ua_string = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 OPR/77.0.4054.254"
        user_agent = UserAgent.parse(ua_string)

        assert user_agent.browser_type == BrowserType.OPERA
        assert user_agent.browser_version == "77.0.4054.254"

    def test_parse_samsung_browser(self):
        """Test parsing Samsung Internet browser."""
        ua_string = "Mozilla/5.0 (Linux; Android 11; SM-A515F) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/14.2 Chrome/87.0.4280.141 Mobile Safari/537.36"
        user_agent = UserAgent.parse(ua_string)

        assert user_agent.browser_type == BrowserType.SAMSUNG
        assert user_agent.browser_version == "14.2"

    def test_parse_ipad_tablet(self):
        """Test parsing iPad as tablet."""
        ua_string = "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1"
        user_agent = UserAgent.parse(ua_string)

        assert user_agent.device_category == DeviceCategory.TABLET
        assert user_agent.operating_system == OperatingSystem.IOS

    def test_parse_android_tablet(self):
        """Test parsing Android tablet."""
        ua_string = "Mozilla/5.0 (Linux; Android 11; SM-T870) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Safari/537.36"
        user_agent = UserAgent.parse(ua_string)

        assert user_agent.device_category == DeviceCategory.TABLET
        assert user_agent.operating_system == OperatingSystem.ANDROID

    def test_parse_empty_string(self):
        """Test parsing empty string."""
        user_agent = UserAgent.parse("")

        assert user_agent.browser_type == BrowserType.UNKNOWN
        assert user_agent.operating_system == OperatingSystem.UNKNOWN
        assert user_agent.device_category == DeviceCategory.UNKNOWN
        assert user_agent.is_bot is False

    def test_parse_bot_user_agent(self):
        """Test parsing bot user agents."""
        bot_agents = [
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
            "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
            "python-requests/2.25.1",
            "curl/7.68.0",
        ]

        for bot_agent in bot_agents:
            user_agent = UserAgent.parse(bot_agent)
            assert user_agent.is_bot is True
            assert user_agent.browser_type == BrowserType.BOT
            assert user_agent.operating_system == OperatingSystem.BOT
            assert user_agent.device_category == DeviceCategory.BOT


class TestUserAgentBotDetection:
    """Test bot detection functionality."""

    def test_is_bot_detection(self):
        """Test bot detection patterns."""
        bot_patterns = [
            "bot",
            "crawler",
            "spider",
            "scraper",
            "curl",
            "wget",
            "python",
            "java",
            "ruby",
            "perl",
            "php",
            "googlebot",
            "bingbot",
            "slurp",
            "duckduckbot",
            "baiduspider",
            "yandexbot",
            "facebookexternalhit",
            "twitterbot",
            "linkedinbot",
            "whatsapp",
            "slackbot",
        ]

        for pattern in bot_patterns:
            test_agent = f"Test {pattern} User Agent"
            assert UserAgent._is_bot(test_agent) is True

    def test_is_not_bot_normal_browsers(self):
        """Test that normal browsers are not detected as bots."""
        normal_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/14.1.1",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) Mobile Safari/604.1",
        ]

        for agent in normal_agents:
            assert UserAgent._is_bot(agent) is False


class TestUserAgentBrowserParsing:
    """Test browser parsing functionality."""

    def test_parse_browser_edge_detection(self):
        """Test Edge browser detection."""
        # New Edge (Chromium-based)
        edge_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/91.0.864.59"
        browser_info = UserAgent._parse_browser(edge_agent)

        assert browser_info["type"] == BrowserType.EDGE
        assert browser_info["version"] == "91.0.864.59"

    def test_parse_browser_chrome_vs_edge(self):
        """Test that Edge is detected before Chrome."""
        # Edge contains Chrome in user agent, but Edge should be detected first
        edge_agent = "Chrome/91.0.4472.124 Edg/91.0.864.59"
        browser_info = UserAgent._parse_browser(edge_agent)

        assert browser_info["type"] == BrowserType.EDGE

    def test_parse_browser_opera_detection(self):
        """Test Opera browser detection."""
        opera_agent = "Mozilla/5.0 Chrome/91.0.4472.124 OPR/77.0.4054.254"
        browser_info = UserAgent._parse_browser(opera_agent)

        assert browser_info["type"] == BrowserType.OPERA
        assert browser_info["version"] == "77.0.4054.254"

    def test_parse_browser_firefox_mobile(self):
        """Test Firefox mobile detection."""
        firefox_mobile = (
            "Mozilla/5.0 (Mobile; rv:89.0) Gecko/89.0 Firefox/89.0 FxiOS/89.0"
        )
        browser_info = UserAgent._parse_browser(firefox_mobile)

        assert browser_info["type"] == BrowserType.FIREFOX_MOBILE

    def test_parse_browser_webview(self):
        """Test WebView detection."""
        webview_agent = "Mozilla/5.0 (Linux; Android 11; wv) AppleWebKit/537.36"
        browser_info = UserAgent._parse_browser(webview_agent)

        assert browser_info["type"] == BrowserType.WEBVIEW

    def test_parse_browser_unknown(self):
        """Test unknown browser detection."""
        unknown_agent = "CustomBrowser/1.0.0"
        browser_info = UserAgent._parse_browser(unknown_agent)

        assert browser_info["type"] == BrowserType.UNKNOWN
        assert browser_info["version"] is None


class TestUserAgentOSParsing:
    """Test operating system parsing functionality."""

    def test_parse_os_android_with_version(self):
        """Test Android OS parsing with version."""
        android_agent = "Mozilla/5.0 (Linux; Android 11; SM-G991B)"
        os_info = UserAgent._parse_operating_system(android_agent)

        assert os_info["os"] == OperatingSystem.ANDROID
        assert os_info["version"] == "11"

    def test_parse_os_ios_with_version(self):
        """Test iOS parsing with version."""
        ios_agent = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)"
        os_info = UserAgent._parse_operating_system(ios_agent)

        assert os_info["os"] == OperatingSystem.IOS
        assert os_info["version"] == "14.6"  # Underscores converted to dots

    def test_parse_os_windows_versions(self):
        """Test Windows version detection."""
        windows_versions = [
            ("Windows NT 10.0", OperatingSystem.WINDOWS, "10"),
            ("Windows NT 6.3", OperatingSystem.WINDOWS, "8.1"),
            ("Windows NT 6.2", OperatingSystem.WINDOWS, "8"),
            ("Windows NT 6.1", OperatingSystem.WINDOWS, "7"),
            ("Windows NT 6.0", OperatingSystem.WINDOWS, "Vista"),
            ("Windows NT 5.1", OperatingSystem.WINDOWS, "XP"),
        ]

        for pattern, expected_os, expected_version in windows_versions:
            test_agent = f"Mozilla/5.0 ({pattern}; Win64; x64)"
            os_info = UserAgent._parse_operating_system(test_agent)

            assert os_info["os"] == expected_os
            assert os_info["version"] == expected_version

    def test_parse_os_macos_with_version(self):
        """Test macOS parsing with version."""
        macos_agent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        os_info = UserAgent._parse_operating_system(macos_agent)

        assert os_info["os"] == OperatingSystem.MACOS
        assert os_info["version"] == "10.15.7"

    def test_parse_os_linux_distributions(self):
        """Test Linux distribution detection."""
        linux_distros = [
            ("Ubuntu", OperatingSystem.UBUNTU),
            ("Debian", OperatingSystem.DEBIAN),
            ("Fedora", OperatingSystem.FEDORA),
            ("Linux", OperatingSystem.LINUX),
        ]

        for distro, expected_os in linux_distros:
            test_agent = f"Mozilla/5.0 (X11; {distro})"
            os_info = UserAgent._parse_operating_system(test_agent)

            assert os_info["os"] == expected_os

    def test_parse_os_chrome_os(self):
        """Test Chrome OS detection."""
        chromeos_agent = "Mozilla/5.0 (X11; CrOS x86_64 13904.97.0)"
        os_info = UserAgent._parse_operating_system(chromeos_agent)

        assert os_info["os"] == OperatingSystem.CHROME_OS

    def test_parse_os_unknown(self):
        """Test unknown OS detection."""
        unknown_agent = "CustomOS/1.0"
        os_info = UserAgent._parse_operating_system(unknown_agent)

        assert os_info["os"] == OperatingSystem.UNKNOWN
        assert os_info["version"] is None


class TestUserAgentDeviceParsing:
    """Test device category parsing functionality."""

    def test_parse_device_tablet_indicators(self):
        """Test tablet detection."""
        tablet_indicators = [
            "iPad",
            "tablet",
            "Tab",
            "GT-P",
            "SM-T",
            "Nexus 7",
            "Nexus 10",
        ]

        for indicator in tablet_indicators:
            test_agent = f"Mozilla/5.0 ({indicator})"
            device_info = UserAgent._parse_device(test_agent, OperatingSystem.ANDROID)

            assert device_info["category"] == DeviceCategory.TABLET

    def test_parse_device_mobile_os(self):
        """Test mobile device detection based on OS."""
        mobile_os_list = [
            OperatingSystem.ANDROID,
            OperatingSystem.IOS,
            OperatingSystem.WINDOWS_PHONE,
            OperatingSystem.BLACKBERRY,
        ]

        for mobile_os in mobile_os_list:
            device_info = UserAgent._parse_device("test", mobile_os)
            assert device_info["category"] == DeviceCategory.MOBILE

    def test_parse_device_tv(self):
        """Test TV device detection."""
        tv_indicators = ["TV", "Smart-TV", "GoogleTV", "AppleTV"]

        for indicator in tv_indicators:
            test_agent = f"Mozilla/5.0 ({indicator})"
            device_info = UserAgent._parse_device(test_agent, OperatingSystem.ANDROID)

            assert device_info["category"] == DeviceCategory.TV

    def test_parse_device_console(self):
        """Test game console detection."""
        console_indicators = ["PlayStation", "Xbox", "Nintendo"]

        for indicator in console_indicators:
            test_agent = f"Mozilla/5.0 ({indicator})"
            device_info = UserAgent._parse_device(test_agent, OperatingSystem.UNKNOWN)

            assert device_info["category"] == DeviceCategory.CONSOLE

    def test_parse_device_desktop(self):
        """Test desktop device detection."""
        desktop_os_list = [
            OperatingSystem.WINDOWS,
            OperatingSystem.MACOS,
            OperatingSystem.LINUX,
            OperatingSystem.CHROME_OS,
        ]

        for desktop_os in desktop_os_list:
            device_info = UserAgent._parse_device("test", desktop_os)
            assert device_info["category"] == DeviceCategory.DESKTOP

    def test_parse_device_unknown(self):
        """Test unknown device detection."""
        device_info = UserAgent._parse_device("test", OperatingSystem.UNKNOWN)
        assert device_info["category"] == DeviceCategory.UNKNOWN


class TestUserAgentProperties:
    """Test UserAgent properties."""

    def test_is_mobile_true(self):
        """Test is_mobile property when true."""
        mobile_agent = UserAgent.parse(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)"
        )
        assert mobile_agent.is_mobile is True

        tablet_agent = UserAgent.parse("Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X)")
        assert tablet_agent.is_mobile is True

    def test_is_mobile_false(self):
        """Test is_mobile property when false."""
        desktop_agent = UserAgent.parse(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124"
        )
        assert desktop_agent.is_mobile is False

    def test_is_desktop_true(self):
        """Test is_desktop property when true."""
        desktop_agent = UserAgent.parse(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124"
        )
        assert desktop_agent.is_desktop is True

    def test_is_desktop_false(self):
        """Test is_desktop property when false."""
        mobile_agent = UserAgent.parse(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)"
        )
        assert mobile_agent.is_desktop is False

    def test_is_modern_browser_true(self):
        """Test is_modern_browser property when true."""
        modern_agents = [
            "Mozilla/5.0 (Windows NT 10.0) Chrome/91.0.4472.124",  # Chrome 91
            "Mozilla/5.0 (Windows NT 10.0) Firefox/89.0",  # Firefox 89
            "Mozilla/5.0 (Macintosh) Version/14.1.1 Safari/605.1.15",  # Safari 14
            "Mozilla/5.0 (Windows NT 10.0) Edg/91.0.864.59",  # Edge 91
        ]

        for agent_string in modern_agents:
            agent = UserAgent.parse(agent_string)
            assert agent.is_modern_browser is True

    def test_is_modern_browser_false_ie(self):
        """Test is_modern_browser property false for IE."""
        ie_agent = UserAgent.parse(
            "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko"
        )
        if ie_agent.browser_type == BrowserType.IE:
            assert ie_agent.is_modern_browser is False

    def test_is_modern_browser_false_old_versions(self):
        """Test is_modern_browser property false for old versions."""
        # Create user agent with old version manually
        old_chrome = UserAgent(
            raw_string="Mozilla/5.0 Chrome/50.0.2661.102",
            browser_type=BrowserType.CHROME,
            browser_version="50.0.2661.102",  # Old version
            operating_system=OperatingSystem.WINDOWS,
            os_version="10",
            device_category=DeviceCategory.DESKTOP,
            device_model=None,
            is_bot=False,
        )

        assert old_chrome.is_modern_browser is False

    def test_browser_family_chromium(self):
        """Test browser family detection for Chromium-based browsers."""
        chromium_types = [
            BrowserType.CHROME,
            BrowserType.EDGE,
            BrowserType.OPERA,
            BrowserType.BRAVE,
            BrowserType.VIVALDI,
            BrowserType.SAMSUNG,
        ]

        for browser_type in chromium_types:
            agent = UserAgent(
                raw_string="test",
                browser_type=browser_type,
                browser_version=None,
                operating_system=OperatingSystem.WINDOWS,
                os_version=None,
                device_category=DeviceCategory.DESKTOP,
                device_model=None,
                is_bot=False,
            )

            assert agent.browser_family == "Chromium"

    def test_browser_family_firefox(self):
        """Test browser family detection for Firefox."""
        firefox_types = [BrowserType.FIREFOX, BrowserType.FIREFOX_MOBILE]

        for browser_type in firefox_types:
            agent = UserAgent(
                raw_string="test",
                browser_type=browser_type,
                browser_version=None,
                operating_system=OperatingSystem.WINDOWS,
                os_version=None,
                device_category=DeviceCategory.DESKTOP,
                device_model=None,
                is_bot=False,
            )

            assert agent.browser_family == "Firefox"

    def test_browser_family_safari(self):
        """Test browser family detection for Safari."""
        safari_types = [BrowserType.SAFARI, BrowserType.MOBILE_SAFARI]

        for browser_type in safari_types:
            agent = UserAgent(
                raw_string="test",
                browser_type=browser_type,
                browser_version=None,
                operating_system=OperatingSystem.MACOS,
                os_version=None,
                device_category=DeviceCategory.DESKTOP,
                device_model=None,
                is_bot=False,
            )

            assert agent.browser_family == "Safari"


class TestUserAgentAnalytics:
    """Test UserAgent analytics functionality."""

    def test_to_analytics_data(self):
        """Test analytics data conversion."""
        agent = UserAgent.parse(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124"
        )
        analytics_data = agent.to_analytics_data()

        expected_keys = [
            "browser",
            "browser_version",
            "browser_family",
            "os",
            "os_version",
            "device_category",
            "is_mobile",
            "is_bot",
            "is_modern",
        ]

        for key in expected_keys:
            assert key in analytics_data

        assert analytics_data["browser"] == "Chrome"
        assert analytics_data["browser_family"] == "Chromium"
        assert analytics_data["os"] == "Windows"
        assert analytics_data["device_category"] == "Desktop"
        assert analytics_data["is_mobile"] is False
        assert analytics_data["is_bot"] is False

    def test_to_analytics_data_unknown_values(self):
        """Test analytics data with unknown values."""
        agent = UserAgent._create_unknown()
        analytics_data = agent.to_analytics_data()

        assert analytics_data["browser_version"] == "unknown"
        assert analytics_data["os_version"] == "unknown"


class TestUserAgentDisplayName:
    """Test UserAgent display name functionality."""

    def test_get_display_name_full(self):
        """Test display name with full information."""
        agent = UserAgent.parse(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124"
        )
        display_name = agent.get_display_name()

        assert "Chrome 91" in display_name
        assert "Windows 10" in display_name

    def test_get_display_name_mobile(self):
        """Test display name for mobile device."""
        agent = UserAgent.parse(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) Safari/604.1"
        )
        display_name = agent.get_display_name()

        assert "Safari" in display_name
        assert "iOS" in display_name
        assert "(Mobile)" in display_name

    def test_get_display_name_tablet(self):
        """Test display name for tablet device."""
        agent = UserAgent.parse(
            "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) Safari/604.1"
        )
        display_name = agent.get_display_name()

        assert "(Tablet)" in display_name

    def test_get_display_name_unknown(self):
        """Test display name for unknown agent."""
        agent = UserAgent._create_unknown()
        display_name = agent.get_display_name()

        assert display_name == "Unknown Browser"

    def test_get_display_name_version_major_only(self):
        """Test that display name shows only major version."""
        agent = UserAgent(
            raw_string="test",
            browser_type=BrowserType.CHROME,
            browser_version="91.0.4472.124",
            operating_system=OperatingSystem.WINDOWS,
            os_version="10.0.19042",
            device_category=DeviceCategory.DESKTOP,
            device_model=None,
            is_bot=False,
        )

        display_name = agent.get_display_name()
        assert "Chrome 91" in display_name  # Should show major version only
        assert "91.0.4472.124" not in display_name  # Should not show full version


class TestUserAgentStringRepresentation:
    """Test UserAgent string representation."""

    def test_str_representation(self):
        """Test __str__ method."""
        agent = UserAgent.parse(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124"
        )
        str_repr = str(agent)

        assert str_repr == agent.get_display_name()

    def test_repr_representation(self):
        """Test __repr__ method."""
        agent = UserAgent.parse(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124"
        )
        repr_str = repr(agent)

        assert "UserAgent" in repr_str
        assert "browser=Chrome" in repr_str
        assert "os=Windows" in repr_str
        assert "device=Desktop" in repr_str


class TestUserAgentImmutability:
    """Test that UserAgent is immutable."""

    def test_immutable_raw_string(self):
        """Test that raw_string cannot be changed."""
        agent = UserAgent.parse(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124"
        )

        with pytest.raises(FrozenInstanceError):
            agent.raw_string = "new_string"

    def test_immutable_browser_type(self):
        """Test that browser_type cannot be changed."""
        agent = UserAgent.parse(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124"
        )

        with pytest.raises(FrozenInstanceError):
            agent.browser_type = BrowserType.FIREFOX


class TestUserAgentEquality:
    """Test UserAgent equality and comparison."""

    def test_equal_user_agents(self):
        """Test that identical user agents are equal."""
        agent1 = UserAgent.parse(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124"
        )
        agent2 = UserAgent.parse(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124"
        )

        assert agent1 == agent2

    def test_different_user_agents_not_equal(self):
        """Test that different user agents are not equal."""
        agent1 = UserAgent.parse(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124"
        )
        agent2 = UserAgent.parse(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Firefox/89.0"
        )

        assert agent1 != agent2


class TestUserAgentEdgeCases:
    """Test UserAgent edge cases and boundary conditions."""

    def test_all_browser_types_supported(self):
        """Test that all browser types are handled."""
        for browser_type in BrowserType:
            agent = UserAgent(
                raw_string="test",
                browser_type=browser_type,
                browser_version=None,
                operating_system=OperatingSystem.UNKNOWN,
                os_version=None,
                device_category=DeviceCategory.UNKNOWN,
                device_model=None,
                is_bot=False,
            )

            assert agent.browser_type == browser_type

    def test_all_operating_systems_supported(self):
        """Test that all operating systems are handled."""
        for os_type in OperatingSystem:
            agent = UserAgent(
                raw_string="test",
                browser_type=BrowserType.UNKNOWN,
                browser_version=None,
                operating_system=os_type,
                os_version=None,
                device_category=DeviceCategory.UNKNOWN,
                device_model=None,
                is_bot=False,
            )

            assert agent.operating_system == os_type

    def test_all_device_categories_supported(self):
        """Test that all device categories are handled."""
        for device_category in DeviceCategory:
            agent = UserAgent(
                raw_string="test",
                browser_type=BrowserType.UNKNOWN,
                browser_version=None,
                operating_system=OperatingSystem.UNKNOWN,
                os_version=None,
                device_category=device_category,
                device_model=None,
                is_bot=False,
            )

            assert agent.device_category == device_category

    def test_version_parsing_edge_cases(self):
        """Test version parsing with edge cases."""
        # Test version with many dots
        agent = UserAgent(
            raw_string="test",
            browser_type=BrowserType.CHROME,
            browser_version="91.0.4472.124.1.2.3",
            operating_system=OperatingSystem.WINDOWS,
            os_version=None,
            device_category=DeviceCategory.DESKTOP,
            device_model=None,
            is_bot=False,
        )

        display_name = agent.get_display_name()
        assert "Chrome 91" in display_name

    def test_modern_browser_no_version(self):
        """Test modern browser detection with no version."""
        agent = UserAgent(
            raw_string="test",
            browser_type=BrowserType.CHROME,
            browser_version=None,  # No version
            operating_system=OperatingSystem.WINDOWS,
            os_version=None,
            device_category=DeviceCategory.DESKTOP,
            device_model=None,
            is_bot=False,
        )

        # Should handle gracefully
        assert isinstance(agent.is_modern_browser, bool)

    def test_modern_browser_invalid_version(self):
        """Test modern browser detection with invalid version."""
        agent = UserAgent(
            raw_string="test",
            browser_type=BrowserType.CHROME,
            browser_version="invalid.version",
            operating_system=OperatingSystem.WINDOWS,
            os_version=None,
            device_category=DeviceCategory.DESKTOP,
            device_model=None,
            is_bot=False,
        )

        # Should handle gracefully without crashing
        assert isinstance(agent.is_modern_browser, bool)

    def test_complex_user_agent_parsing(self):
        """Test parsing complex real-world user agent."""
        complex_ua = "Mozilla/5.0 (Linux; Android 11; SM-G991B Build/RP1A.200720.012; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/91.0.4472.120 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/325.0.0.28.119;]"

        agent = UserAgent.parse(complex_ua)

        # Should parse successfully
        assert agent.operating_system == OperatingSystem.ANDROID
        assert agent.device_category == DeviceCategory.MOBILE
        assert agent.is_bot is False

    def test_user_agent_with_unicode(self):
        """Test user agent with Unicode characters."""
        unicode_ua = "Mozilla/5.0 (测试设备) Chrome/91.0.4472.124"

        agent = UserAgent.parse(unicode_ua)

        # Should handle gracefully
        assert unicode_ua in agent.raw_string

    def test_edge_case_os_version_format(self):
        """Test OS version with different formats."""
        # Test underscore format (iOS)
        ios_ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6_1 like Mac OS X)"
        agent = UserAgent.parse(ios_ua)

        if agent.operating_system == OperatingSystem.IOS:
            assert "14.6.1" in (agent.os_version or "")

    def test_browser_family_unknown_type(self):
        """Test browser family with unknown browser type."""
        agent = UserAgent(
            raw_string="test",
            browser_type=BrowserType.UNKNOWN,
            browser_version=None,
            operating_system=OperatingSystem.UNKNOWN,
            os_version=None,
            device_category=DeviceCategory.UNKNOWN,
            device_model=None,
            is_bot=False,
        )

        assert agent.browser_family == "Unknown"
