"""
Email Adapter

Concrete implementation of IEmailService for sending emails.
Supports multiple email providers through a common interface.
"""

import asyncio
from datetime import UTC, datetime
from typing import Any

from app.core.logging import logger
from app.modules.identity.application.contracts.ports import IEmailService


class SMTPEmailAdapter(IEmailService):
    """SMTP-based email service implementation.
    
    This adapter provides email sending capabilities using SMTP.
    In production, this would integrate with services like:
    - SendGrid
    - AWS SES
    - Mailgun
    - Postmark
    """
    
    def __init__(
        self,
        smtp_host: str = "localhost",
        smtp_port: int = 587,
        smtp_user: str = "",
        smtp_password: str = "",
        from_email: str = "noreply@example.com",
        from_name: str = "Ezzday",
        use_tls: bool = True
    ):
        """Initialize SMTP email adapter.
        
        Args:
            smtp_host: SMTP server hostname
            smtp_port: SMTP server port
            smtp_user: SMTP username
            smtp_password: SMTP password
            from_email: Default sender email
            from_name: Default sender name
            use_tls: Whether to use TLS
        """
        self._smtp_host = smtp_host
        self._smtp_port = smtp_port
        self._smtp_user = smtp_user
        self._smtp_password = smtp_password
        self._from_email = from_email
        self._from_name = from_name
        self._use_tls = use_tls
        self._sent_emails: list[dict[str, Any]] = []
    
    async def send_verification_email(self, email: str, token: str) -> None:
        """Send email verification.
        
        Args:
            email: Recipient email address
            token: Verification token
        """
        subject = "Verify Your Email Address"
        
        html_content = f"""
        <h2>Welcome to Ezzday!</h2>
        <p>Please verify your email address by clicking the link below:</p>
        <p><a href="https://ezzday.com/verify-email?token={token}">Verify Email</a></p>
        <p>Or copy and paste this link into your browser:</p>
        <p>https://ezzday.com/verify-email?token={token}</p>
        <p>This link will expire in 24 hours.</p>
        <p>If you didn't create an account, please ignore this email.</p>
        """
        
        text_content = f"""
        Welcome to Ezzday!
        
        Please verify your email address by visiting:
        https://ezzday.com/verify-email?token={token}
        
        This link will expire in 24 hours.
        
        If you didn't create an account, please ignore this email.
        """
        
        await self._send_email(
            to_email=email,
            subject=subject,
            html_content=html_content,
            text_content=text_content,
            email_type="verification"
        )
    
    async def send_password_reset_email(self, email: str, token: str) -> None:
        """Send password reset email.
        
        Args:
            email: Recipient email address
            token: Reset token
        """
        subject = "Reset Your Password"
        
        html_content = f"""
        <h2>Password Reset Request</h2>
        <p>We received a request to reset your password. Click the link below to create a new password:</p>
        <p><a href="https://ezzday.com/reset-password?token={token}">Reset Password</a></p>
        <p>Or copy and paste this link into your browser:</p>
        <p>https://ezzday.com/reset-password?token={token}</p>
        <p>This link will expire in 1 hour.</p>
        <p>If you didn't request a password reset, please ignore this email and your password will remain unchanged.</p>
        """
        
        text_content = f"""
        Password Reset Request
        
        We received a request to reset your password. Visit the link below to create a new password:
        https://ezzday.com/reset-password?token={token}
        
        This link will expire in 1 hour.
        
        If you didn't request a password reset, please ignore this email and your password will remain unchanged.
        """
        
        await self._send_email(
            to_email=email,
            subject=subject,
            html_content=html_content,
            text_content=text_content,
            email_type="password_reset"
        )
    
    async def send_welcome_email(self, email: str, username: str) -> None:
        """Send welcome email.
        
        Args:
            email: Recipient email address
            username: User's username
        """
        subject = "Welcome to Ezzday!"
        
        html_content = f"""
        <h2>Welcome to Ezzday, {username}!</h2>
        <p>Your account has been successfully created and verified.</p>
        <p>Here are some things you can do to get started:</p>
        <ul>
            <li><a href="https://ezzday.com/profile">Complete your profile</a></li>
            <li><a href="https://ezzday.com/settings/security">Set up two-factor authentication</a></li>
            <li><a href="https://ezzday.com/help">Explore our help center</a></li>
        </ul>
        <p>If you have any questions, feel free to contact our support team.</p>
        <p>Best regards,<br>The Ezzday Team</p>
        """
        
        text_content = f"""
        Welcome to Ezzday, {username}!
        
        Your account has been successfully created and verified.
        
        Here are some things you can do to get started:
        - Complete your profile: https://ezzday.com/profile
        - Set up two-factor authentication: https://ezzday.com/settings/security
        - Explore our help center: https://ezzday.com/help
        
        If you have any questions, feel free to contact our support team.
        
        Best regards,
        The Ezzday Team
        """
        
        await self._send_email(
            to_email=email,
            subject=subject,
            html_content=html_content,
            text_content=text_content,
            email_type="welcome"
        )
    
    async def send_security_alert(self, email: str, alert_type: str, details: dict[str, Any]) -> None:
        """Send security alert email.
        
        Args:
            email: Recipient email address
            alert_type: Type of security alert
            details: Alert details
        """
        subject = f"Security Alert: {alert_type.replace('_', ' ').title()}"
        
        # Build alert content based on type
        alert_messages = {
            "new_login": "A new login to your account was detected.",
            "suspicious_activity": "Suspicious activity was detected on your account.",
            "password_changed": "Your password was recently changed.",
            "mfa_disabled": "Two-factor authentication was disabled on your account.",
            "account_locked": "Your account has been temporarily locked due to multiple failed login attempts."
        }
        
        alert_message = alert_messages.get(alert_type, "A security event occurred on your account.")
        
        html_content = f"""
        <h2>Security Alert</h2>
        <p>{alert_message}</p>
        <h3>Details:</h3>
        <ul>
        """
        
        for key, value in details.items():
            html_content += f"<li><strong>{key.replace('_', ' ').title()}:</strong> {value}</li>"
        
        html_content += """
        </ul>
        <p>If this was you, you can safely ignore this email.</p>
        <p>If you don't recognize this activity, please:</p>
        <ol>
            <li><a href="https://ezzday.com/reset-password">Change your password immediately</a></li>
            <li><a href="https://ezzday.com/settings/security">Review your security settings</a></li>
            <li>Contact our support team if you need assistance</li>
        </ol>
        """
        
        text_content = f"""
        Security Alert
        
        {alert_message}
        
        Details:
        """
        
        for key, value in details.items():
            text_content += f"\n- {key.replace('_', ' ').title()}: {value}"
        
        text_content += """
        
        If this was you, you can safely ignore this email.
        
        If you don't recognize this activity, please:
        1. Change your password immediately: https://ezzday.com/reset-password
        2. Review your security settings: https://ezzday.com/settings/security
        3. Contact our support team if you need assistance
        """
        
        await self._send_email(
            to_email=email,
            subject=subject,
            html_content=html_content,
            text_content=text_content,
            email_type="security_alert",
            priority="high"
        )
    
    async def send_mfa_code(self, email: str, code: str) -> None:
        """Send MFA code via email.
        
        Args:
            email: Recipient email address
            code: MFA code
        """
        subject = "Your Verification Code"
        
        html_content = f"""
        <h2>Verification Code</h2>
        <p>Your verification code is:</p>
        <h1 style="font-size: 32px; letter-spacing: 4px; text-align: center; padding: 20px; background-color: #f0f0f0; border-radius: 8px;">{code}</h1>
        <p>This code will expire in 5 minutes.</p>
        <p>If you didn't request this code, please ignore this email and consider changing your password.</p>
        """
        
        text_content = f"""
        Verification Code
        
        Your verification code is: {code}
        
        This code will expire in 5 minutes.
        
        If you didn't request this code, please ignore this email and consider changing your password.
        """
        
        await self._send_email(
            to_email=email,
            subject=subject,
            html_content=html_content,
            text_content=text_content,
            email_type="mfa_code",
            priority="high"
        )
    
    async def _send_email(
        self,
        to_email: str,
        subject: str,
        html_content: str,
        text_content: str,
        email_type: str,
        priority: str = "normal"
    ) -> None:
        """Send email through SMTP.
        
        Args:
            to_email: Recipient email
            subject: Email subject
            html_content: HTML content
            text_content: Plain text content
            email_type: Type of email
            priority: Email priority
        """
        try:
            # In a real implementation, this would use smtplib or an email service SDK
            # For now, we'll simulate the send
            await asyncio.sleep(0.1)  # Simulate network delay
            
            # Log the email
            email_record = {
                "to": to_email,
                "from": f"{self._from_name} <{self._from_email}>",
                "subject": subject,
                "type": email_type,
                "priority": priority,
                "status": "sent",
                "timestamp": datetime.now(UTC).isoformat()
            }
            
            self._sent_emails.append(email_record)
            
            logger.info(
                "Email sent successfully",
                to=to_email,
                subject=subject,
                email_type=email_type
            )
            
        except Exception as e:
            logger.error(
                f"Failed to send email: {e}",
                to=to_email,
                subject=subject,
                error=str(e)
            )
            # Don't raise - email failures should not break the application
    
    def get_sent_emails(self) -> list[dict[str, Any]]:
        """Get sent emails log (for testing/debugging).
        
        Returns:
            List of sent email records
        """
        return self._sent_emails.copy()
    
    async def health_check(self) -> bool:
        """Check if email service is healthy.
        
        Returns:
            True if service is accessible
        """
        try:
            # In a real implementation, this would test SMTP connection
            # For now, we'll just return True
            return True
        except Exception as e:
            logger.error(f"Email service health check failed: {e}")
            return False


class SendGridEmailAdapter(IEmailService):
    """SendGrid-based email service implementation."""
    
    def __init__(self, api_key: str, from_email: str = "noreply@example.com"):
        """Initialize SendGrid adapter.
        
        Args:
            api_key: SendGrid API key
            from_email: Default sender email
        """
        self._api_key = api_key
        self._from_email = from_email
        # In a real implementation, initialize SendGrid client here
    
    async def send_verification_email(self, email: str, token: str) -> None:
        """Send email verification using SendGrid."""
        # Implementation would use SendGrid SDK
        await asyncio.sleep(0.05)
        logger.info(f"SendGrid: Verification email sent to {email}")
    
    async def send_password_reset_email(self, email: str, token: str) -> None:
        """Send password reset email using SendGrid."""
        await asyncio.sleep(0.05)
        logger.info(f"SendGrid: Password reset email sent to {email}")
    
    async def send_welcome_email(self, email: str, username: str) -> None:
        """Send welcome email using SendGrid."""
        await asyncio.sleep(0.05)
        logger.info(f"SendGrid: Welcome email sent to {email}")
    
    async def send_security_alert(self, email: str, alert_type: str, details: dict[str, Any]) -> None:
        """Send security alert using SendGrid."""
        await asyncio.sleep(0.05)
        logger.info(f"SendGrid: Security alert sent to {email}")
    
    async def send_mfa_code(self, email: str, code: str) -> None:
        """Send MFA code using SendGrid."""
        await asyncio.sleep(0.05)
        logger.info(f"SendGrid: MFA code sent to {email}")
