"""Webhook receiver for handling incoming webhook events.

This module provides webhook receiving functionality with signature validation,
event processing, and error handling.
"""

import asyncio
import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from aiohttp import web

from app.modules.integration.domain.aggregates import WebhookEndpoint
from app.modules.integration.infrastructure.security import WebhookSignatureValidator

logger = logging.getLogger(__name__)


class WebhookReceiver:
    """Webhook receiver for handling incoming events."""

    def __init__(
        self,
        signature_validator: WebhookSignatureValidator,
        event_handler: Callable | None = None,
        error_handler: Callable | None = None,
    ):
        """Initialize webhook receiver.

        Args:
            signature_validator: Signature validation service
            event_handler: Async function to handle events
            error_handler: Async function to handle errors
        """
        self.signature_validator = signature_validator
        self.event_handler = event_handler
        self.error_handler = error_handler
        self.routes = web.RouteTableDef()
        self._setup_routes()

        # Event queue for async processing
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self._processing = False

        # Metrics
        self.metrics = {
            "total_received": 0,
            "signature_valid": 0,
            "signature_invalid": 0,
            "processing_success": 0,
            "processing_failed": 0,
        }

    def _setup_routes(self):
        """Setup webhook routes."""

        @self.routes.post("/{endpoint_path:.*}")
        async def handle_webhook(request: web.Request) -> web.Response:
            """Handle incoming webhook request."""
            endpoint_path = request.match_info.get("endpoint_path", "")
            return await self._handle_webhook_request(request, endpoint_path)

        @self.routes.put("/{endpoint_path:.*}")
        async def handle_webhook_put(request: web.Request) -> web.Response:
            """Handle PUT webhook request."""
            endpoint_path = request.match_info.get("endpoint_path", "")
            return await self._handle_webhook_request(request, endpoint_path)

        @self.routes.patch("/{endpoint_path:.*}")
        async def handle_webhook_patch(request: web.Request) -> web.Response:
            """Handle PATCH webhook request."""
            endpoint_path = request.match_info.get("endpoint_path", "")
            return await self._handle_webhook_request(request, endpoint_path)

    async def _handle_webhook_request(
        self, request: web.Request, endpoint_path: str
    ) -> web.Response:
        """Handle incoming webhook request.

        Args:
            request: aiohttp request
            endpoint_path: Webhook endpoint path

        Returns:
            HTTP response
        """
        self.metrics["total_received"] += 1

        try:
            # Get request data
            headers = dict(request.headers)
            raw_body = await request.read()

            # Parse body
            try:
                if request.content_type == "application/json":
                    body = await request.json() if raw_body else {}
                else:
                    body = {"raw": raw_body.decode("utf-8", errors="ignore")}
            except Exception as e:
                logger.exception(f"Failed to parse webhook body: {e}")
                body = {"raw": raw_body.decode("utf-8", errors="ignore")}

            # Create webhook event
            event = {
                "id": str(uuid4()),
                "endpoint_path": endpoint_path,
                "method": request.method,
                "headers": headers,
                "body": body,
                "raw_body": raw_body,
                "received_at": datetime.now(UTC),
                "remote_addr": request.remote,
                "external_id": headers.get("X-Event-ID") or headers.get("X-Request-ID"),
                "event_type": headers.get("X-Event-Type", "unknown"),
            }

            # Validate endpoint exists (would be done via repository in real impl)
            endpoint = await self._get_endpoint(endpoint_path)
            if not endpoint:
                logger.warning(f"Unknown webhook endpoint: {endpoint_path}")
                return web.Response(status=404, text="Endpoint not found")

            # Check method is allowed
            if request.method not in [m.value for m in endpoint.allowed_methods]:
                return web.Response(status=405, text="Method not allowed")

            # Validate signature
            is_valid = await self._validate_signature(endpoint, headers, raw_body)

            event["signature_valid"] = is_valid

            if not is_valid:
                self.metrics["signature_invalid"] += 1
                logger.warning(f"Invalid webhook signature for {endpoint_path}")
                return web.Response(status=401, text="Invalid signature")

            self.metrics["signature_valid"] += 1

            # Check required headers
            for header, value in endpoint.required_headers.items():
                if headers.get(header) != value:
                    return web.Response(
                        status=400, text=f"Missing or invalid required header: {header}"
                    )

            # Add to processing queue
            event["endpoint"] = endpoint
            await self.event_queue.put(event)

            # Start processing if not already running
            if not self._processing:
                asyncio.create_task(self._process_events())

            # Return success response
            return web.Response(
                status=200,
                text=json.dumps({"id": event["id"], "status": "received"}),
                content_type="application/json",
            )

        except Exception as e:
            logger.error(f"Webhook handling error: {e}", exc_info=True)

            if self.error_handler:
                try:
                    await self.error_handler(e, request)
                except Exception as handler_error:
                    logger.exception(f"Error handler failed: {handler_error}")

            return web.Response(status=500, text="Internal server error")

    async def _get_endpoint(self, path: str) -> WebhookEndpoint | None:
        """Get webhook endpoint by path.

        This would typically query the repository.
        For now, returns a mock endpoint for demonstration.
        """
        # In real implementation, this would query WebhookEndpointRepository
        # For now, return None to indicate not found
        return None

    async def _validate_signature(
        self, endpoint: WebhookEndpoint, headers: dict[str, str], body: bytes
    ) -> bool:
        """Validate webhook signature.

        Args:
            endpoint: Webhook endpoint
            headers: Request headers
            body: Raw request body

        Returns:
            True if signature is valid
        """
        signature_header = endpoint.signature_config.header_name
        signature = headers.get(signature_header)

        if not signature:
            logger.warning(f"Missing signature header: {signature_header}")
            return False

        return self.signature_validator.validate(
            secret=endpoint.secret_token,
            signature=signature,
            payload=body,
            algorithm=endpoint.signature_config.algorithm,
            encoding=endpoint.signature_config.encoding,
        )

    async def _process_events(self):
        """Process events from queue."""
        self._processing = True

        try:
            while not self.event_queue.empty():
                event = await self.event_queue.get()

                try:
                    if self.event_handler:
                        await self.event_handler(event)

                    self.metrics["processing_success"] += 1

                except Exception as e:
                    self.metrics["processing_failed"] += 1
                    logger.error(f"Event processing failed: {e}", exc_info=True)

                    if self.error_handler:
                        try:
                            await self.error_handler(e, event)
                        except Exception as handler_error:
                            logger.exception(f"Error handler failed: {handler_error}")

        finally:
            self._processing = False

    def create_app(
        self, middlewares: list[web.middleware] | None = None
    ) -> web.Application:
        """Create aiohttp application for webhook receiver.

        Args:
            middlewares: List of middlewares to add

        Returns:
            Configured aiohttp application
        """
        app = web.Application(middlewares=middlewares or [])
        app.add_routes(self.routes)

        # Add startup/cleanup handlers
        app.on_startup.append(self._on_startup)
        app.on_cleanup.append(self._on_cleanup)

        return app

    async def _on_startup(self, app: web.Application):
        """Handle application startup."""
        logger.info("Webhook receiver starting up")

    async def _on_cleanup(self, app: web.Application):
        """Handle application cleanup."""
        logger.info("Webhook receiver shutting down")

        # Process remaining events
        if not self.event_queue.empty():
            logger.info(f"Processing {self.event_queue.qsize()} remaining events")
            await self._process_events()

    async def simulate_webhook(
        self,
        endpoint: WebhookEndpoint,
        payload: dict[str, Any],
        event_type: str = "test",
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Simulate a webhook event for testing.

        Args:
            endpoint: Webhook endpoint
            payload: Event payload
            event_type: Event type
            headers: Additional headers

        Returns:
            Simulated event data
        """
        # Generate signature
        body = json.dumps(payload).encode()
        signature = self.signature_validator.generate_signature(
            secret=endpoint.secret_token,
            payload=body,
            algorithm=endpoint.signature_config.algorithm,
            encoding=endpoint.signature_config.encoding,
        )

        # Build headers
        event_headers = {
            endpoint.signature_config.header_name: signature,
            "X-Event-Type": event_type,
            "X-Event-ID": str(uuid4()),
            "Content-Type": "application/json",
        }

        if headers:
            event_headers.update(headers)

        # Create event
        event = {
            "id": str(uuid4()),
            "endpoint": endpoint,
            "method": "POST",
            "headers": event_headers,
            "body": payload,
            "raw_body": body,
            "received_at": datetime.now(UTC),
            "signature_valid": True,
            "event_type": event_type,
        }

        # Process event
        if self.event_handler:
            await self.event_handler(event)

        return event

    def get_metrics(self) -> dict[str, Any]:
        """Get receiver metrics."""
        total = self.metrics["total_received"]
        return {
            **self.metrics,
            "signature_valid_rate": (
                self.metrics["signature_valid"] / total if total > 0 else 0
            ),
            "processing_success_rate": (
                self.metrics["processing_success"]
                / (
                    self.metrics["processing_success"]
                    + self.metrics["processing_failed"]
                )
                if (
                    self.metrics["processing_success"]
                    + self.metrics["processing_failed"]
                )
                > 0
                else 0
            ),
        }
