"""
Performance benchmarks for session management.

Tests session creation, validation, and cleanup performance
under various load conditions and scenarios.
"""

import asyncio
import statistics
import time
from datetime import UTC, datetime, timedelta

import pytest

from app.modules.identity.application.commands.authentication import (
    LoginCommand,
    RefreshTokenCommand,
)
from app.modules.identity.application.commands.session import (
    RevokeAllSessionsCommand,
    RevokeSessionCommand,
    ValidateSessionCommand,
)
from app.modules.identity.application.queries.session import (
    GetActiveSessionsQuery,
    GetSessionDetailsQuery,
)


@pytest.mark.performance
class TestSessionCreationPerformance:
    """Test session creation performance."""

    @pytest.fixture
    async def test_users(self, app_container, faker):
        """Create multiple test users for performance testing."""
        app_container.get("register_user_command_handler")
        users = []

        for _ in range(100):  # Create 100 test users
            email = faker.email()
            password = "TestPassword123!@#"

            # In a real test, you'd use proper registration commands
            # For benchmark purposes, we'll create users directly
            user_service = app_container.get("user_service")
            user = await user_service.create_user(
                email=email, password=password, username=faker.user_name()
            )

            users.append({"id": user.id, "email": email, "password": password})

        return users

    @pytest.mark.asyncio
    async def test_concurrent_session_creation_performance(
        self, app_container, test_users
    ):
        """Test performance of concurrent session creation."""
        login_handler = app_container.get("login_command_handler")

        async def create_session(user_data):
            """Create a session for a user."""
            start_time = time.time()

            command = LoginCommand(
                email=user_data["email"],
                password=user_data["password"],
                ip_address="192.168.1.100",
                user_agent="Mozilla/5.0 (Performance Test)",
            )

            result = await login_handler.handle(command)
            end_time = time.time()

            return {
                "duration": end_time - start_time,
                "success": result.success,
                "session_id": result.session_id if result.success else None,
            }

        # Test with different concurrency levels
        concurrency_levels = [1, 5, 10, 25, 50, 100]
        results = {}

        for concurrency in concurrency_levels:
            print(f"\nTesting with {concurrency} concurrent sessions...")

            # Select subset of users for this test
            selected_users = test_users[:concurrency]

            # Measure concurrent session creation
            start_time = time.time()

            tasks = [create_session(user) for user in selected_users]
            session_results = await asyncio.gather(*tasks)

            end_time = time.time()
            total_duration = end_time - start_time

            # Calculate metrics
            successful_sessions = [r for r in session_results if r["success"]]
            session_durations = [r["duration"] for r in successful_sessions]

            results[concurrency] = {
                "total_duration": total_duration,
                "successful_sessions": len(successful_sessions),
                "success_rate": len(successful_sessions) / len(session_results),
                "avg_session_creation_time": statistics.mean(session_durations)
                if session_durations
                else 0,
                "p95_session_creation_time": statistics.quantiles(
                    session_durations, n=20
                )[18]
                if len(session_durations) > 20
                else max(session_durations)
                if session_durations
                else 0,
                "throughput": len(successful_sessions) / total_duration
                if total_duration > 0
                else 0,
            }

            print(f"  Success rate: {results[concurrency]['success_rate']:.2%}")
            print(
                f"  Avg creation time: {results[concurrency]['avg_session_creation_time']:.3f}s"
            )
            print(
                f"  P95 creation time: {results[concurrency]['p95_session_creation_time']:.3f}s"
            )
            print(
                f"  Throughput: {results[concurrency]['throughput']:.1f} sessions/sec"
            )

        # Performance assertions
        assert results[1]["success_rate"] >= 0.99  # 99% success rate for single session
        assert (
            results[1]["avg_session_creation_time"] <= 0.1
        )  # Under 100ms for single session

        assert results[10]["success_rate"] >= 0.95  # 95% success rate for 10 concurrent
        assert results[10]["avg_session_creation_time"] <= 0.5  # Under 500ms average

        assert results[50]["success_rate"] >= 0.90  # 90% success rate for 50 concurrent
        assert results[50]["throughput"] >= 20  # At least 20 sessions/sec throughput

        return results

    @pytest.mark.asyncio
    async def test_session_validation_performance(self, app_container, test_users):
        """Test session validation performance."""
        login_handler = app_container.get("login_command_handler")
        validate_handler = app_container.get("validate_session_command_handler")

        # Create sessions for testing
        sessions = []
        for user in test_users[:50]:  # Use 50 users
            login_command = LoginCommand(
                email=user["email"],
                password=user["password"],
                ip_address="192.168.1.100",
                user_agent="Mozilla/5.0...",
            )

            login_result = await login_handler.handle(login_command)
            if login_result.success:
                sessions.append(
                    {
                        "session_id": login_result.session_id,
                        "user_id": user["id"],
                        "access_token": login_result.access_token,
                    }
                )

        async def validate_session(session_data):
            """Validate a session."""
            start_time = time.time()

            command = ValidateSessionCommand(
                session_id=session_data["session_id"],
                ip_address="192.168.1.100",
                user_agent="Mozilla/5.0...",
            )

            try:
                result = await validate_handler.handle(command)
                end_time = time.time()

                return {
                    "duration": end_time - start_time,
                    "valid": result.is_valid,
                    "session_id": session_data["session_id"],
                }
            except Exception as e:
                end_time = time.time()
                return {
                    "duration": end_time - start_time,
                    "valid": False,
                    "error": str(e),
                    "session_id": session_data["session_id"],
                }

        # Test validation performance
        validation_rounds = 5
        all_results = []

        for round_num in range(validation_rounds):
            print(f"\nValidation round {round_num + 1}...")

            start_time = time.time()

            # Validate all sessions concurrently
            tasks = [validate_session(session) for session in sessions]
            round_results = await asyncio.gather(*tasks)

            end_time = time.time()
            round_duration = end_time - start_time

            valid_validations = [r for r in round_results if r["valid"]]
            validation_durations = [r["duration"] for r in round_results]

            round_metrics = {
                "round": round_num + 1,
                "total_duration": round_duration,
                "validations": len(round_results),
                "valid_sessions": len(valid_validations),
                "validation_rate": len(valid_validations) / len(round_results),
                "avg_validation_time": statistics.mean(validation_durations),
                "p95_validation_time": statistics.quantiles(validation_durations, n=20)[
                    18
                ]
                if len(validation_durations) > 20
                else max(validation_durations),
                "throughput": len(round_results) / round_duration,
            }

            all_results.append(round_metrics)

            print(f"  Validation rate: {round_metrics['validation_rate']:.2%}")
            print(f"  Avg validation time: {round_metrics['avg_validation_time']:.3f}s")
            print(f"  Throughput: {round_metrics['throughput']:.1f} validations/sec")

        # Calculate overall metrics
        overall_avg_time = statistics.mean(
            [r["avg_validation_time"] for r in all_results]
        )
        overall_throughput = statistics.mean([r["throughput"] for r in all_results])

        # Performance assertions
        assert overall_avg_time <= 0.05  # Under 50ms average validation time
        assert overall_throughput >= 100  # At least 100 validations/sec
        assert all(
            r["validation_rate"] >= 0.95 for r in all_results
        )  # 95% validation success rate

        return all_results

    @pytest.mark.asyncio
    async def test_session_cleanup_performance(self, app_container, test_users):
        """Test session cleanup and expiration performance."""
        login_handler = app_container.get("login_command_handler")
        session_service = app_container.get("session_service")

        # Create many sessions with different expiration times
        expired_sessions = []
        active_sessions = []

        for i, user in enumerate(test_users):
            login_command = LoginCommand(
                email=user["email"],
                password=user["password"],
                ip_address="192.168.1.100",
                user_agent="Mozilla/5.0...",
            )

            login_result = await login_handler.handle(login_command)

            if login_result.success:
                session_id = login_result.session_id

                # Make half the sessions "expired" by backdating them
                if i % 2 == 0:
                    await session_service.set_session_expiry(
                        session_id,
                        datetime.now(UTC) - timedelta(hours=1),  # Expired 1 hour ago
                    )
                    expired_sessions.append(session_id)
                else:
                    active_sessions.append(session_id)

        print(
            f"Created {len(expired_sessions)} expired sessions and {len(active_sessions)} active sessions"
        )

        # Test cleanup performance
        start_time = time.time()

        cleanup_result = await session_service.cleanup_expired_sessions()

        end_time = time.time()
        cleanup_duration = end_time - start_time

        cleanup_metrics = {
            "total_sessions": len(expired_sessions) + len(active_sessions),
            "expired_sessions": len(expired_sessions),
            "active_sessions": len(active_sessions),
            "cleanup_duration": cleanup_duration,
            "sessions_cleaned": cleanup_result["sessions_cleaned"],
            "cleanup_rate": cleanup_result["sessions_cleaned"] / cleanup_duration
            if cleanup_duration > 0
            else 0,
        }

        print(f"Cleanup completed in {cleanup_duration:.3f}s")
        print(f"Cleaned {cleanup_result['sessions_cleaned']} sessions")
        print(f"Cleanup rate: {cleanup_metrics['cleanup_rate']:.1f} sessions/sec")

        # Performance assertions
        assert cleanup_duration <= 5.0  # Cleanup should complete within 5 seconds
        assert (
            cleanup_metrics["cleanup_rate"] >= 10
        )  # At least 10 sessions/sec cleanup rate
        assert (
            cleanup_result["sessions_cleaned"] >= len(expired_sessions) * 0.9
        )  # Clean at least 90% of expired sessions

        return cleanup_metrics


@pytest.mark.performance
class TestSessionTokenPerformance:
    """Test session token operations performance."""

    @pytest.fixture
    async def active_sessions(self, app_container, test_users):
        """Create active sessions with tokens for testing."""
        login_handler = app_container.get("login_command_handler")
        sessions = []

        for user in test_users[:25]:  # Use 25 users
            login_command = LoginCommand(
                email=user["email"],
                password=user["password"],
                ip_address="192.168.1.100",
                user_agent="Mozilla/5.0...",
            )

            login_result = await login_handler.handle(login_command)

            if login_result.success:
                sessions.append(
                    {
                        "user_id": user["id"],
                        "session_id": login_result.session_id,
                        "access_token": login_result.access_token,
                        "refresh_token": login_result.refresh_token,
                    }
                )

        return sessions

    @pytest.mark.asyncio
    async def test_token_refresh_performance(self, app_container, active_sessions):
        """Test token refresh performance."""
        refresh_handler = app_container.get("refresh_token_command_handler")

        async def refresh_token(session_data):
            """Refresh a token."""
            start_time = time.time()

            command = RefreshTokenCommand(refresh_token=session_data["refresh_token"])

            try:
                result = await refresh_handler.handle(command)
                end_time = time.time()

                return {
                    "duration": end_time - start_time,
                    "success": True,
                    "new_access_token": result.access_token,
                    "new_refresh_token": result.refresh_token,
                }
            except Exception as e:
                end_time = time.time()
                return {
                    "duration": end_time - start_time,
                    "success": False,
                    "error": str(e),
                }

        # Test concurrent token refresh
        print(f"Testing concurrent refresh of {len(active_sessions)} tokens...")

        start_time = time.time()

        tasks = [refresh_token(session) for session in active_sessions]
        refresh_results = await asyncio.gather(*tasks)

        end_time = time.time()
        total_duration = end_time - start_time

        # Calculate metrics
        successful_refreshes = [r for r in refresh_results if r["success"]]
        refresh_durations = [r["duration"] for r in refresh_results]

        metrics = {
            "total_duration": total_duration,
            "total_refreshes": len(refresh_results),
            "successful_refreshes": len(successful_refreshes),
            "success_rate": len(successful_refreshes) / len(refresh_results),
            "avg_refresh_time": statistics.mean(refresh_durations),
            "p95_refresh_time": statistics.quantiles(refresh_durations, n=20)[18]
            if len(refresh_durations) > 20
            else max(refresh_durations),
            "throughput": len(refresh_results) / total_duration,
        }

        print(f"Success rate: {metrics['success_rate']:.2%}")
        print(f"Avg refresh time: {metrics['avg_refresh_time']:.3f}s")
        print(f"P95 refresh time: {metrics['p95_refresh_time']:.3f}s")
        print(f"Throughput: {metrics['throughput']:.1f} refreshes/sec")

        # Performance assertions
        assert metrics["success_rate"] >= 0.95  # 95% success rate
        assert metrics["avg_refresh_time"] <= 0.1  # Under 100ms average
        assert metrics["p95_refresh_time"] <= 0.2  # Under 200ms P95
        assert metrics["throughput"] >= 50  # At least 50 refreshes/sec

        return metrics

    @pytest.mark.asyncio
    async def test_bulk_session_revocation_performance(
        self, app_container, active_sessions
    ):
        """Test bulk session revocation performance."""
        revoke_handler = app_container.get("revoke_session_command_handler")
        revoke_all_handler = app_container.get("revoke_all_sessions_command_handler")

        # Test individual session revocation performance
        individual_revoke_sessions = active_sessions[:10]

        async def revoke_session(session_data):
            """Revoke an individual session."""
            start_time = time.time()

            command = RevokeSessionCommand(
                session_id=session_data["session_id"], revoked_by="performance_test"
            )

            try:
                result = await revoke_handler.handle(command)
                end_time = time.time()

                return {"duration": end_time - start_time, "success": result.success}
            except Exception as e:
                end_time = time.time()
                return {
                    "duration": end_time - start_time,
                    "success": False,
                    "error": str(e),
                }

        print("Testing individual session revocation...")

        start_time = time.time()

        tasks = [revoke_session(session) for session in individual_revoke_sessions]
        individual_results = await asyncio.gather(*tasks)

        end_time = time.time()
        individual_duration = end_time - start_time

        individual_metrics = {
            "duration": individual_duration,
            "revocations": len(individual_results),
            "successful": len([r for r in individual_results if r["success"]]),
            "avg_revoke_time": statistics.mean(
                [r["duration"] for r in individual_results]
            ),
            "throughput": len(individual_results) / individual_duration,
        }

        print(
            f"Individual revocation throughput: {individual_metrics['throughput']:.1f} revocations/sec"
        )

        # Test bulk revocation for remaining users
        bulk_users = list({s["user_id"] for s in active_sessions[10:]})

        print(f"Testing bulk revocation for {len(bulk_users)} users...")

        async def revoke_all_user_sessions(user_id):
            """Revoke all sessions for a user."""
            start_time = time.time()

            command = RevokeAllSessionsCommand(
                user_id=user_id, revoked_by="performance_test"
            )

            try:
                result = await revoke_all_handler.handle(command)
                end_time = time.time()

                return {
                    "duration": end_time - start_time,
                    "success": result.success,
                    "sessions_revoked": result.sessions_revoked,
                }
            except Exception as e:
                end_time = time.time()
                return {
                    "duration": end_time - start_time,
                    "success": False,
                    "error": str(e),
                }

        start_time = time.time()

        bulk_tasks = [revoke_all_user_sessions(user_id) for user_id in bulk_users]
        bulk_results = await asyncio.gather(*bulk_tasks)

        end_time = time.time()
        bulk_duration = end_time - start_time

        bulk_metrics = {
            "duration": bulk_duration,
            "users": len(bulk_users),
            "successful": len([r for r in bulk_results if r["success"]]),
            "total_sessions_revoked": sum(
                [r.get("sessions_revoked", 0) for r in bulk_results if r["success"]]
            ),
            "avg_bulk_revoke_time": statistics.mean(
                [r["duration"] for r in bulk_results]
            ),
            "user_throughput": len(bulk_users) / bulk_duration,
        }

        print(
            f"Bulk revocation user throughput: {bulk_metrics['user_throughput']:.1f} users/sec"
        )
        print(f"Total sessions revoked: {bulk_metrics['total_sessions_revoked']}")

        # Performance assertions
        assert (
            individual_metrics["throughput"] >= 20
        )  # At least 20 individual revocations/sec
        assert (
            bulk_metrics["user_throughput"] >= 10
        )  # At least 10 users/sec for bulk revocation
        assert (
            individual_metrics["avg_revoke_time"] <= 0.1
        )  # Under 100ms per revocation
        assert (
            bulk_metrics["avg_bulk_revoke_time"] <= 0.2
        )  # Under 200ms per bulk revocation

        return {"individual": individual_metrics, "bulk": bulk_metrics}


@pytest.mark.performance
class TestSessionQueryPerformance:
    """Test session query performance."""

    @pytest.fixture
    async def session_data_set(self, app_container, test_users):
        """Create a large dataset of sessions for query testing."""
        login_handler = app_container.get("login_command_handler")
        session_service = app_container.get("session_service")

        # Create multiple sessions per user with different characteristics
        all_sessions = []

        for user in test_users:
            # Create 3-5 sessions per user with different IPs and user agents
            session_count = 3 + (hash(user["id"]) % 3)  # 3-5 sessions

            for i in range(session_count):
                login_command = LoginCommand(
                    email=user["email"],
                    password=user["password"],
                    ip_address=f"192.168.{i+1}.{hash(user['id']) % 255}",
                    user_agent=f"Mozilla/5.0 (Device {i})",
                )

                login_result = await login_handler.handle(login_command)

                if login_result.success:
                    session_id = login_result.session_id

                    # Vary session ages
                    age_hours = i * 2  # 0, 2, 4, 6, 8 hours old
                    created_at = datetime.now(UTC) - timedelta(hours=age_hours)
                    await session_service.update_session_timestamp(
                        session_id, created_at
                    )

                    all_sessions.append(
                        {
                            "session_id": session_id,
                            "user_id": user["id"],
                            "created_at": created_at,
                            "ip_index": i,
                        }
                    )

        return all_sessions

    @pytest.mark.asyncio
    async def test_get_active_sessions_performance(
        self, app_container, session_data_set
    ):
        """Test performance of getting active sessions."""
        get_sessions_handler = app_container.get("get_active_sessions_query_handler")

        # Get unique user IDs
        user_ids = list({s["user_id"] for s in session_data_set})

        async def get_user_sessions(user_id):
            """Get active sessions for a user."""
            start_time = time.time()

            query = GetActiveSessionsQuery(user_id=user_id, page=1, page_size=10)

            try:
                result = await get_sessions_handler.handle(query)
                end_time = time.time()

                return {
                    "duration": end_time - start_time,
                    "success": True,
                    "session_count": len(result.sessions),
                    "total_count": result.total_count,
                }
            except Exception as e:
                end_time = time.time()
                return {
                    "duration": end_time - start_time,
                    "success": False,
                    "error": str(e),
                }

        # Test concurrent queries for all users
        print(f"Testing concurrent session queries for {len(user_ids)} users...")

        start_time = time.time()

        tasks = [get_user_sessions(user_id) for user_id in user_ids]
        query_results = await asyncio.gather(*tasks)

        end_time = time.time()
        total_duration = end_time - start_time

        # Calculate metrics
        successful_queries = [r for r in query_results if r["success"]]
        query_durations = [r["duration"] for r in query_results]

        metrics = {
            "total_duration": total_duration,
            "total_queries": len(query_results),
            "successful_queries": len(successful_queries),
            "success_rate": len(successful_queries) / len(query_results),
            "avg_query_time": statistics.mean(query_durations),
            "p95_query_time": statistics.quantiles(query_durations, n=20)[18]
            if len(query_durations) > 20
            else max(query_durations),
            "throughput": len(query_results) / total_duration,
            "total_sessions_returned": sum(
                [r.get("session_count", 0) for r in successful_queries]
            ),
        }

        print(f"Success rate: {metrics['success_rate']:.2%}")
        print(f"Avg query time: {metrics['avg_query_time']:.3f}s")
        print(f"P95 query time: {metrics['p95_query_time']:.3f}s")
        print(f"Throughput: {metrics['throughput']:.1f} queries/sec")
        print(f"Total sessions returned: {metrics['total_sessions_returned']}")

        # Performance assertions
        assert metrics["success_rate"] >= 0.98  # 98% success rate
        assert metrics["avg_query_time"] <= 0.05  # Under 50ms average
        assert metrics["p95_query_time"] <= 0.1  # Under 100ms P95
        assert metrics["throughput"] >= 100  # At least 100 queries/sec

        return metrics

    @pytest.mark.asyncio
    async def test_session_details_query_performance(
        self, app_container, session_data_set
    ):
        """Test performance of getting detailed session information."""
        get_details_handler = app_container.get("get_session_details_query_handler")

        # Select a subset of sessions for detailed queries
        test_sessions = session_data_set[:50]  # Test with 50 sessions

        async def get_session_details(session_data):
            """Get detailed session information."""
            start_time = time.time()

            query = GetSessionDetailsQuery(
                session_id=session_data["session_id"],
                include_security_info=True,
                include_device_info=True,
            )

            try:
                result = await get_details_handler.handle(query)
                end_time = time.time()

                return {
                    "duration": end_time - start_time,
                    "success": True,
                    "has_security_info": hasattr(result, "security_info"),
                    "has_device_info": hasattr(result, "device_info"),
                }
            except Exception as e:
                end_time = time.time()
                return {
                    "duration": end_time - start_time,
                    "success": False,
                    "error": str(e),
                }

        print(f"Testing detailed session queries for {len(test_sessions)} sessions...")

        start_time = time.time()

        tasks = [get_session_details(session) for session in test_sessions]
        detail_results = await asyncio.gather(*tasks)

        end_time = time.time()
        total_duration = end_time - start_time

        # Calculate metrics
        successful_queries = [r for r in detail_results if r["success"]]
        query_durations = [r["duration"] for r in detail_results]

        metrics = {
            "total_duration": total_duration,
            "total_queries": len(detail_results),
            "successful_queries": len(successful_queries),
            "success_rate": len(successful_queries) / len(detail_results),
            "avg_query_time": statistics.mean(query_durations),
            "max_query_time": max(query_durations),
            "throughput": len(detail_results) / total_duration,
        }

        print(f"Success rate: {metrics['success_rate']:.2%}")
        print(f"Avg query time: {metrics['avg_query_time']:.3f}s")
        print(f"Max query time: {metrics['max_query_time']:.3f}s")
        print(f"Throughput: {metrics['throughput']:.1f} queries/sec")

        # Performance assertions
        assert metrics["success_rate"] >= 0.95  # 95% success rate
        assert metrics["avg_query_time"] <= 0.1  # Under 100ms average
        assert metrics["max_query_time"] <= 0.5  # Under 500ms maximum
        assert metrics["throughput"] >= 50  # At least 50 detailed queries/sec

        return metrics
