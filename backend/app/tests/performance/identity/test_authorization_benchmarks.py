"""
Performance benchmarks for authorization operations.

Tests permission checking, role resolution, and access control
performance under various load conditions.
"""

import asyncio
import random
import statistics
import time

import pytest

from app.modules.identity.application.commands.authorization import (
    CheckPermissionCommand,
)
from app.modules.identity.application.queries.authorization import (
    GetRolePermissionsQuery,
    GetUserAccessQuery,
)
from app.modules.identity.domain.enums import PermissionScope


@pytest.mark.performance
class TestPermissionCheckingPerformance:
    """Test permission checking performance."""

    @pytest.fixture
    async def complex_authorization_setup(self, app_container, faker):
        """Create a complex authorization setup with many users, roles, and permissions."""
        user_service = app_container.get("user_service")
        role_service = app_container.get("role_service")
        permission_service = app_container.get("permission_service")

        # Create permissions
        permissions = []
        resources = [
            "user",
            "project",
            "report",
            "admin",
            "finance",
            "hr",
            "sales",
            "marketing",
        ]
        actions = ["read", "write", "delete", "admin", "approve", "export"]
        scopes = [
            PermissionScope.USER,
            PermissionScope.DEPARTMENT,
            PermissionScope.ORGANIZATION,
            PermissionScope.GLOBAL,
        ]

        for resource in resources:
            for action in actions:
                for scope in scopes:
                    permission = await permission_service.create_permission(
                        name=f"{resource}:{action}",
                        resource=resource,
                        action=action,
                        scope=scope,
                        description=f"{action.title()} access to {resource}",
                        created_by="system",
                    )
                    permissions.append(permission)

        print(f"Created {len(permissions)} permissions")

        # Create roles with different permission sets
        roles = []
        role_configs = [
            {"name": "Admin", "permission_count": 150},
            {"name": "Manager", "permission_count": 75},
            {"name": "Senior", "permission_count": 40},
            {"name": "Regular", "permission_count": 20},
            {"name": "Intern", "permission_count": 10},
        ]

        for config in role_configs:
            # Select random permissions for this role
            role_permissions = random.sample(
                permissions, min(config["permission_count"], len(permissions))
            )

            role = await role_service.create_role(
                name=config["name"],
                description=f"{config['name']} role with {config['permission_count']} permissions",
                permissions=[p.id for p in role_permissions],
                created_by="system",
            )
            roles.append({"role": role, "permissions": role_permissions})

        print(f"Created {len(roles)} roles")

        # Create users and assign roles
        users = []
        for i in range(500):  # Create 500 users
            email = f"perftest{i}@example.com"
            user = await user_service.create_user(
                email=email,
                username=f"perfuser{i}",
                password="TestPassword123!@#",
                first_name=f"User{i}",
                last_name="Test",
            )

            # Assign 1-3 random roles to each user
            user_roles = random.sample(roles, random.randint(1, 3))  # noqa: S311 - Random selection for test data is not security-sensitive
            for role_data in user_roles:
                await role_service.assign_role_to_user(
                    user_id=user.id, role_id=role_data["role"].id, assigned_by="system"
                )

            users.append(
                {
                    "user": user,
                    "roles": [r["role"] for r in user_roles],
                    "expected_permissions": set(),
                }
            )

            # Calculate expected permissions for verification
            for role_data in user_roles:
                for perm in role_data["permissions"]:
                    users[-1]["expected_permissions"].add(perm.id)

        print(f"Created {len(users)} users with role assignments")

        return {"users": users, "roles": roles, "permissions": permissions}

    @pytest.mark.asyncio
    async def test_bulk_permission_checking_performance(
        self, app_container, complex_authorization_setup
    ):
        """Test bulk permission checking performance."""
        check_permission_handler = app_container.get("check_permission_command_handler")

        users = complex_authorization_setup["users"][:100]  # Use 100 users
        permissions = complex_authorization_setup["permissions"]

        # Create test cases: user + permission combinations
        test_cases = []
        for user_data in users:
            # Test 10 random permissions per user
            test_permissions = random.sample(permissions, 10)
            for permission in test_permissions:
                test_cases.append(
                    {
                        "user_id": user_data["user"].id,
                        "permission": permission,
                        "expected": permission.id in user_data["expected_permissions"],
                    }
                )

        print(f"Testing {len(test_cases)} permission checks...")

        async def check_permission(test_case):
            """Check a single permission."""
            start_time = time.time()

            command = CheckPermissionCommand(
                user_id=test_case["user_id"],
                resource=test_case["permission"].resource,
                action=test_case["permission"].action,
                context={"scope": test_case["permission"].scope.value},
            )

            try:
                result = await check_permission_handler.handle(command)
                end_time = time.time()

                return {
                    "duration": end_time - start_time,
                    "allowed": result.allowed,
                    "expected": test_case["expected"],
                    "correct": result.allowed == test_case["expected"],
                }
            except Exception as e:
                end_time = time.time()
                return {
                    "duration": end_time - start_time,
                    "allowed": False,
                    "expected": test_case["expected"],
                    "correct": False,
                    "error": str(e),
                }

        # Test with different batch sizes
        batch_sizes = [10, 50, 100, 500, len(test_cases)]
        results = {}

        for batch_size in batch_sizes:
            if batch_size > len(test_cases):
                continue

            print(f"\nTesting batch size: {batch_size}")

            batch = test_cases[:batch_size]

            start_time = time.time()

            tasks = [check_permission(test_case) for test_case in batch]
            batch_results = await asyncio.gather(*tasks)

            end_time = time.time()
            total_duration = end_time - start_time

            # Calculate metrics
            check_durations = [r["duration"] for r in batch_results]
            correct_results = [r for r in batch_results if r["correct"]]

            results[batch_size] = {
                "total_duration": total_duration,
                "checks": len(batch_results),
                "correct_checks": len(correct_results),
                "accuracy": len(correct_results) / len(batch_results),
                "avg_check_time": statistics.mean(check_durations),
                "p95_check_time": statistics.quantiles(check_durations, n=20)[18]
                if len(check_durations) > 20
                else max(check_durations),
                "throughput": len(batch_results) / total_duration,
            }

            print(f"  Accuracy: {results[batch_size]['accuracy']:.2%}")
            print(f"  Avg check time: {results[batch_size]['avg_check_time']:.4f}s")
            print(f"  P95 check time: {results[batch_size]['p95_check_time']:.4f}s")
            print(f"  Throughput: {results[batch_size]['throughput']:.1f} checks/sec")

        # Performance assertions
        assert results[10]["accuracy"] >= 0.95  # 95% accuracy
        assert results[10]["avg_check_time"] <= 0.01  # Under 10ms average
        assert (
            results[100]["throughput"] >= 500
        )  # At least 500 checks/sec for 100 batch
        assert (
            results[500]["throughput"] >= 200
        )  # At least 200 checks/sec for 500 batch

        return results

    @pytest.mark.asyncio
    async def test_permission_caching_performance(
        self, app_container, complex_authorization_setup
    ):
        """Test permission checking performance with caching."""
        check_permission_handler = app_container.get("check_permission_command_handler")
        app_container.get("cache_service")

        users = complex_authorization_setup["users"][:50]
        permissions = complex_authorization_setup["permissions"][:50]

        # Create test cases
        test_cases = []
        for user_data in users:
            for permission in permissions[:5]:  # 5 permissions per user
                test_cases.append(
                    {
                        "user_id": user_data["user"].id,
                        "resource": permission.resource,
                        "action": permission.action,
                    }
                )

        async def check_permission_with_timing(test_case):
            """Check permission and measure time."""
            start_time = time.time()

            command = CheckPermissionCommand(
                user_id=test_case["user_id"],
                resource=test_case["resource"],
                action=test_case["action"],
            )

            result = await check_permission_handler.handle(command)
            end_time = time.time()

            return {
                "duration": end_time - start_time,
                "allowed": result.allowed,
                "from_cache": getattr(result, "from_cache", False),
            }

        # First run: populate cache
        print("First run: populating cache...")

        start_time = time.time()

        tasks = [check_permission_with_timing(test_case) for test_case in test_cases]
        first_results = await asyncio.gather(*tasks)

        end_time = time.time()
        first_duration = end_time - start_time

        first_metrics = {
            "duration": first_duration,
            "checks": len(first_results),
            "avg_time": statistics.mean([r["duration"] for r in first_results]),
            "throughput": len(first_results) / first_duration,
            "cached_results": len(
                [r for r in first_results if r.get("from_cache", False)]
            ),
        }

        print(f"  Avg time: {first_metrics['avg_time']:.4f}s")
        print(f"  Throughput: {first_metrics['throughput']:.1f} checks/sec")
        print(f"  Cached results: {first_metrics['cached_results']}")

        # Second run: should hit cache
        print("\nSecond run: using cache...")

        # Wait a moment to ensure cache is populated
        await asyncio.sleep(0.1)

        start_time = time.time()

        tasks = [check_permission_with_timing(test_case) for test_case in test_cases]
        second_results = await asyncio.gather(*tasks)

        end_time = time.time()
        second_duration = end_time - start_time

        second_metrics = {
            "duration": second_duration,
            "checks": len(second_results),
            "avg_time": statistics.mean([r["duration"] for r in second_results]),
            "throughput": len(second_results) / second_duration,
            "cached_results": len(
                [r for r in second_results if r.get("from_cache", False)]
            ),
        }

        print(f"  Avg time: {second_metrics['avg_time']:.4f}s")
        print(f"  Throughput: {second_metrics['throughput']:.1f} checks/sec")
        print(f"  Cached results: {second_metrics['cached_results']}")

        # Calculate improvement
        improvement_factor = first_metrics["avg_time"] / second_metrics["avg_time"]
        throughput_improvement = (
            second_metrics["throughput"] / first_metrics["throughput"]
        )

        print("\nCache performance improvement:")
        print(f"  Speed improvement: {improvement_factor:.1f}x")
        print(f"  Throughput improvement: {throughput_improvement:.1f}x")

        # Performance assertions
        assert improvement_factor >= 2.0  # At least 2x improvement with caching
        assert (
            second_metrics["throughput"] >= 1000
        )  # At least 1000 checks/sec with cache
        assert (
            second_metrics["cached_results"] >= len(test_cases) * 0.8
        )  # At least 80% cache hits

        return {
            "first_run": first_metrics,
            "second_run": second_metrics,
            "improvement_factor": improvement_factor,
            "throughput_improvement": throughput_improvement,
        }


@pytest.mark.performance
class TestRoleResolutionPerformance:
    """Test role resolution and hierarchy performance."""

    @pytest.fixture
    async def hierarchical_role_setup(self, app_container):
        """Create a hierarchical role setup for testing."""
        role_service = app_container.get("role_service")
        permission_service = app_container.get("permission_service")
        user_service = app_container.get("user_service")

        # Create permissions
        permissions = []
        for i in range(100):
            permission = await permission_service.create_permission(
                name=f"permission_{i}",
                resource=f"resource_{i % 10}",
                action=f"action_{i % 5}",
                scope=PermissionScope.ORGANIZATION,
                created_by="system",
            )
            permissions.append(permission)

        # Create hierarchical roles
        # Level 1: CEO (top level)
        ceo_role = await role_service.create_role(
            name="CEO",
            description="Chief Executive Officer",
            permissions=[p.id for p in permissions],  # All permissions
            created_by="system",
        )

        # Level 2: Department Heads
        dept_heads = []
        for dept in ["Engineering", "Sales", "Marketing", "HR", "Finance"]:
            # Each department head gets 80% of permissions
            dept_permissions = random.sample(permissions, int(len(permissions) * 0.8))
            dept_role = await role_service.create_role(
                name=f"{dept}_Head",
                description=f"Head of {dept}",
                permissions=[p.id for p in dept_permissions],
                parent_role_id=ceo_role.id,
                created_by="system",
            )
            dept_heads.append(dept_role)

        # Level 3: Team Leads
        team_leads = []
        for dept_role in dept_heads:
            for team in ["Team_A", "Team_B"]:
                # Each team lead gets 60% of department permissions
                dept_permissions = await role_service.get_role_permissions(dept_role.id)
                team_permissions = random.sample(
                    dept_permissions, int(len(dept_permissions) * 0.6)
                )
                team_role = await role_service.create_role(
                    name=f"{dept_role.name}_{team}_Lead",
                    description=f"Lead of {team} in {dept_role.name}",
                    permissions=[p.id for p in team_permissions],
                    parent_role_id=dept_role.id,
                    created_by="system",
                )
                team_leads.append(team_role)

        # Level 4: Regular employees
        employees = []
        for lead_role in team_leads:
            for i in range(5):  # 5 employees per team
                # Each employee gets 40% of team permissions
                lead_permissions = await role_service.get_role_permissions(lead_role.id)
                emp_permissions = random.sample(
                    lead_permissions, int(len(lead_permissions) * 0.4)
                )
                emp_role = await role_service.create_role(
                    name=f"{lead_role.name}_Employee_{i}",
                    description=f"Employee {i} in {lead_role.name}",
                    permissions=[p.id for p in emp_permissions],
                    parent_role_id=lead_role.id,
                    created_by="system",
                )
                employees.append(emp_role)

        # Create users and assign roles
        all_roles = [ceo_role, *dept_heads, *team_leads, *employees]
        users = []

        for i, role in enumerate(all_roles):
            user = await user_service.create_user(
                email=f"hierarchy_user_{i}@example.com",
                username=f"huser_{i}",
                password="TestPassword123!@#",
            )

            await role_service.assign_role_to_user(
                user_id=user.id, role_id=role.id, assigned_by="system"
            )

            users.append(
                {
                    "user": user,
                    "role": role,
                    "level": 4
                    if role in employees
                    else 3
                    if role in team_leads
                    else 2
                    if role in dept_heads
                    else 1,
                }
            )

        return {
            "users": users,
            "roles": {
                "ceo": ceo_role,
                "dept_heads": dept_heads,
                "team_leads": team_leads,
                "employees": employees,
            },
            "permissions": permissions,
        }

    @pytest.mark.asyncio
    async def test_hierarchical_access_resolution_performance(
        self, app_container, hierarchical_role_setup
    ):
        """Test performance of resolving access through role hierarchy."""
        get_user_access_handler = app_container.get("get_user_access_query_handler")

        users = hierarchical_role_setup["users"]

        async def get_user_access_with_timing(user_data):
            """Get user access and measure time."""
            start_time = time.time()

            query = GetUserAccessQuery(
                user_id=user_data["user"].id,
                include_inherited=True,
                include_role_hierarchy=True,
            )

            try:
                result = await get_user_access_handler.handle(query)
                end_time = time.time()

                return {
                    "duration": end_time - start_time,
                    "user_level": user_data["level"],
                    "roles_count": len(result.roles),
                    "permissions_count": len(result.permissions),
                    "inherited_permissions": getattr(
                        result, "inherited_permissions_count", 0
                    ),
                }
            except Exception as e:
                end_time = time.time()
                return {
                    "duration": end_time - start_time,
                    "user_level": user_data["level"],
                    "error": str(e),
                }

        print(f"Testing hierarchical access resolution for {len(users)} users...")

        start_time = time.time()

        tasks = [get_user_access_with_timing(user_data) for user_data in users]
        access_results = await asyncio.gather(*tasks)

        end_time = time.time()
        total_duration = end_time - start_time

        # Group results by hierarchy level
        results_by_level = {}
        for result in access_results:
            if "error" not in result:
                level = result["user_level"]
                if level not in results_by_level:
                    results_by_level[level] = []
                results_by_level[level].append(result)

        # Calculate metrics for each level
        level_metrics = {}
        for level, level_results in results_by_level.items():
            durations = [r["duration"] for r in level_results]
            permissions_counts = [r["permissions_count"] for r in level_results]

            level_metrics[level] = {
                "users": len(level_results),
                "avg_duration": statistics.mean(durations),
                "max_duration": max(durations),
                "avg_permissions": statistics.mean(permissions_counts),
                "max_permissions": max(permissions_counts),
            }

            level_name = ["", "CEO", "Dept Head", "Team Lead", "Employee"][level]
            print(f"\nLevel {level} ({level_name}):")
            print(f"  Users: {level_metrics[level]['users']}")
            print(f"  Avg duration: {level_metrics[level]['avg_duration']:.4f}s")
            print(f"  Max duration: {level_metrics[level]['max_duration']:.4f}s")
            print(f"  Avg permissions: {level_metrics[level]['avg_permissions']:.0f}")
            print(f"  Max permissions: {level_metrics[level]['max_permissions']:.0f}")

        overall_metrics = {
            "total_duration": total_duration,
            "total_users": len(access_results),
            "successful_resolutions": len(
                [r for r in access_results if "error" not in r]
            ),
            "avg_resolution_time": statistics.mean(
                [r["duration"] for r in access_results if "error" not in r]
            ),
            "throughput": len(access_results) / total_duration,
        }

        print("\nOverall metrics:")
        print(f"  Total duration: {overall_metrics['total_duration']:.3f}s")
        print(
            f"  Success rate: {overall_metrics['successful_resolutions'] / overall_metrics['total_users']:.2%}"
        )
        print(f"  Avg resolution time: {overall_metrics['avg_resolution_time']:.4f}s")
        print(f"  Throughput: {overall_metrics['throughput']:.1f} resolutions/sec")

        # Performance assertions
        assert overall_metrics["avg_resolution_time"] <= 0.1  # Under 100ms average
        assert (
            level_metrics[4]["avg_duration"] <= 0.05
        )  # Employees (deepest level) under 50ms
        assert (
            level_metrics[1]["avg_duration"] <= 0.15
        )  # CEO (most permissions) under 150ms
        assert overall_metrics["throughput"] >= 50  # At least 50 resolutions/sec

        return {"overall": overall_metrics, "by_level": level_metrics}

    @pytest.mark.asyncio
    async def test_role_permission_inheritance_performance(
        self, app_container, hierarchical_role_setup
    ):
        """Test performance of role permission inheritance calculations."""
        get_role_permissions_handler = app_container.get(
            "get_role_permissions_query_handler"
        )

        all_roles = (
            [hierarchical_role_setup["roles"]["ceo"]]
            + hierarchical_role_setup["roles"]["dept_heads"]
            + hierarchical_role_setup["roles"]["team_leads"]
            + hierarchical_role_setup["roles"]["employees"]
        )

        async def get_role_permissions_with_timing(role):
            """Get role permissions with timing."""
            start_time = time.time()

            query = GetRolePermissionsQuery(role_id=role.id, include_inherited=True)

            try:
                result = await get_role_permissions_handler.handle(query)
                end_time = time.time()

                return {
                    "duration": end_time - start_time,
                    "role_id": role.id,
                    "role_name": role.name,
                    "direct_permissions": len(
                        [
                            p
                            for p in result.permissions
                            if not getattr(p, "inherited", False)
                        ]
                    ),
                    "inherited_permissions": len(
                        [
                            p
                            for p in result.permissions
                            if getattr(p, "inherited", False)
                        ]
                    ),
                    "total_permissions": len(result.permissions),
                }
            except Exception as e:
                end_time = time.time()
                return {
                    "duration": end_time - start_time,
                    "role_id": role.id,
                    "error": str(e),
                }

        print(f"Testing role permission inheritance for {len(all_roles)} roles...")

        # Test in batches to avoid overwhelming the system
        batch_size = 20
        all_results = []

        for i in range(0, len(all_roles), batch_size):
            batch = all_roles[i : i + batch_size]

            start_time = time.time()

            tasks = [get_role_permissions_with_timing(role) for role in batch]
            batch_results = await asyncio.gather(*tasks)

            end_time = time.time()
            batch_duration = end_time - start_time

            all_results.extend(batch_results)

            print(
                f"  Batch {i//batch_size + 1}: {len(batch)} roles in {batch_duration:.3f}s"
            )

        # Analyze results
        successful_results = [r for r in all_results if "error" not in r]
        durations = [r["duration"] for r in successful_results]

        # Group by permission count ranges
        permission_ranges = {
            "0-10": [],
            "11-25": [],
            "26-50": [],
            "51-100": [],
            "100+": [],
        }

        for result in successful_results:
            count = result["total_permissions"]
            if count <= 10:
                permission_ranges["0-10"].append(result)
            elif count <= 25:
                permission_ranges["11-25"].append(result)
            elif count <= 50:
                permission_ranges["26-50"].append(result)
            elif count <= 100:
                permission_ranges["51-100"].append(result)
            else:
                permission_ranges["100+"].append(result)

        print("\nResults by permission count:")
        for range_name, range_results in permission_ranges.items():
            if range_results:
                range_durations = [r["duration"] for r in range_results]
                print(
                    f"  {range_name} permissions: {len(range_results)} roles, avg time: {statistics.mean(range_durations):.4f}s"
                )

        overall_metrics = {
            "total_roles": len(all_results),
            "successful_roles": len(successful_results),
            "avg_resolution_time": statistics.mean(durations),
            "max_resolution_time": max(durations),
            "p95_resolution_time": statistics.quantiles(durations, n=20)[18]
            if len(durations) > 20
            else max(durations),
        }

        print("\nOverall inheritance resolution metrics:")
        print(
            f"  Success rate: {overall_metrics['successful_roles'] / overall_metrics['total_roles']:.2%}"
        )
        print(f"  Avg resolution time: {overall_metrics['avg_resolution_time']:.4f}s")
        print(f"  Max resolution time: {overall_metrics['max_resolution_time']:.4f}s")
        print(f"  P95 resolution time: {overall_metrics['p95_resolution_time']:.4f}s")

        # Performance assertions
        assert overall_metrics["avg_resolution_time"] <= 0.05  # Under 50ms average
        assert overall_metrics["max_resolution_time"] <= 0.2  # Under 200ms maximum
        assert overall_metrics["p95_resolution_time"] <= 0.1  # Under 100ms P95

        return {"overall": overall_metrics, "by_permission_range": permission_ranges}
