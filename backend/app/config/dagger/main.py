#!/usr/bin/env python3
"""
EzzDay Backend - Enhanced Dagger CI/CD Pipeline
Comprehensive CI/CD automation using Dagger Python SDK with container-native approach
"""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

import dagger
from dagger import Container, Directory


class EzzDayPipeline:
    """Enhanced pipeline orchestrator for EzzDay backend CI/CD"""

    def __init__(self, client: dagger.Client):
        self.client = client
        self.python_version = "3.12"
        self.postgres_version = "15"
        self.redis_version = "7"
        self.base_image = f"python:{self.python_version}-slim"

    async def setup_base_container(self, source: Directory) -> Container:
        """Setup base container with dependencies"""
        return (
            self.client.container()
            .from_(self.base_image)
            .with_directory("/app", source)
            .with_workdir("/app")
            .with_exec(["apt-get", "update"])
            .with_exec(["apt-get", "install", "-y", "libpq-dev", "gcc", "curl"])
            .with_exec(["pip", "install", "uv"])
            .with_exec(
                [
                    "uv",
                    "pip",
                    "install",
                    "--system",
                    "-r",
                    "app/config/requirements/dev.txt",
                ]
            )
        )

    async def lint_and_format(self, source: Directory) -> dict[str, bool]:
        """Run comprehensive linting and formatting checks"""
        print("🔍 Running lint and format checks...")

        container = await self.setup_base_container(source)

        # Define lint tools with their commands
        lint_tools = {
            "black": ["black", "--check", "--diff", "app/"],
            "isort": ["isort", "--check-only", "--diff", "app/"],
            "flake8": [
                "flake8",
                "app/",
                "--max-line-length=100",
                "--exclude=migrations",
            ],
            "mypy": ["mypy", "app/", "--ignore-missing-imports"],
            "bandit": [
                "bandit",
                "-r",
                "app/",
                "-x",
                "app/tests/",
                "-f",
                "json",
                "-o",
                "/tmp/bandit.json",  # noqa: S108 - Container temp file, not host system
            ],
            "pylint": [
                "pylint",
                "app/",
                "--disable=all",
                "--enable=E,W,F",
                "--output-format=json",
            ],
            "safety": ["safety", "check", "--json", "--ignore=70612"],
        }

        results = {}

        for tool, cmd in lint_tools.items():
            try:
                exit_code = await container.with_exec(cmd).exit_code()
                results[tool] = exit_code == 0

                if exit_code == 0:
                    print(f"✅ {tool.title()} passed")
                else:
                    print(f"❌ {tool.title()} failed")

            except Exception as e:
                print(f"⚠️  {tool.title()} encountered an error: {e}")
                results[tool] = False

        # Generate lint report
        await self.generate_lint_report(container, results)

        return results

    async def generate_lint_report(
        self, container: Container, results: dict[str, bool]
    ):
        """Generate comprehensive lint report"""
        report = {
            "summary": {
                "total_checks": len(results),
                "passed": sum(1 for passed in results.values() if passed),
                "failed": sum(1 for passed in results.values() if not passed),
            },
            "details": results,
            "recommendations": [],
        }

        # Add recommendations based on failures
        for tool, passed in results.items():
            if not passed:
                recommendations = {
                    "black": "Run 'black app/' to auto-format code",
                    "isort": "Run 'isort app/' to sort imports",
                    "flake8": "Fix PEP8 violations reported by flake8",
                    "mypy": "Add type hints and fix type errors",
                    "bandit": "Review and fix security issues",
                    "pylint": "Address code quality issues",
                    "safety": "Update vulnerable packages",
                }
                if tool in recommendations:
                    report["recommendations"].append(recommendations[tool])

        # Save report
        report_json = json.dumps(report, indent=2)
        await container.with_new_file("/tmp/lint-report.json", report_json).file(  # noqa: S108 - Container temp file, not host system
            "/tmp/lint-report.json"  # noqa: S108 - Container temp file, not host system
        ).export("./reports/lint-report.json")

    async def run_unit_tests(self, source: Directory) -> dict[str, Any]:
        """Run comprehensive unit tests with coverage"""
        print("🧪 Running unit tests...")

        # Setup test database and Redis
        postgres_service = (
            self.client.container()
            .from_(f"postgres:{self.postgres_version}-alpine")
            .with_env_variable("POSTGRES_DB", "ezzday_test")
            .with_env_variable("POSTGRES_USER", "ezzday_test")
            .with_env_variable("POSTGRES_PASSWORD", "test_password")
            .with_exposed_port(5432)
            .as_service()
        )

        redis_service = (
            self.client.container()
            .from_(f"redis:{self.redis_version}-alpine")
            .with_exposed_port(6379)
            .as_service()
        )

        # Setup test container
        test_container = (
            await self.setup_base_container(source)
            .with_service_binding("postgres", postgres_service)
            .with_service_binding("redis", redis_service)
            .with_env_variable(
                "DATABASE_URL",
                "postgresql://ezzday_test:test_password@postgres:5432/ezzday_test",
            )
            .with_env_variable("REDIS_URL", "redis://redis:6379/0")
            .with_env_variable("ENVIRONMENT", "test")
            .with_env_variable("SECRET_KEY", "test-secret-key-not-for-production")
            .with_exec(
                [
                    "uv",
                    "pip",
                    "install",
                    "--system",
                    "-r",
                    "app/config/requirements/test.txt",
                ]
            )
        )

        # Wait for services
        await asyncio.sleep(10)

        # Run different test suites
        test_suites = {
            "unit": {
                "cmd": [
                    "pytest",
                    "app/tests/unit/",
                    "--cov=app",
                    "--cov-report=xml",
                    "--cov-report=term-missing",
                    "--cov-fail-under=80",
                    "-v",
                    "--tb=short",
                    "--junitxml=/tmp/unit-results.xml",
                ],
                "timeout": 300,
            },
            "integration": {
                "cmd": [
                    "pytest",
                    "app/tests/integration/",
                    "--cov=app",
                    "--cov-append",
                    "--cov-report=xml",
                    "-v",
                    "--tb=short",
                    "--maxfail=5",
                    "--junitxml=/tmp/integration-results.xml",
                ],
                "timeout": 600,
            },
            "e2e": {
                "cmd": [
                    "pytest",
                    "app/tests/e2e/",
                    "-v",
                    "--tb=short",
                    "--maxfail=3",
                    "--junitxml=/tmp/e2e-results.xml",
                ],
                "timeout": 900,
            },
        }

        results = {}

        for suite_name, suite_config in test_suites.items():
            try:
                print(f"Running {suite_name} tests...")
                exit_code = await test_container.with_exec(
                    suite_config["cmd"]
                ).exit_code()
                results[suite_name] = {"passed": exit_code == 0, "exit_code": exit_code}

                if exit_code == 0:
                    print(f"✅ {suite_name.title()} tests passed")
                else:
                    print(f"❌ {suite_name.title()} tests failed")

            except Exception as e:
                print(f"⚠️  {suite_name.title()} tests encountered an error: {e}")
                results[suite_name] = {"passed": False, "error": str(e)}

        # Export test results and coverage
        await self.export_test_artifacts(test_container)

        return results

    async def export_test_artifacts(self, container: Container):
        """Export test artifacts for analysis"""
        artifacts = [
            "/tmp/unit-results.xml",  # noqa: S108 - Container temp file, not host system
            "/tmp/integration-results.xml",  # noqa: S108 - Container temp file, not host system
            "/tmp/e2e-results.xml",  # noqa: S108 - Container temp file, not host system
            "coverage.xml",
            "htmlcov/",
        ]

        for artifact in artifacts:
            try:
                if artifact.endswith("/"):
                    # Directory
                    await container.directory(artifact).export(f"./reports/{artifact}")
                else:
                    # File
                    await container.file(artifact).export(
                        f"./reports/{Path(artifact).name}"
                    )
            except Exception as e:
                print(f"Warning: Could not export {artifact}: {e}")

    async def security_scan(self, source: Directory) -> dict[str, Any]:
        """Run comprehensive security scans"""
        print("🔒 Running security scans...")

        container = await self.setup_base_container(source)

        security_tools = {
            "safety": {
                "cmd": ["safety", "check", "--json", "--output", "/tmp/safety.json"],  # noqa: S108 - Container temp file
                "critical": True,
            },
            "bandit": {
                "cmd": ["bandit", "-r", "app/", "-f", "json", "-o", "/tmp/bandit.json"],  # noqa: S108 - Container temp file
                "critical": True,
            },
            "semgrep": {
                "container": self.client.container().from_(
                    "returntocorp/semgrep:latest"
                ),
                "cmd": [
                    "semgrep",
                    "--config=auto",
                    "--json",
                    "--output=/tmp/semgrep.json",
                    "app/",
                ],
                "critical": False,
            },
        }

        results = {}

        for tool, config in security_tools.items():
            try:
                if "container" in config:
                    # Use specific container
                    scan_container = (
                        config["container"]
                        .with_directory("/app", source)
                        .with_workdir("/app")
                    )
                else:
                    scan_container = container

                exit_code = await scan_container.with_exec(config["cmd"]).exit_code()
                results[tool] = {
                    "passed": exit_code == 0,
                    "critical": config["critical"],
                    "exit_code": exit_code,
                }

                if exit_code == 0:
                    print(f"✅ {tool.title()} scan passed")
                else:
                    status = "❌" if config["critical"] else "⚠️"
                    print(f"{status} {tool.title()} scan found issues")

            except Exception as e:
                print(f"⚠️  {tool.title()} scan encountered an error: {e}")
                results[tool] = {
                    "passed": False,
                    "error": str(e),
                    "critical": config["critical"],
                }

        return results

    async def build_and_push_image(
        self,
        source: Directory,
        tag: str,
        registry: str = "ezzday",
        dockerfile: str = "Dockerfile",
        push: bool = True,
    ) -> dict[str, Any]:
        """Build and optionally push Docker image"""
        print(f"🐳 Building image: {registry}/backend:{tag}")

        # Build the image
        image = (
            self.client.container()
            .build(source, dockerfile=dockerfile)
            .with_label("version", tag)
            .with_label("commit", os.getenv("GITHUB_SHA", "unknown"))
            .with_label("build-date", os.getenv("BUILD_DATE", "unknown"))
            .with_label("environment", os.getenv("ENVIRONMENT", "development"))
        )

        # Test the built image
        health_check = await (
            image.with_env_variable("DATABASE_URL", "sqlite:///test.db")
            .with_env_variable("SECRET_KEY", "test-key")
            .with_env_variable("ENVIRONMENT", "test")
            .with_exec(
                ["python", "-c", "import app.main; print('✅ Image build successful')"]
            )
            .exit_code()
        )

        if health_check != 0:
            print("❌ Image health check failed")
            return {"success": False, "error": "Health check failed"}

        # Security scan of the image
        await self.scan_image_security(image)

        # Push to registry if credentials are available and push is enabled
        if push:
            registry_user = os.getenv("REGISTRY_USER")
            registry_password = os.getenv("REGISTRY_PASSWORD")

            if registry_user and registry_password:
                try:
                    registry_secret = self.client.set_secret(
                        "registry_password", registry_password
                    )

                    push_result = await image.with_registry_auth(
                        registry, registry_user, registry_secret
                    ).publish(f"{registry}/backend:{tag}")
                    print(f"✅ Image pushed successfully: {push_result}")
                    return {"success": True, "image_url": push_result}
                except Exception as e:
                    print(f"❌ Failed to push image: {e}")
                    return {"success": False, "error": f"Push failed: {e}"}
            else:
                print("⚠️  Registry credentials not available, skipping push")
                return {
                    "success": True,
                    "image_url": None,
                    "note": "Push skipped - no credentials",
                }

        return {"success": True, "image_url": None, "note": "Push disabled"}

    async def scan_image_security(self, image: Container):
        """Scan built image for security vulnerabilities"""
        print("🔍 Scanning image for security vulnerabilities...")

        # Use Trivy for image scanning
        trivy_container = (
            self.client.container()
            .from_("aquasec/trivy:latest")
            .with_mounted_file("/image.tar", image.as_tarball())
        )

        try:
            await trivy_container.with_exec(
                [
                    "trivy",
                    "image",
                    "--format",
                    "json",
                    "--output",
                    "/tmp/trivy-report.json",  # noqa: S108 - Container temp file, not host system
                    "--input",
                    "/image.tar",
                ]
            ).exit_code()

            print("✅ Image security scan completed")
        except Exception as e:
            print(f"⚠️  Image security scan failed: {e}")

    async def deploy_to_environment(self, tag: str, environment: str) -> dict[str, Any]:
        """Deploy to specified environment using Kubernetes"""
        print(f"🚀 Deploying to {environment}: tag {tag}")

        # Use kubectl for deployment
        kubectl_container = (
            self.client.container()
            .from_("bitnami/kubectl:latest")
            .with_env_variable("ENVIRONMENT", environment)
            .with_env_variable("IMAGE_TAG", tag)
        )

        # Add kubeconfig if available
        kubeconfig = os.getenv("KUBECONFIG_CONTENT")
        if kubeconfig:
            kubectl_container = kubectl_container.with_new_file(
                "/root/.kube/config", kubeconfig
            )

        deployment_steps = []

        if environment == "staging":
            deployment_steps = [
                [
                    "kubectl",
                    "apply",
                    "-f",
                    "app/config/deployment/k8/overlays/staging/",
                ],
                [
                    "kubectl",
                    "set",
                    "image",
                    "deployment/ezzday-backend",
                    f"ezzday-backend=ezzday/backend:{tag}",
                ],
                [
                    "kubectl",
                    "rollout",
                    "status",
                    "deployment/ezzday-backend",
                    "--timeout=300s",
                ],
            ]
        elif environment == "production":
            deployment_steps = [
                ["kubectl", "apply", "-f", "app/config/deployment/k8/overlays/prod/"],
                [
                    "kubectl",
                    "set",
                    "image",
                    "deployment/ezzday-backend",
                    f"ezzday-backend=ezzday/backend:{tag}",
                ],
                [
                    "kubectl",
                    "rollout",
                    "status",
                    "deployment/ezzday-backend",
                    "--timeout=600s",
                ],
                ["kubectl", "get", "pods", "-l", "app=ezzday-backend"],
            ]

        results = []
        for step in deployment_steps:
            try:
                exit_code = await kubectl_container.with_exec(step).exit_code()
                results.append({"cmd": " ".join(step), "success": exit_code == 0})

                if exit_code != 0:
                    print(f"❌ Deployment step failed: {' '.join(step)}")
                    return {"success": False, "failed_step": " ".join(step)}
                print(f"✅ Deployment step passed: {' '.join(step)}")

            except Exception as e:
                print(f"❌ Deployment step error: {e}")
                return {"success": False, "error": str(e)}

        print(f"✅ {environment.title()} deployment successful")
        return {"success": True, "steps": results}

    async def performance_tests(self, source: Directory) -> dict[str, Any]:
        """Run performance and load tests"""
        print("⚡ Running performance tests...")

        # Setup application container
        app_container = (
            await self.setup_base_container(source)
            .with_env_variable("ENVIRONMENT", "test")
            .with_env_variable("DATABASE_URL", "sqlite:///test.db")
            .with_env_variable("SECRET_KEY", "test-key")
            .with_exposed_port(8000)
            .as_service()
        )

        # Run load tests with k6
        k6_container = (
            self.client.container()
            .from_("grafana/k6:latest")
            .with_service_binding("app", app_container)
            .with_directory("/tests", source.directory("tests/performance"))
        )

        test_results = {}

        # Run different load test scenarios
        scenarios = [
            {"name": "smoke", "script": "smoke-test.js"},
            {"name": "load", "script": "load-test.js"},
            {"name": "stress", "script": "stress-test.js"},
        ]

        for scenario in scenarios:
            try:
                exit_code = await k6_container.with_exec(
                    [
                        "k6",
                        "run",
                        f"/tests/{scenario['script']}",
                        "--out",
                        f"json=/tmp/{scenario['name']}-results.json",
                    ]
                ).exit_code()

                test_results[scenario["name"]] = {"passed": exit_code == 0}

                if exit_code == 0:
                    print(f"✅ {scenario['name'].title()} test passed")
                else:
                    print(f"❌ {scenario['name'].title()} test failed")

            except Exception as e:
                print(f"⚠️  {scenario['name'].title()} test error: {e}")
                test_results[scenario["name"]] = {"passed": False, "error": str(e)}

        return test_results


async def run_ci_pipeline(source_dir: str) -> bool:
    """Run the complete CI pipeline"""
    async with dagger.Connection(dagger.Config(log_output=sys.stderr)) as client:
        pipeline = EzzDayPipeline(client)
        source = client.host().directory(source_dir)

        print("🚀 Starting EzzDay Enhanced CI Pipeline")

        # Ensure reports directory exists
        os.makedirs("reports", exist_ok=True)

        # Run all CI steps with detailed reporting
        ci_steps = [
            ("Code Quality", pipeline.lint_and_format(source)),
            ("Unit Tests", pipeline.run_unit_tests(source)),
            ("Security Scan", pipeline.security_scan(source)),
            ("Performance Tests", pipeline.performance_tests(source)),
        ]

        all_passed = True
        step_results = {}

        for step_name, step_coro in ci_steps:
            print(f"\n--- {step_name} ---")
            try:
                result = await step_coro
                step_results[step_name] = result

                # Determine if step passed based on result type
                if isinstance(result, dict):
                    if "passed" in result:
                        success = result["passed"]
                    else:
                        # For complex results, check if any critical failures
                        success = all(
                            item.get("passed", True)
                            for item in result.values()
                            if isinstance(item, dict) and item.get("critical", False)
                        )
                else:
                    success = bool(result)

                if success:
                    print(f"✅ {step_name} passed")
                else:
                    print(f"❌ {step_name} failed")
                    all_passed = False

            except Exception as e:
                print(f"💥 {step_name} encountered an error: {e}")
                step_results[step_name] = {"error": str(e)}
                all_passed = False

        # Generate final CI report
        ci_report = {
            "pipeline": "ci",
            "timestamp": asyncio.get_event_loop().time(),
            "overall_success": all_passed,
            "steps": step_results,
        }

        with open("reports/ci-report.json", "w") as f:
            json.dump(ci_report, f, indent=2)

        return all_passed


async def run_cd_pipeline(source_dir: str, environment: str, tag: str) -> bool:
    """Run the complete CD pipeline"""
    async with dagger.Connection(dagger.Config(log_output=sys.stderr)) as client:
        pipeline = EzzDayPipeline(client)
        source = client.host().directory(source_dir)

        print(f"🚀 Starting EzzDay CD Pipeline for {environment}")

        # Build and push image
        build_result = await pipeline.build_and_push_image(source, tag)
        if not build_result.get("success", False):
            print("❌ Build and push failed")
            return False

        # Deploy to environment
        deploy_result = await pipeline.deploy_to_environment(tag, environment)
        if not deploy_result.get("success", False):
            print(f"❌ Deployment to {environment} failed")
            return False

        # Generate CD report
        cd_report = {
            "pipeline": "cd",
            "environment": environment,
            "tag": tag,
            "timestamp": asyncio.get_event_loop().time(),
            "build_result": build_result,
            "deploy_result": deploy_result,
            "overall_success": True,
        }

        os.makedirs("reports", exist_ok=True)
        with open(f"reports/cd-{environment}-report.json", "w") as f:
            json.dump(cd_report, f, indent=2)

        return True


async def main():
    """Main entry point with enhanced argument parsing"""
    import argparse

    parser = argparse.ArgumentParser(description="EzzDay Enhanced CI/CD Pipeline")
    parser.add_argument(
        "--mode", choices=["ci", "cd"], default="ci", help="Pipeline mode"
    )
    parser.add_argument("--source", default=".", help="Source directory")
    parser.add_argument(
        "--environment",
        choices=["staging", "production"],
        help="Deployment environment (for CD mode)",
    )
    parser.add_argument("--tag", default="latest", help="Image tag (for CD mode)")
    parser.add_argument(
        "--reports-dir", default="reports", help="Directory for reports"
    )

    args = parser.parse_args()

    # Ensure reports directory exists
    os.makedirs(args.reports_dir, exist_ok=True)

    if args.mode == "ci":
        success = await run_ci_pipeline(args.source)
    elif args.mode == "cd":
        if not args.environment:
            print("❌ Environment required for CD mode")
            sys.exit(1)
        success = await run_cd_pipeline(args.source, args.environment, args.tag)

    if success:
        print("\n🎉 Pipeline completed successfully!")
        sys.exit(0)
    else:
        print("\n💥 Pipeline failed!")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
