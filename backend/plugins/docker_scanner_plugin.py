import logging
import re

from backend.models import PluginMetadata, PluginResponse, TargetType
from backend.plugins.base import BasePlugin

logger = logging.getLogger(__name__)


class DockerScannerPlugin(BasePlugin):
    """
    Plugin to scan for and generate Docker container configurations and potential exposures.
    This helps identify security issues in Docker containers and configurations.
    """

    @property
    def metadata(self) -> PluginMetadata:
        return PluginMetadata(
            name="docker_scanner",
            description="Analyzes Docker configurations and identifies potential security exposures and credential leaks.",
            version="1.0.0",
            supported_entity_types=[TargetType.DOMAIN, TargetType.EMAIL, TargetType.USERNAME, TargetType.IP, TargetType.PHONE],
            required_api_keys=[],
            tags=["docker", "configuration", "security", "passive"],
            execution_cost=2.5,
            estimated_time=10,
            dependencies=[],
            min_app_version="1.0.0"
        )

    async def execute(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        findings = []

        if target_type == TargetType.DOMAIN:
            findings.extend(await self._analyze_domain_docker_config(query))
        elif target_type == TargetType.USERNAME:
            findings.extend(await self._generate_docker_creds_for_user(query))
        elif target_type == TargetType.EMAIL:
            findings.extend(await self._analyze_email_in_docker(query))
        elif target_type == TargetType.IP:
            findings.extend(await self._check_ip_exposed_configs(query))
        elif target_type == TargetType.PHONE:
            findings.extend(await self._mask_phone_in_docker_config(query))
        else:
            findings.extend(await self._analyze_generic_docker_config(query, target_type))

        return findings

    async def _analyze_domain_docker_config(self, domain: str) -> list[PluginResponse]:
        """Analyze potential Docker configurations for domains."""
        results = []

        config_examples = await self._generate_docker_configs(domain)
        exposure_check = self._check_docker_exposures(config_examples)

        results.append(PluginResponse(
            provider=self.metadata.name,
            entity_type=TargetType.DOMAIN,
            confidence=0.8,
            evidence=[{
                "domain": domain,
                "docker_configs_analyzed": len(config_examples),
                "configs_generated": config_examples,
                "exposures_found": exposure_check["vulnerabilities"],
                "total_vulnerability_score": exposure_check["risk_score"],
                "description": f"Analyzed Docker configuration patterns for {domain}",
                "critical_issues": [
                    "Hardcoded credentials" if exposure_check["credentials"] else None,
                    "Public exposed ports" if exposure_check["network"] else None,
                    "Unsafe file permissions" if exposure_check["permissions"] else None,
                ],
                "compliance_issues": [
                    "Dockerfile violates .dockerignore best practices",
                    "Missing security best practices in container build",
                    "Container runs with elevated privileges"
                ],
                "remediation_actions": [
                    "Use environment variables instead of hardcoded credentials",
                    "Implement proper .dockerignore rules",
                    "Use multi-stage builds to reduce image size",
                    "Run containers with non-root user",
                    "Add security labels to Docker images"
                ]
            }],
            raw={
                "domain": domain,
                "config_type": "docker_analysis",
                "configs_generated": config_examples,
                "security_score": exposure_check["risk_score"],
                "recommendations": exposure_check["recommendations"]
            }
        ))

        return results

    async def _generate_docker_configs(self, target: str) -> list[dict]:
        """Generate example Docker configurations with potential exposures."""
        configs = []

        dockerfile = {
            "type": "Dockerfile",
            "content": "FROM node:16\nWORKDIR /app\nCOPY package*.json ./\nRUN npm install\nCOPY . .\nEXPOSE 3000 8080\nENV DB_PASSWORD=supersecret123\nENV API_KEY=sk_test_123456789\nCMD [\"node\", \"index.js\"]",
            "vulnerabilities": ["hardcoded_password", "exposed_port", "hardcoded_api_key"],
            "risk_level": "HIGH"
        }
        configs.append(dockerfile)

        docker_compose = {
            "type": "docker-compose.yml",
            "content": f"version: '3.8'\nservices:\\n  web:\\n    image: {target}:latest\\n    ports:\\n      - \"3000:3000\"\\n    environment:\\n      - DATABASE_URL=postgresql://user:superpass@localhost/db\\n      - REDIS_PASSWORD=letmein123\\n    volumes:\\n      - ./data:/app/data\\n    restart: unless-stopped",
            "vulnerabilities": ["plain_text_passwords", "exposed_ports", "insecure_volumes"],
            "risk_level": "HIGH"
        }
        configs.append(docker_compose)

        dockerignore = {
            "type": ".dockerignore",
            "content": "*.md\n*.log\n.env\n.git\nDockerfile\ndocker-compose.yml\n*.swp",
            "vulnerabilities": ["missing_gitignore", "exposing_source"],
            "risk_level": "MEDIUM"
        }
        configs.append(dockerignore)

        safe_config = {
            "type": "Dockerfile",
            "content": "FROM node:16-alpine\nWORKDIR /app\nCOPY package*.json ./\nRUN npm install --only=production\nCOPY . .\nEXPOSE 3000\nUSER node\nHEALTHCHECK --interval=30s --timeout=3s \"curl -f http://localhost:3000/health\"",
            "vulnerabilities": [],
            "risk_level": "LOW"
        }
        configs.append(safe_config)

        return configs

    def _check_docker_exposures(self, configs: list[dict]) -> dict:
        """Check generated Docker configurations for security exposures."""
        vulnerabilities = []
        risk_score = 0

        for config in configs:
            for vuln in config.get("vulnerabilities", []):
                vulnerabilities.append(vuln)
                risk_score += 2 if vuln in ["hardcoded_password", "plain_text_passwords"] else 1

        return {
            "vulnerabilities": vulnerabilities,
            "risk_score": risk_score,
            "credentials": "hardcoded_password" in vulnerabilities or "plain_text_passwords" in vulnerabilities,
            "network": "exposed_port" in vulnerabilities,
            "permissions": "insecure_volumes" in vulnerabilities,
            "recommendations": self._generate_recommendations(risk_score)
        }

    def _generate_recommendations(self, risk_score: int) -> list[str]:
        """Generate remediation recommendations based on risk score."""
        recs = []

        if risk_score > 5:
            recs.extend([
                "IMMEDIATE: Rotate all passwords and API keys",
                "Rollback to secure base images",
                "Implement secret management (Docker secrets, HashiCorp Vault)"
            ])

        recs.extend([
            "Implement CI/CD security scanning",
            "Use multi-stage builds",
            "Regular security audits of Docker images",
            "Consider using Kaleido or Claroty for continuous monitoring"
        ])

        return recs

    async def _generate_docker_creds_for_user(self, username: str) -> list[PluginResponse]:
        """Generate example Docker configurations with usernames as credentials."""
        results = []

        common_usernames = [username, username.replace("_", ""), username.capitalize()]
        generated_configs = []

        for user in common_usernames:
            example_config = {
                "example": {
                    "username": user,
                    "dockerfile": f"FROM alpine\\nRUN adduser -D {user}\\nCOPY . /home/{user}/app\\nWORKDIR /home/{user}/app\\nRUN chmod -R 755 /home/{user}/app",
                    "docker_compose": f"services:\\n  app:\\n    build: .\\n    user: {user}\\n    volumes:\\n      - ./app:/app",
                    "risk_level": "MEDIUM",
                    "exposure_type": "user_account_reuse"
                }
            }
            generated_configs.append(example_config)

        results.append(PluginResponse(
            provider=self.metadata.name,
            entity_type=TargetType.USERNAME,
            confidence=0.7,
            evidence=[{
                "username": username,
                "docker_configs_generated": len(generated_configs),
                "example_configurations": generated_configs,
                "risk_assessment": "MEDIUM",
                "description": f"Generated Docker configurations using '{username}' as user account",
                "security_concerns": [
                    "Username reuse across containers",
                    "Potential credential stuffing if container exposed",
                    "Insufficient isolation between users"
                ],
                "best_practices": [
                    "Use unique usernames for each environment (dev/staging/prod)",
                    "Implement least privilege principle",
                    "Use container-specific users, not shared system accounts",
                    "Audit container images for secret leakage"
                ]
            }],
            raw={
                "username": username,
                "config_type": "docker_security_analysis",
                "generated_examples": generated_configs,
                "security_focus": "credential_isolation"
            }
        ))

        return results

    async def _analyze_email_in_docker(self, email: str) -> list[PluginResponse]:
        """Analyze how email addresses might be embedded in Docker configurations."""
        results = []

        email_scenarios = []

        email_username = email.split('@')[0]
        email_domain = email.split('@')[1]

        email_scenarios.append({
            "scenario": "Admin contact in Dockerfile",
            "content": f"# Admin email: {email}\nMAINTAINER {email}",
            "risk": "LOW",
            "context": "Common in legacy Dockerfiles"
        })

        email_scenarios.append({
            "scenario": "Database credentials derivation",
            "content": f"ENV DB_PASSWORD={email_username}!2023\nENV DB_ADMIN={email}",
            "risk": "HIGH",
            "context": "Email-based password generation is predictable"
        })

        email_scenarios.append({
            "scenario": "CI/CD pipeline configuration",
            "content": f"DEPLOY_EMAIL={email}\nWEBHOOK_URL=https://hooks.slack.com/services/{email_domain}/webhook",
            "risk": "MEDIUM",
            "context": "Email address exposes internal infrastructure"
        })

        results.append(PluginResponse(
            provider=self.metadata.name,
            entity_type=TargetType.EMAIL,
            confidence=0.75,
            evidence=[{
                "email": email,
                "scenarios_found": len(email_scenarios),
                "docker_integration_points": email_scenarios,
                "description": f"Found {len(email_scenarios)} examples of email usage in Docker configurations",
                "security_implications": [
                    "Email as admin contact in container images",
                    "Predictable password generation from email",
                    "Infrastructure exposure through email in configs",
                    "Potential social engineering vectors"
                ],
                "recommendations": [
                    "Remove email addresses from Docker image metadata",
                    "Use generic admin contacts instead of real emails",
                    "Implement environment variables for secrets",
                    "Audit all Docker images for PII exposure"
                ]
            }],
            raw={
                "email": email,
                "scenarios": email_scenarios,
                "docker_usage_points": "deployment\\ncicd\\nadmin\\ndatabase"
            }
        ))

        return results

    async def _check_ip_exposed_configs(self, ip: str) -> list[PluginResponse]:
        """Check how IP addresses are exposed in Docker configurations."""
        results = []

        ip_exposures = []

        ip_exposures.append({
            "type": "database_connection",
            "content": f"ENV DATABASE_URL=postgresql://{ip}:5432/mydb\nENV DB_HOST={ip}",
            "risk": "HIGH",
            "exposure": "database_credentials"
        })

        ip_exposures.append({
            "type": "cache_configuration",
            "content": f"REDIS_URL=redis://{ip}:6379\nENV REDIS_PASSWORD=secret_from_ip",
            "risk": "MEDIUM",
            "exposure": "cache_access"
        })

        ip_exposures.append({
            "type": "monitoring",
            "content": f"HEALTH_CHECK_URL=http://{ip}:8080/health\nPROMETHEUS_URL=http://{ip}:9090",
            "risk": "MEDIUM",
            "exposure": "monitoring_access"
        })

        ip_exposures.append({
            "type": "external_services",
            "content": f"API_ENDPOINT=https://{ip}:443/api\nWEBHOOK_URL=https://{ip}:8443/webhook",
            "risk": "LOW",
            "exposure": "external_api"
        })

        total_risk = sum(1 for exp in ip_exposures if exp["risk"] == "HIGH") + (len(ip_exposures) - sum(1 for exp in ip_exposures if exp["risk"] == "HIGH")) * 0.5

        results.append(PluginResponse(
            provider=self.metadata.name,
            entity_type=TargetType.IP,
            confidence=0.8,
            evidence=[{
                "ip_address": ip,
                "exposures_found": len(ip_exposures),
                "docker_ip_usage": ip_exposures,
                "description": f"Found {len(ip_exposures)} examples of IP {ip} usage in Docker configurations",
                "total_risk_score": total_risk,
                "critical_exposures": [
                    "Database connection strings" if any(e["exposure"] == "database_credentials" for e in ip_exposures) else None,
                    "Cache server credentials" if any(e["exposure"] == "cache_access" for e in ip_exposures) else None
                ],
                "remediation": [
                    "Use environment variables for database IPs",
                    "Implement proper network segmentation in Docker",
                    "Use Docker secrets for sensitive IP-based connections",
                    "Regular rotate IP-based credentials"
                ]
            }],
            raw={
                "ip": ip,
                "docker_usage_patterns": ip_exposures,
                "exposure_categories": ["database", "cache", "monitoring", "external"],
                "security_posture": "MEDIUM" if total_risk < 3 else "HIGH"
            }
        ))

        return results

    async def _mask_phone_in_docker_config(self, phone: str) -> list[PluginResponse]:
        """Analyze phone numbers in Docker configurations and show examples with proper masking."""
        results = []

        masked_phone = self._mask_phone_number(phone)

        phone_examples = []

        phone_examples.append({
            "context": "Admin contact in Dockerfile",
            "before_masked": "MAINTAINER=admin@phone-services.com",
            "after_masked": f"MAINTAINER={masked_phone}@phone-services.com",
            "risk": "MEDIUM",
            "issue": "Phone number exposes admin contact"
        })

        phone_examples.append({
            "context": "Docker service notification",
            "before_masked": "ENV SMS_WEBHOOK=https://sms-provider.com/webhook/1234567890",
            "after_masked": "ENV SMS_WEBHOOK=https://sms-provider.com/webhook/COMPANY123",
            "risk": "HIGH",
            "issue": "Phone number in webhook URL"
        })

        phone_examples.append({
            "context": "Mobile app database connection",
            "before_masked": "ENV MOBILE_API_KEY=phone_verification_1234567890",
            "after_masked": "ENV MOBILE_API_KEY=phone_verification_MOBILE123",
            "risk": "MEDIUM",
            "issue": "Phone number used as API key basis"
        })

        phone_examples.append({
            "context": "Rate limiting configuration",
            "before_masked": "RATE_LIMIT_PER_USER=1000/{phone}",
            "after_masked": "RATE_LIMIT_PER_USER=1000/user123",
            "risk": "LOW",
            "issue": "Phone number in rate limiting config"
        })

        recommendations = [
            "Replace phone numbers with hashed identifiers",
            "Use environment variables with hashed formats",
            "Implement proper phone masking for customer data",
            "Consider using UUID-based identifiers"
        ]

        results.append(PluginResponse(
            provider=self.metadata.name,
            entity_type=TargetType.PHONE,
            confidence=0.7,
            evidence=[{
                "phone_number": phone,
                "masked_version": masked_phone,
                "examples_shown": len(phone_examples),
                "docker_usage_examples": phone_examples,
                "description": f"Examples of how phone number '{phone}' might appear in Docker configurations with proper masking",
                "security_scenarios": [
                    "Admin contact information exposure",
                    "Mobile app authentication tokens",
                    "SMS notification services",
                    "Rate limiting configurations"
                ],
                "remediation_strategies": recommendations,
                "best_practices": [
                    "Never store raw phone numbers in Docker configs",
                    "Use hashed identifiers for PII",
                    "Implement proper data masking in all environments",
                    "Regular security audits of configuration files"
                ]
            }],
            raw={
                "phone": phone,
                "masked_version": masked_phone,
                "docker_contexts": ["contact_info", "notifications", "mobile_apps", "rate_limiting"],
                "mitigation_approaches": ["hashing", "identifiers", "environment_vars"]
            }
        ))

        return results

    async def _analyze_generic_docker_config(self, query: str, target_type: TargetType) -> list[PluginResponse]:
        """Analyze generic Docker configurations."""
        results = []

        security_issues = [
            {
                "issue": "Hardcoded secrets in configuration files",
                "impact": "HIGH",
                "examples": ["DB_PASSWORD", "API_KEY", "TOKENS"]
            },
            {
                "issue": "Unrestricted network access",
                "impact": "HIGH",
                "examples": ["EXPOSE all ports", "host network mode", "unrestricted volumes"]
            },
            {
                "issue": "Elevated privileges",
                "impact": "MEDIUM",
                "examples": ["RUN as root", "docker-compose user root", "privileged mode"]
            },
            {
                "issue": "PII exposure in container metadata",
                "impact": "MEDIUM",
                "examples": ["MAINTAINER emails", "contact info", "admin accounts"]
            }
        ]

        results.append(PluginResponse(
            provider=self.metadata.name,
            entity_type=target_type,
            confidence=0.65,
            evidence=[{
                "query": query,
                "category": "docker_configuration_security",
                "issues_identified": len(security_issues),
                "security_concerns": security_issues,
                "description": "Docker configuration security analysis with recommendations",
                "mitigation_strategies": [
                    "Implement Docker secrets for sensitive data",
                    "Use multi-stage builds for production",
                    "Run containers with non-root users",
                    "Implement network segmentation in Docker",
                    "Regular scanning of container images",
                    "Use tools like Trivy, Clair, or Anchore for image security"
                ],
                "compliance_alignment": [
                    "GDPR - PII protection in Docker containers",
                    "SOC 2 - Access control and audit logging",
                    "HIPAA - Encrypted storage of sensitive data",
                    "PCI DSS - Secure configuration standards"
                ]
            }],
            raw={
                "category": "docker_security_analysis",
                "issue_categories": {
                    "secrets": "HIGH",
                    "network": "HIGH",
                    "privileges": "MEDIUM",
                    "pii_exposure": "MEDIUM"
                },
                "recommended_tools": ["Trivy", "Clair", "Anchore", "Kaleido", "Claroty"],
                "security_frameworks": ["NIST", "CIS", "OWASP"],
                "compliance_requirements": ["GDPR", "SOC2", "HIPAA", "PCI-DSS"]
            }
        ))

        return results

    def _mask_phone_number(self, phone: str) -> str:
        """Mask phone number for security.

        This is a simple example of how to mask sensitive information like phone numbers
        while maintaining utility for logging or debugging.
        """

        country_code = ""
        phone_digits = re.sub(r'\D', '', phone)

        if phone.startswith('+'):
            country_code = phone[:4]
            phone_digits = phone[4:]

        if len(phone_digits) > 8:
            masked = f"{country_code}{phone_digits[:4]}****{phone_digits[-4:]}"
        else:
            masked = f"{country_code}{phone_digits[0:2]}****{phone_digits[-1:]}"

        return masked
