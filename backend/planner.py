import logging

from backend.models import InvestigationTemplate, TargetType
from backend.providers import AIProviderFactory

logger = logging.getLogger(__name__)


class AIPlanner:
    """
    AI Planner that determines the sequence of plugins to execute for a given target.
    Supports both template-based planning and dynamic LLM-assisted planning.
    """

    def __init__(self):
        # Predefined templates for common target types
        self.templates: dict[TargetType, InvestigationTemplate] = {
            TargetType.DOMAIN: InvestigationTemplate(
                target_type=TargetType.DOMAIN,
                steps=[
                    "dns_lookup",
                    "whois_lookup",
                    "cert_transparency",
                    "wayback_machine",
                    "web_recon",
                    "email_discovery",
                    "github_discovery",
                    "username_enumeration",
                    "google_dorking",
                    "metadata_extraction",
                    "leaked_db",
                    "darkweb_monitor",
                ],
            ),
            TargetType.NZ_DOMAIN: InvestigationTemplate(
                target_type=TargetType.NZ_DOMAIN,
                steps=[
                    "dns_lookup",
                    "whois_lookup",
                    "cert_transparency",
                    "wayback_machine",
                    "web_recon",
                    "email_discovery",
                    "github_discovery",
                    "username_enumeration",
                    "google_dorking",
                    "metadata_extraction",
                    "leaked_db",
                    "darkweb_monitor",
                ],
            ),
            TargetType.SUBDOMAIN: InvestigationTemplate(
                target_type=TargetType.SUBDOMAIN,
                steps=["dns_lookup", "wayback_machine", "web_recon"],
            ),
            TargetType.IP: InvestigationTemplate(
                target_type=TargetType.IP, steps=["ip_geolocation"]
            ),
            TargetType.EMAIL: InvestigationTemplate(
                target_type=TargetType.EMAIL,
                steps=[
                    "email_discovery",
                    "gravatar_lookup",
                    "emailrep_lookup",
                    "breach_check",
                    "exposed_credentials",
                    "stealer_logs",
                    "darkweb_monitor",
                    "telegram_osint",
                ],
            ),
            TargetType.USERNAME: InvestigationTemplate(
                target_type=TargetType.USERNAME,
                steps=[
                    "username_enumeration",
                    "exposed_credentials",
                    "stealer_logs",
                    "darkweb_monitor",
                    "telegram_osint",
                ],
            ),
            TargetType.PHONE: InvestigationTemplate(
                target_type=TargetType.PHONE,
                steps=[
                    "phone_lookup",
                    "exposed_credentials",
                    "breach_check",
                    "stealer_logs",
                    "telegram_osint",
                ],
            ),
            TargetType.PERSON: InvestigationTemplate(
                target_type=TargetType.PERSON,
                steps=[
                    "name_permutator",
                    "username_enumeration",
                    "google_dorking",
                    "exposed_credentials",
                    "stealer_logs",
                    "darkweb_monitor",
                    "telegram_osint",
                ],
            ),
            TargetType.ADDRESS: InvestigationTemplate(
                target_type=TargetType.ADDRESS,
                steps=["google_dorking", "darkweb_monitor", "stealer_logs"],
            ),
            TargetType.LEAK: InvestigationTemplate(
                target_type=TargetType.LEAK,
                steps=["leaked_db", "stealer_logs", "darkweb_monitor", "breach_check"],
            ),
            TargetType.COMPANY: InvestigationTemplate(
                target_type=TargetType.COMPANY,
                steps=[
                    "email_discovery",
                    "github_discovery",
                    "username_enumeration",
                    "google_dorking",
                    "metadata_extraction",
                ],  # General company search
            ),
            TargetType.ABN: InvestigationTemplate(
                target_type=TargetType.ABN,
                steps=[
                    "email_discovery",
                    "github_discovery",
                    "username_enumeration",
                    "google_dorking",
                    "metadata_extraction",
                ],  # ABN search
            ),
        }

    async def plan_investigation(
        self, target_type: TargetType, query: str, use_dynamic: bool = False
    ) -> list[str]:
        """
        Returns a list of plugin names to execute.
        """
        if not use_dynamic:
            template = self.templates.get(target_type)
            if template:
                logger.info(f"Using template for {target_type}: {template.steps}")
                return template.steps
            logger.warning(
                f"No template found for {target_type}, falling back to dynamic planning."
            )

        return await self._plan_dynamically(target_type, query)

    async def _plan_dynamically(self, target_type: TargetType, query: str) -> list[str]:
        """
        Uses an LLM to determine the best plugins for the given target.
        """
        # In a real scenario, we would pass the list of available plugins to the LLM
        # For now, we'll simulate the LLM's decision or use a basic heuristic
        logger.info(f"Planning dynamically for {target_type} with query: {query}")

        # Try to get a provider for the planner
        provider = AIProviderFactory.get_provider("openrouter")
        if not provider:
            return self.templates.get(
                target_type, InvestigationTemplate(target_type=target_type, steps=[])
            ).steps

        prompt = (
            f"You are an OSINT expert. Given a target of type '{target_type}' with the value '{query}', "
            f"which of the following plugins should be executed in order to gather the most intelligence? "
            f"Available plugins: dns_lookup, whois_lookup, cert_transparency, ip_geolocation, "
            f"wayback_machine, web_recon, "
            f"email_discovery, gravatar_lookup, emailrep_lookup, phone_lookup, name_permutator, "
            f"github_discovery, username_enumeration, google_dorking, metadata_extraction, "
            f"breach_check, exposed_credentials, stealer_logs, darkweb_monitor, leaked_db, telegram_osint. "
            f"Return ONLY a comma-separated list of plugin names. Example: dns_lookup,whois_lookup"
        )

        try:
            model = (
                "gpt-3.5-turbo"
                if getattr(provider, "provider", "") == "openrouter"
                else getattr(provider, "_default_model", "gpt-3.5-turbo")
            )
            response = await provider.chat(prompt, model)
            suggested = [p.strip() for p in response.content.split(",") if p.strip()]
            valid_known = {
                "dns_lookup",
                "whois_lookup",
                "cert_transparency",
                "ip_geolocation",
                "wayback_machine",
                "web_recon",
                "email_discovery",
                "gravatar_lookup",
                "emailrep_lookup",
                "phone_lookup",
                "name_permutator",
                "github_discovery",
                "username_enumeration",
                "google_dorking",
                "metadata_extraction",
                "breach_check",
                "exposed_credentials",
                "stealer_logs",
                "darkweb_monitor",
                "leaked_db",
                "telegram_osint",
            }

            plugins = [p for p in suggested if p in valid_known]
            logger.info(f"AI Planner suggested: {plugins}")
            return plugins
        except Exception as e:
            logger.error(f"Dynamic planning failed: {e}")
            return self.templates.get(
                target_type, InvestigationTemplate(target_type=target_type, steps=[])
            ).steps
