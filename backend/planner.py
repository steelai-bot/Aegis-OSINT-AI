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
                steps=["dns_lookup", "whois_lookup", "cert_transparency", "email_discovery", "github_discovery", "username_enumeration", "google_dorking", "metadata_extraction"]
            ),
            TargetType.NZ_DOMAIN: InvestigationTemplate(
                target_type=TargetType.NZ_DOMAIN,
                steps=["dns_lookup", "whois_lookup", "cert_transparency", "email_discovery", "github_discovery", "username_enumeration", "google_dorking", "metadata_extraction"]
            ),
            TargetType.IP: InvestigationTemplate(
                target_type=TargetType.IP,
                steps=["ip_geolocation"]
            ),
            TargetType.COMPANY: InvestigationTemplate(
                target_type=TargetType.COMPANY,
                steps=["email_discovery", "github_discovery", "username_enumeration", "google_dorking", "metadata_extraction"] # General company search
            ),
            TargetType.ABN: InvestigationTemplate(
                target_type=TargetType.ABN,
                steps=["email_discovery", "github_discovery", "username_enumeration", "google_dorking", "metadata_extraction"] # ABN search
            ),
        }

    async def plan_investigation(self, target_type: TargetType, query: str, use_dynamic: bool = False) -> list[str]:
        """
        Returns a list of plugin names to execute.
        """
        if not use_dynamic:
            template = self.templates.get(target_type)
            if template:
                logger.info(f"Using template for {target_type}: {template.steps}")
                return template.steps
            logger.warning(f"No template found for {target_type}, falling back to dynamic planning.")

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
            # Fallback to basic heuristic if no AI provider is available
            return self.templates.get(target_type, InvestigationTemplate(target_type=target_type, steps=[])).steps

        prompt = (
            f"You are an OSINT expert. Given a target of type '{target_type}' with the value '{query}', "
            f"which of the following plugins should be executed in order to gather the most intelligence? "
            f"Available plugins: dns_lookup, whois_lookup, cert_transparency, ip_geolocation, "
            f"email_discovery, github_discovery, username_enumeration, google_dorking, metadata_extraction. "
            f"Return ONLY a comma-separated list of plugin names. Example: dns_lookup,whois_lookup"
        )

        try:
            response = await provider.chat(prompt, "gpt-3.5-turbo")
            plugins = [p.strip() for p in response.content.split(",") if p.strip()]
            # Validate that the suggested plugins actually exist (this would be checked by the Engine/Manager)
            logger.info(f"AI Planner suggested: {plugins}")
            return plugins
        except Exception as e:
            logger.error(f"Dynamic planning failed: {e}")
            return self.templates.get(target_type, InvestigationTemplate(target_type=target_type, steps=[])).steps
