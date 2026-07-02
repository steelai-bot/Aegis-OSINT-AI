"""Scan service for running OSINT investigations."""

from __future__ import annotations

import asyncio
import logging
from typing import List, Dict, Any

from backend.agents.base import InvestigationContext, AgentResult
from backend.agents.breach import BreachAgent
from backend.agents.email import EmailAgent
from backend.agents.recon import ReconAgent
from backend.storage.database import get_db_session
from backend.services.investigation_engine import InvestigationEngine

logger = logging.getLogger(__name__)

class ScanService:
    """Service for running scan investigations."""

    def __init__(self, session):
        self.session = session
        self.engine = InvestigationEngine(session)

    async def run_scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Run a scan investigation."""
        logger.info(f"Starting scan for target: {target} (type: {target_type})")
        
        # Create investigation context
        context = InvestigationContext(
            investigation_id=None,
            target=target,
            target_type=target_type,
            metadata={}
        )
        
        # Run the investigation engine
        try:
            results = await self.engine.run(context)
            logger.info(f"Scan completed with results: {results}")
            return {
                "status": "success",
                "target": target,
                "type": target_type,
                "exposures": [r.status for r in results],
                "raw_log": results
            }
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            raise

    async def run_agents(self, investigation_id: str, target: str, target_type: str) -> List[AgentResult]:
        """Run specific agents for an investigation."""
        logger.info(f"Running agents for investigation {investigation_id}")
        
        # Create context
        context = InvestigationContext(
            investigation_id=investigation_id,
            target=target,
            target_type=target_type,
            metadata={}
        )
        
        # Run agents
        try:
            # Example: run breach agent
            breach_agent = BreachAgent()
            result = await breach_agent.execute(context)
            
            # Add more agents as needed
            results = [result]
            logger.info(f"Agents completed: {[r.status for r in results]}")
            return results
        except Exception as e:
            logger.error(f"Agents execution failed: {e}")
            raise