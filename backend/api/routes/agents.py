"""Agent execution API routes."""

from fastapi import APIRouter

from backend.agents import InvestigationContext
from backend.api.schemas.agents import AgentRunRequest, AgentRunResponse
from backend.services.investigation_engine import InvestigationEngine

router = APIRouter(tags=["agents"])


@router.post("/agents/run", response_model=list[AgentRunResponse])
async def run_agents(payload: AgentRunRequest):
    context = InvestigationContext(
        investigation_id=payload.investigation_id,
        target=payload.target,
        target_type=payload.target_type,
        metadata=payload.metadata,
    )
    results = await InvestigationEngine().run(context)
    return [
        AgentRunResponse(
            agent_name=result.agent_name,
            status=result.status,
            findings=result.findings,
            metadata=result.metadata,
        )
        for result in results
    ]
