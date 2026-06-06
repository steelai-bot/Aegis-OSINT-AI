"""Agent execution API routes."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.agents import InvestigationContext
from backend.api.schemas.agents import AgentRunRequest, AgentRunResponse
from backend.api.security import require_permission
from backend.services.investigation_engine import InvestigationEngine
from backend.storage.database import get_db_session

router = APIRouter(tags=["agents"])


@router.post(
    "/agents/run",
    response_model=list[AgentRunResponse],
    dependencies=[Depends(require_permission("agent:run"))],
)
async def run_agents(payload: AgentRunRequest, session: AsyncSession = Depends(get_db_session)):
    context = InvestigationContext(
        investigation_id=payload.investigation_id,
        target=payload.target,
        target_type=payload.target_type,
        metadata=payload.metadata,
    )
    results = await InvestigationEngine(session=session).run(context)
    return [
        AgentRunResponse(
            agent_name=result.agent_name,
            status=result.status,
            findings=result.findings,
            metadata=result.metadata,
        )
        for result in results
    ]
