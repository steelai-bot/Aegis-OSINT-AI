"""Agent execution API schemas."""

from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class AgentRunRequest(BaseModel):
    investigation_id: UUID | None = None
    target: str = Field(min_length=1, max_length=2048)
    target_type: str = Field(min_length=1, max_length=50)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentRunResponse(BaseModel):
    agent_name: str
    status: str
    findings: list[dict[str, Any]]
    metadata: dict[str, Any]
