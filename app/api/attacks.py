"""
Specter-OS — Attacks API
View and query individual attack results.
"""

import json
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.attack import Attack

router = APIRouter(prefix="/attacks", tags=["Attacks"])


class AttackResponse(BaseModel):
    id: str
    campaign_id: str
    attack_type: str
    status: str
    severity: str | None
    turns_taken: int
    judge_score: float | None
    judge_verdict: dict | None
    conversation_log: list | None
    created_at: datetime
    completed_at: datetime | None

    class Config:
        from_attributes = True


@router.get("/campaign/{campaign_id}", response_model=list[AttackResponse])
async def list_campaign_attacks(
    campaign_id: str, db: AsyncSession = Depends(get_db)
):
    """List all attacks for a campaign."""
    result = await db.execute(
        select(Attack)
        .where(Attack.campaign_id == campaign_id)
        .order_by(Attack.created_at)
    )
    attacks = result.scalars().all()

    return [
        AttackResponse(
            id=a.id,
            campaign_id=a.campaign_id,
            attack_type=a.attack_type.value,
            status=a.status.value,
            severity=a.severity.value if a.severity else None,
            turns_taken=a.turns_taken,
            judge_score=a.judge_score,
            judge_verdict=json.loads(a.judge_verdict) if a.judge_verdict else None,
            conversation_log=json.loads(a.conversation_log) if a.conversation_log else None,
            created_at=a.created_at,
            completed_at=a.completed_at,
        )
        for a in attacks
    ]


@router.get("/{attack_id}", response_model=AttackResponse)
async def get_attack(attack_id: str, db: AsyncSession = Depends(get_db)):
    """Get a single attack with full conversation log."""
    result = await db.execute(select(Attack).where(Attack.id == attack_id))
    attack = result.scalar_one_or_none()
    if not attack:
        raise HTTPException(status_code=404, detail="Attack not found")

    return AttackResponse(
        id=attack.id,
        campaign_id=attack.campaign_id,
        attack_type=attack.attack_type.value,
        status=attack.status.value,
        severity=attack.severity.value if attack.severity else None,
        turns_taken=attack.turns_taken,
        judge_score=attack.judge_score,
        judge_verdict=json.loads(attack.judge_verdict) if attack.judge_verdict else None,
        conversation_log=json.loads(attack.conversation_log) if attack.conversation_log else None,
        created_at=attack.created_at,
        completed_at=attack.completed_at,
    )
