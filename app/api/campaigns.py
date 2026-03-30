"""
Specter-OS — Campaigns API
CRUD + execution endpoints for red-team campaigns.
"""

import asyncio
import json
from datetime import datetime, UTC
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel, HttpUrl
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.campaign import Campaign, CampaignStatus
from app.models.attack import Attack
from app.models.finding import Finding
from app.services.orchestrator import CampaignOrchestrator
from app.utils.logger import get_logger

router = APIRouter(prefix="/campaigns", tags=["Campaigns"])
logger = get_logger("api.campaigns")


# ── Schemas ──────────────────────────────────────────

class CampaignCreate(BaseModel):
    name: str
    target_url: str
    target_description: str | None = None
    # Optional target connection config
    target_config: dict | None = None


class CampaignResponse(BaseModel):
    id: str
    name: str
    target_url: str
    status: str
    created_at: datetime
    completed_at: datetime | None

    class Config:
        from_attributes = True


class CampaignDetail(CampaignResponse):
    target_description: str | None
    scout_report: dict | None
    attacks_count: int
    findings_count: int
    critical_count: int
    high_count: int


# ── Background Task ───────────────────────────────────

async def _run_campaign_task(campaign_id: str, target_config: dict | None):
    """Background task that runs the full campaign pipeline."""
    from app.database import AsyncSessionFactory
    async with AsyncSessionFactory() as db:
        orchestrator = CampaignOrchestrator(db)
        try:
            await orchestrator.run_campaign(campaign_id, target_config)
        except Exception as e:
            logger.error(f"Background campaign {campaign_id} failed: {e}")


# ── Routes ────────────────────────────────────────────

@router.post("/", response_model=CampaignResponse, status_code=201)
async def create_campaign(
    payload: CampaignCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Create a new campaign and immediately launch it in the background."""
    import uuid
    campaign = Campaign(
        id=str(uuid.uuid4()),
        name=payload.name,
        target_url=payload.target_url,
        target_description=payload.target_description,
        status=CampaignStatus.PENDING,
    )
    db.add(campaign)
    await db.commit()
    await db.refresh(campaign)

    logger.info(f"Campaign created: {campaign.id} — {campaign.name}")

    # Launch pipeline asynchronously
    background_tasks.add_task(
        asyncio.ensure_future,
        _run_campaign_task(campaign.id, payload.target_config)
    )

    return campaign


@router.get("/", response_model=list[CampaignResponse])
async def list_campaigns(db: AsyncSession = Depends(get_db)):
    """List all campaigns."""
    result = await db.execute(
        select(Campaign).order_by(Campaign.created_at.desc())
    )
    return result.scalars().all()


@router.get("/{campaign_id}", response_model=CampaignDetail)
async def get_campaign(campaign_id: str, db: AsyncSession = Depends(get_db)):
    """Get detailed campaign info including stats."""
    result = await db.execute(
        select(Campaign).where(Campaign.id == campaign_id)
    )
    campaign = result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    # Count attacks and findings
    attacks_result = await db.execute(
        select(Attack).where(Attack.campaign_id == campaign_id)
    )
    attacks = attacks_result.scalars().all()

    findings_result = await db.execute(
        select(Finding).where(Finding.campaign_id == campaign_id)
    )
    findings = findings_result.scalars().all()

    scout = None
    if campaign.scout_report:
        try:
            scout = json.loads(campaign.scout_report)
        except Exception:
            pass

    return CampaignDetail(
        id=campaign.id,
        name=campaign.name,
        target_url=campaign.target_url,
        target_description=campaign.target_description,
        status=campaign.status.value,
        created_at=campaign.created_at,
        completed_at=campaign.completed_at,
        scout_report=scout,
        attacks_count=len(attacks),
        findings_count=len(findings),
        critical_count=sum(1 for f in findings if f.severity == "critical"),
        high_count=sum(1 for f in findings if f.severity == "high"),
    )


@router.post("/{campaign_id}/run")
async def run_campaign(
    campaign_id: str,
    background_tasks: BackgroundTasks,
    target_config: dict | None = None,
    db: AsyncSession = Depends(get_db),
):
    """Re-run or manually trigger a campaign (useful for retrying failed campaigns)."""
    result = await db.execute(
        select(Campaign).where(Campaign.id == campaign_id)
    )
    campaign = result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    if campaign.status in (CampaignStatus.SCOUTING, CampaignStatus.ATTACKING, CampaignStatus.JUDGING):
        raise HTTPException(status_code=409, detail="Campaign is already running")

    campaign.status = CampaignStatus.PENDING
    await db.commit()

    background_tasks.add_task(
        asyncio.ensure_future,
        _run_campaign_task(campaign_id, target_config)
    )

    return {"message": f"Campaign {campaign_id} re-launched", "status": "pending"}


@router.delete("/{campaign_id}", status_code=204)
async def delete_campaign(campaign_id: str, db: AsyncSession = Depends(get_db)):
    """Delete a campaign and all its associated data."""
    result = await db.execute(
        select(Campaign).where(Campaign.id == campaign_id)
    )
    campaign = result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    await db.delete(campaign)
    await db.commit()
