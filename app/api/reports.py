"""
Specter-OS — Reports API
Generate and download CISO PDF reports for campaigns.
"""

import json
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models.campaign import Campaign
from app.models.finding import Finding
from app.services.report import CISOReportGenerator
from app.utils.logger import get_logger

router = APIRouter(prefix="/reports", tags=["Reports"])
logger = get_logger("api.reports")


@router.get("/campaign/{campaign_id}/pdf")
async def generate_pdf_report(
    campaign_id: str, db: AsyncSession = Depends(get_db)
):
    """Generate and download a CISO PDF report for a campaign."""
    # Load campaign
    result = await db.execute(
        select(Campaign).where(Campaign.id == campaign_id)
    )
    campaign = result.scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")

    # Load findings
    findings_result = await db.execute(
        select(Finding)
        .where(Finding.campaign_id == campaign_id)
        .order_by(Finding.cvss_score.desc())
    )
    findings = findings_result.scalars().all()

    if not findings:
        raise HTTPException(
            status_code=404,
            detail="No findings yet. Run the campaign first.",
        )

    # Build data dicts
    scout_data = {}
    if campaign.scout_report:
        try:
            scout_data = json.loads(campaign.scout_report)
        except Exception:
            pass

    campaign_data = {
        "name": campaign.name,
        "target_url": campaign.target_url,
        "agent_name": scout_data.get("agent_name", "Unknown Agent"),
    }

    findings_data = [
        {
            "title": f.title,
            "severity": f.severity,
            "cvss_score": f.cvss_score,
            "description": f.description,
            "proof_of_concept": f.proof_of_concept or "",
            "remediation": f.remediation or "",
            "owasp_category": "",  # Would come from judge_verdict if stored separately
        }
        for f in findings
    ]

    generator = CISOReportGenerator()
    pdf_path = await generator.generate(campaign_data, findings_data)

    if not Path(pdf_path).exists():
        raise HTTPException(status_code=500, detail="Report generation failed")

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=Path(pdf_path).name,
    )


@router.get("/campaign/{campaign_id}/findings")
async def get_findings(campaign_id: str, db: AsyncSession = Depends(get_db)):
    """Get all findings for a campaign as JSON."""
    result = await db.execute(
        select(Finding)
        .where(Finding.campaign_id == campaign_id)
        .order_by(Finding.cvss_score.desc())
    )
    findings = result.scalars().all()

    return [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "cvss_score": f.cvss_score,
            "description": f.description,
            "remediation": f.remediation,
            "proof_of_concept": f.proof_of_concept,
            "attack_id": f.attack_id,
            "created_at": f.created_at.isoformat(),
        }
        for f in findings
    ]
