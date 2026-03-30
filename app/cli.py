"""
Specter-OS — CLI Management Tool
Bootstrap, run, and manage Specter-OS from the command line.
"""

import asyncio
import json
import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()
app = typer.Typer(
    name="specter",
    help="⚡ Specter-OS — Autonomous AI Agent Red Teaming Engine",
    add_completion=False,
)


@app.command()
def serve(
    host: str = typer.Option("0.0.0.0", help="Host to bind"),
    port: int = typer.Option(8000, help="Port to listen on"),
    reload: bool = typer.Option(False, help="Enable hot-reload (dev mode)"),
):
    """Start the Specter-OS API server."""
    import uvicorn
    console.print(Panel.fit(
        "[bold red]⚡ SPECTER-OS[/bold red]\n[dim]Autonomous AI Red Teaming Engine[/dim]",
        border_style="red",
    ))
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info",
    )


@app.command()
def attack(
    target: str = typer.Argument(..., help="Target agent URL"),
    name: str = typer.Option("CLI Campaign", help="Campaign name"),
    config: str = typer.Option(None, help="Path to target config JSON file"),
):
    """Launch a full red-team campaign from the CLI."""
    async def _run():
        from app.database import init_db, AsyncSessionFactory
        from app.services.orchestrator import CampaignOrchestrator
        from app.models.campaign import Campaign, CampaignStatus
        import uuid

        await init_db()

        target_config = None
        if config:
            with open(config) as f:
                target_config = json.load(f)

        async with AsyncSessionFactory() as db:
            campaign = Campaign(
                id=str(uuid.uuid4()),
                name=name,
                target_url=target,
                status=CampaignStatus.PENDING,
            )
            db.add(campaign)
            await db.commit()

            console.print(f"\n[bold green]Campaign launched:[/bold green] {campaign.id}")
            orchestrator = CampaignOrchestrator(db)
            result = await orchestrator.run_campaign(campaign.id, target_config)

            console.print(Panel.fit(
                f"[bold]Campaign Complete[/bold]\n"
                f"Status: [green]{result.status.value}[/green]\n"
                f"ID: {result.id}",
                title="⚡ Specter-OS",
                border_style="green",
            ))

    asyncio.run(_run())


@app.command()
def report(
    campaign_id: str = typer.Argument(..., help="Campaign ID to generate report for"),
):
    """Generate a CISO PDF report for a campaign."""
    async def _run():
        from app.database import init_db, AsyncSessionFactory
        from app.models.campaign import Campaign
        from app.models.finding import Finding
        from app.services.report import CISOReportGenerator
        from sqlalchemy import select
        import json

        await init_db()

        async with AsyncSessionFactory() as db:
            result = await db.execute(
                select(Campaign).where(Campaign.id == campaign_id)
            )
            campaign = result.scalar_one_or_none()
            if not campaign:
                console.print(f"[red]Campaign {campaign_id} not found[/red]")
                raise typer.Exit(1)

            findings_result = await db.execute(
                select(Finding)
                .where(Finding.campaign_id == campaign_id)
                .order_by(Finding.cvss_score.desc())
            )
            findings = findings_result.scalars().all()

            scout_data = {}
            if campaign.scout_report:
                try:
                    scout_data = json.loads(campaign.scout_report)
                except Exception:
                    pass

            campaign_data = {
                "name": campaign.name,
                "target_url": campaign.target_url,
                "agent_name": scout_data.get("agent_name", "Unknown"),
            }
            findings_data = [
                {
                    "title": f.title,
                    "severity": f.severity,
                    "cvss_score": f.cvss_score,
                    "description": f.description,
                    "proof_of_concept": f.proof_of_concept or "",
                    "remediation": f.remediation or "",
                    "owasp_category": "",
                }
                for f in findings
            ]

            gen = CISOReportGenerator()
            pdf_path = await gen.generate(campaign_data, findings_data)
            console.print(f"\n[bold green]✅ Report saved:[/bold green] {pdf_path}")

    asyncio.run(_run())


@app.command()
def status(
    campaign_id: str = typer.Argument(..., help="Campaign ID"),
):
    """Check campaign status and findings summary."""
    async def _run():
        from app.database import init_db, AsyncSessionFactory
        from app.models.campaign import Campaign
        from app.models.finding import Finding
        from app.models.attack import Attack
        from sqlalchemy import select

        await init_db()

        async with AsyncSessionFactory() as db:
            result = await db.execute(
                select(Campaign).where(Campaign.id == campaign_id)
            )
            campaign = result.scalar_one_or_none()
            if not campaign:
                console.print(f"[red]Campaign not found[/red]")
                raise typer.Exit(1)

            attacks_result = await db.execute(
                select(Attack).where(Attack.campaign_id == campaign_id)
            )
            attacks = attacks_result.scalars().all()

            findings_result = await db.execute(
                select(Finding).where(Finding.campaign_id == campaign_id)
            )
            findings = findings_result.scalars().all()

            console.print(Panel.fit(
                f"[bold]{campaign.name}[/bold]\n"
                f"Target: {campaign.target_url}\n"
                f"Status: [yellow]{campaign.status.value}[/yellow]\n"
                f"Attacks: {len(attacks)} | Findings: {len(findings)}",
                title="📊 Campaign Status",
                border_style="yellow",
            ))

            if findings:
                table = Table(title="Findings")
                table.add_column("Severity", style="bold")
                table.add_column("CVSS")
                table.add_column("Title")
                for f in sorted(findings, key=lambda x: x.cvss_score, reverse=True):
                    sev_color = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "green"}.get(f.severity, "white")
                    table.add_row(f"[{sev_color}]{f.severity.upper()}[/{sev_color}]", f"{f.cvss_score:.1f}", f.title)
                console.print(table)

    asyncio.run(_run())


if __name__ == "__main__":
    app()
