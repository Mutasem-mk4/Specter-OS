"""
Specter-OS — Campaign Orchestrator
The Command Center. Coordinates Scout → Forge → Inject → Judge pipeline
for a full red-team campaign run.
"""

import json
import uuid
from datetime import datetime, UTC
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.agents.scout import ScoutAgent
from app.agents.forge import ForgeEngine
from app.agents.injector import InjectorAgent
from app.agents.judge import JudgeLLM
from app.models.campaign import Campaign, CampaignStatus
from app.models.attack import Attack, AttackType, AttackStatus
from app.models.finding import Finding
from app.utils.logger import get_logger

logger = get_logger("orchestrator")


class CampaignOrchestrator:
    """
    Orchestrates the full Specter-OS pipeline:
    Scout → Forge → Inject → Judge → Findings
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.scout = ScoutAgent()
        self.forge = ForgeEngine()
        self.injector = InjectorAgent()
        self.judge = JudgeLLM()

    async def run_campaign(
        self,
        campaign_id: str,
        target_config: dict | None = None,
    ) -> Campaign:
        """
        Execute the full red-team pipeline for a campaign.

        Args:
            campaign_id: Campaign DB ID to execute
            target_config: Optional HTTP client config for the target

        Returns:
            Updated Campaign object
        """
        # Load campaign
        result = await self.db.execute(
            select(Campaign).where(Campaign.id == campaign_id)
        )
        campaign = result.scalar_one_or_none()
        if not campaign:
            raise ValueError(f"Campaign {campaign_id} not found")

        logger.info(
            f"\n{'='*60}\n"
            f"🚀 SPECTER-OS CAMPAIGN LAUNCHED\n"
            f"   Name:   {campaign.name}\n"
            f"   Target: {campaign.target_url}\n"
            f"{'='*60}"
        )

        try:
            # ── Phase 0: Commander Agent (Dual-Threat Integration) ──
            campaign.status = CampaignStatus.SCOUTING
            await self.db.commit()
            
            logger.info("\n🧠 PHASE 0: COMMANDER AGENT RECON & DAST\n" + "-"*40)
            from app.agents.commander import CommanderAgent
            commander = CommanderAgent()
            cmd_result = await commander.execute_mission(campaign.target_url)
            
            logger.info(f"✅ Commander Mission Complete. Summary:\n{cmd_result['commander_summary']}")
            
            # Record any Web-based findings discovered by Aura via Commander
            summary_lower = cmd_result['commander_summary'].lower()
            if any(k in summary_lower for k in ["xss", "sqli", "vulnerable", "vulnerability"]):
                finding = Finding(
                    id=str(uuid.uuid4()),
                    campaign_id=campaign_id,
                    attack_id=str(uuid.uuid4()), # Dummy ID for Web Aura findings
                    title="Aura Web DAST Vulnerability Cluster",
                    description=f"Commander Agent utilized Aura to uncover web architecture vulnerabilities:\n\n{cmd_result['commander_summary']}",
                    severity="high",
                    cvss_score=8.5,
                    proof_of_concept="Executed via Aura Web Toolkit integration. Refer to CLI logs.",
                    remediation="Sanitize all web inputs, establish tight CORS, and apply standard OWASP AppSec guidelines."
                )
                self.db.add(finding)
                await self.db.commit()
                logger.info("✅ Aura Web Findings recorded successfully.")

            # ── Phase 1: Scout HTTP/LLM Interface ──────────────────
            await self.db.commit()

            logger.info("\n📡 PHASE 1: SCOUTING TARGET\n" + "-"*40)
            scout_report = await self.scout.run(campaign.target_url, target_config)
            campaign.scout_report = scout_report.model_dump_json()
            await self.db.commit()

            scout_dict = scout_report.model_dump()
            logger.info(
                f"\n✅ Scout complete:\n"
                f"   Agent: {scout_report.agent_name}\n"
                f"   Capabilities: {len(scout_report.capabilities)}\n"
                f"   Recommended attacks: {scout_report.recommended_attack_types}"
            )

            # ── Phase 2: Forge ──────────────────────────────────────
            campaign.status = CampaignStatus.ATTACKING
            await self.db.commit()

            logger.info("\n⚡ PHASE 2: FORGING ATTACK CAMPAIGN\n" + "-"*40)
            attack_plans = await self.forge.forge_campaign(scout_dict)

            # Create Attack records in DB
            attack_records: list[tuple[Attack, dict]] = []
            for plan in attack_plans:
                attack = Attack(
                    id=str(uuid.uuid4()),
                    campaign_id=campaign_id,
                    attack_type=AttackType(plan["attack_type"]),
                    status=AttackStatus.PENDING,
                    payload=json.dumps(plan),
                )
                self.db.add(attack)
                attack_records.append((attack, plan))

            await self.db.commit()
            logger.info(f"✅ {len(attack_plans)} attacks forged and queued")

            # ── Phase 3: Inject ─────────────────────────────────────
            logger.info("\n🎯 PHASE 3: EXECUTING ATTACKS\n" + "-"*40)
            injection_results = []

            for attack_record, plan in attack_records:
                attack_record.status = AttackStatus.RUNNING
                await self.db.commit()

                result = await self.injector.execute(
                    attack_id=attack_record.id,
                    attack_plan=plan,
                    target_url=campaign.target_url,
                    target_config=target_config,
                )

                attack_record.status = result.status
                attack_record.conversation_log = json.dumps(result.conversation_log)
                attack_record.turns_taken = result.turns_taken
                attack_record.severity = result.severity
                attack_record.completed_at = datetime.now(UTC)
                await self.db.commit()

                injection_results.append((attack_record, plan, result))

            succeeded = sum(
                1 for _, _, r in injection_results
                if r.status == AttackStatus.SUCCEEDED
            )
            logger.info(
                f"\n✅ Injection complete: {succeeded}/{len(injection_results)} attacks SUCCEEDED"
            )

            # ── Phase 4: Judge ──────────────────────────────────────
            campaign.status = CampaignStatus.JUDGING
            await self.db.commit()

            logger.info("\n⚖️  PHASE 4: JUDGING RESULTS\n" + "-"*40)
            finding_count = 0

            for attack_record, plan, inj_result in injection_results:
                verdict = await self.judge.judge(
                    attack_type=attack_record.attack_type.value,
                    attack_plan=plan,
                    conversation_log=inj_result.conversation_log,
                    injector_status=inj_result.status.value,
                )

                attack_record.judge_verdict = verdict.model_dump_json()
                attack_record.judge_score = verdict.cvss_score
                await self.db.commit()

                # Create Finding if severity is noteworthy
                if verdict.attack_succeeded or verdict.cvss_score >= 4.0:
                    finding = Finding(
                        id=str(uuid.uuid4()),
                        campaign_id=campaign_id,
                        attack_id=attack_record.id,
                        title=verdict.finding_title,
                        description=verdict.technical_description,
                        severity=verdict.severity,
                        cvss_score=verdict.cvss_score,
                        proof_of_concept=verdict.proof_of_concept,
                        remediation=verdict.remediation,
                    )
                    self.db.add(finding)
                    finding_count += 1

            await self.db.commit()
            logger.info(f"✅ Judge complete: {finding_count} findings documented")

            # ── Phase 5: Complete ───────────────────────────────────
            campaign.status = CampaignStatus.COMPLETED
            campaign.completed_at = datetime.now(UTC)
            await self.db.commit()

            logger.info(
                f"\n{'='*60}\n"
                f"🏁 CAMPAIGN COMPLETE\n"
                f"   Success rate: {succeeded}/{len(injection_results)}\n"
                f"   Findings:     {finding_count}\n"
                f"{'='*60}\n"
            )

        except Exception as e:
            logger.error(f"Campaign failed: {e}", exc_info=True)
            campaign.status = CampaignStatus.FAILED
            await self.db.commit()
            raise

        return campaign
