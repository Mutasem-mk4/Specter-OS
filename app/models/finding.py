"""
Specter-OS — Finding Model
A confirmed finding/vulnerability discovered during a campaign.
"""

import uuid
from datetime import datetime, UTC
from sqlalchemy import String, DateTime, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    campaign_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False
    )
    attack_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("attacks.id", ondelete="SET NULL"), nullable=True
    )

    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)

    # CVSS-like score 0.0 - 10.0
    cvss_score: Mapped[float] = mapped_column(default=0.0)

    # Proof of concept — the exact conversation that broke the agent
    proof_of_concept: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Remediation recommendation
    remediation: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    # Relationships
    campaign: Mapped["Campaign"] = relationship("Campaign", back_populates="findings")

    def __repr__(self) -> str:
        return f"<Finding id={self.id} title={self.title!r} severity={self.severity}>"
