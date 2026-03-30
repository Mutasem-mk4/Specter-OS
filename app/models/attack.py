"""
Specter-OS — Attack Model
A single attack attempt within a Campaign, including its full conversation log.
"""

import uuid
from datetime import datetime, UTC
from enum import Enum
from sqlalchemy import String, DateTime, Text, Enum as SAEnum, ForeignKey, Float
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.database import Base


class AttackType(str, Enum):
    GOAL_HIJACKING = "goal_hijacking"
    INDIRECT_INJECTION = "indirect_injection"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    MEMORY_POISONING = "memory_poisoning"
    IDENTITY_SPOOFING = "identity_spoofing"
    CASCADING_ATTACK = "cascading_attack"
    JAILBREAK = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"
    DENIAL_OF_SERVICE = "denial_of_service"
    ROLE_CONFUSION = "role_confusion"


class AttackStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"   # Attack broke through
    DEFENDED = "defended"     # Target agent held
    ERROR = "error"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Attack(Base):
    __tablename__ = "attacks"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    campaign_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False
    )

    attack_type: Mapped[AttackType] = mapped_column(
        SAEnum(AttackType), nullable=False
    )
    status: Mapped[AttackStatus] = mapped_column(
        SAEnum(AttackStatus), default=AttackStatus.PENDING, nullable=False
    )
    severity: Mapped[SeverityLevel | None] = mapped_column(
        SAEnum(SeverityLevel), nullable=True
    )

    # The generated attack payload
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Full conversation transcript (JSON: list of {role, content} dicts)
    conversation_log: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Judge LLM verdict
    judge_verdict: Mapped[str | None] = mapped_column(Text, nullable=True)
    judge_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    turns_taken: Mapped[int] = mapped_column(default=0)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    campaign: Mapped["Campaign"] = relationship("Campaign", back_populates="attacks")

    def __repr__(self) -> str:
        return f"<Attack id={self.id} type={self.attack_type} status={self.status}>"
