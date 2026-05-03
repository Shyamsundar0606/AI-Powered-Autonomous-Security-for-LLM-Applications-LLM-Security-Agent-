from sqlalchemy import Column, DateTime, Integer, String, Text, func

from logstore.db import Base


class LogEntry(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    user_input = Column(Text, nullable=False)
    risk_score = Column(Integer, nullable=False)
    label = Column(String(32), nullable=False, index=True)
    reason = Column(Text, nullable=False)
    attack_type = Column(String(32), nullable=False, default="unknown", index=True)
    incident_status = Column(String(32), nullable=False, default="NEW", index=True)
    incident_notes = Column(Text, nullable=False, default="")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
