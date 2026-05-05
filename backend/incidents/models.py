from sqlalchemy import Column, DateTime, Integer, String, Text, func

from logstore.db import Base


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    source_log_id = Column(Integer, nullable=False, unique=True, index=True)
    prompt_summary = Column(Text, nullable=False)
    attack_type = Column(String(32), nullable=False, default="unknown", index=True)
    label = Column(String(32), nullable=False, index=True)
    risk_score = Column(Integer, nullable=False)
    severity = Column(String(16), nullable=False, default="LOW", index=True)
    status = Column(String(32), nullable=False, default="NEW", index=True)
    assignee = Column(String(128), nullable=False, default="", index=True)
    notes = Column(Text, nullable=False, default="")
    repeated_count = Column(Integer, nullable=False, default=0)
    alert_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    resolved_at = Column(DateTime(timezone=True), nullable=True)


class IncidentTimelineEvent(Base):
    __tablename__ = "incident_timeline"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, nullable=False, index=True)
    event_type = Column(String(32), nullable=False, index=True)
    previous_status = Column(String(32), nullable=True)
    new_status = Column(String(32), nullable=True)
    previous_severity = Column(String(16), nullable=True)
    new_severity = Column(String(16), nullable=True)
    actor = Column(String(128), nullable=False, default="system")
    notes = Column(Text, nullable=False, default="")
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
