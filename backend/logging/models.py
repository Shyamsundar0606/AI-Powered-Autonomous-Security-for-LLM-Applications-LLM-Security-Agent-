from sqlalchemy import Column, DateTime, Integer, String, Text, func

from logging.db import Base


class LogEntry(Base):
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    user_input = Column(Text, nullable=False)
    risk_score = Column(Integer, nullable=False)
    label = Column(String(32), nullable=False, index=True)
    reason = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
