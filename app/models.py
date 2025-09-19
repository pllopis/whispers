import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, LargeBinary, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Session

from .db import Base

class Secret(Base):
    __tablename__ = "secrets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token = Column(String(64), unique=True, index=True, nullable=False)  # public link token
    title = Column(String(255), nullable=True)
    ciphertext = Column(LargeBinary, nullable=False)
    creator = Column(String(255), nullable=False)  # subject/username of creator
    allowed_users = Column(Text, nullable=True)    # comma-separated usernames
    allowed_groups = Column(Text, nullable=True)   # comma-separated group names
    expires_at = Column(DateTime(timezone=True), nullable=False)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    revoked = Column(Boolean, default=False)

    def is_expired(self) -> bool:
        now = datetime.now(timezone.utc)
        exp = self.expires_at
        # SQLite may return naive datetimes; treat them as UTC
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return now >= exp

    @staticmethod
    def purge_expired(db: Session) -> int:
        """Delete expired secrets.

        Returns the number of rows removed.
        """

        now = datetime.now(timezone.utc)
        return (
            db.query(Secret)
            .filter(Secret.expires_at <= now)
            .delete(synchronize_session=False)
        )
