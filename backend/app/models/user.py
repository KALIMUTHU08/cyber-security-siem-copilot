"""
app/models/user.py — User account model with RBAC roles.

Roles (stored as plain strings, never elevated dynamically):
  ADMIN | SECURITY_ANALYST | SOC_OPERATOR | VIEWER
"""
from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, String
from app.database.base import Base


class UserModel(Base):
    __tablename__ = "users"

    id = Column(String(64), primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=False, default="")
    # Password is always stored hashed — never plaintext.
    hashed_password = Column(String(255), nullable=False)
    # Role is a plain string; validation is enforced in the schema/service layer.
    role = Column(String(32), nullable=False, default="VIEWER")
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
