"""
app/schemas/user.py — Pydantic v2 schemas for auth and user management.
"""
from datetime import datetime
from typing import List, Optional

from pydantic import EmailStr, Field

from app.schemas.common import CamelModel

# Valid role strings — validated in UserCreate/UserUpdate
VALID_ROLES = {"ADMIN", "SECURITY_ANALYST", "SOC_OPERATOR", "VIEWER"}


class UserLogin(CamelModel):
    email: str
    password: str


class UserOut(CamelModel):
    id: str
    email: str
    full_name: str
    role: str
    is_active: bool
    last_login: Optional[datetime] = None
    created_at: Optional[datetime] = None


class TokenResponse(CamelModel):
    access_token: str
    token_type: str = "bearer"
    user: "UserOut"
    permissions: List[str] = []


class UserCreate(CamelModel):
    email: str
    full_name: str = ""
    password: str = Field(min_length=8)
    role: str = "VIEWER"


class UserUpdate(CamelModel):
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    # Password reset — optional, min 8 chars if provided
    new_password: Optional[str] = None


class MeResponse(CamelModel):
    user: UserOut
    permissions: List[str] = []
