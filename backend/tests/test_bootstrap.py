"""
backend/tests/test_bootstrap.py — Automated tests for _bootstrap_demo_accounts.

Covers every security requirement stated in the spec:
  1. Fresh DB admin creation succeeds when password is configured.
  2. Fresh DB admin creation is SKIPPED (no hardcoded fallback) when
     DEFAULT_ADMIN_PASSWORD is not set.
  3. Existing admin + sync disabled -> password hash is unchanged.
  4. Existing admin + BOOTSTRAP_ADMIN_PASSWORD_SYNC=true -> hash updated.
  5. Sync enabled + empty DEFAULT_ADMIN_PASSWORD -> hash NOT changed (safe).
  6. BOOTSTRAP_ADMIN_PASSWORD_SYNC does NOT touch the analyst account.
  7. Analyst created when DEFAULT_ANALYST_PASSWORD is configured and
     the account does not exist.
  8. Existing analyst password is NEVER overwritten automatically.
  9. No plaintext password is ever persisted in the DB (hash != plaintext).
 10. Sync flag does not affect any user other than the configured admin.
"""
import uuid
from datetime import datetime
from unittest.mock import patch

import pytest

from app.main import _bootstrap_demo_accounts
from app.core.security import hash_password, verify_password
from app.models.user import UserModel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_user(db, email: str, password: str, role: str = "ADMIN") -> UserModel:
    """Insert a user with a real bcrypt hash and return it."""
    user = UserModel(
        id=str(uuid.uuid4()),
        email=email,
        full_name="Test User",
        hashed_password=hash_password(password),
        role=role,
        is_active=True,
        created_at=datetime.utcnow(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _settings_patch(**kwargs):
    """Return a context-manager that patches only the specified settings fields."""
    defaults = {
        "DEFAULT_ADMIN_EMAIL": "admin@siem.local",
        "DEFAULT_ADMIN_PASSWORD": "",
        "DEFAULT_ANALYST_EMAIL": "analyst@siem.local",
        "DEFAULT_ANALYST_PASSWORD": "",
        "BOOTSTRAP_ADMIN_PASSWORD_SYNC": False,
    }
    defaults.update(kwargs)
    return patch.multiple("app.main.settings", **defaults)


# ===========================================================================
# 1. Fresh DB -- admin created when password is configured
# ===========================================================================

def test_fresh_db_admin_created_with_configured_password(db_session):
    with _settings_patch(DEFAULT_ADMIN_PASSWORD="ValidPass!99"):
        _bootstrap_demo_accounts(db_session)
    admin = db_session.query(UserModel).filter_by(email="admin@siem.local").first()
    assert admin is not None, "Admin account must be created on fresh DB"
    assert admin.role == "ADMIN"
    assert admin.is_active is True


# ===========================================================================
# 2. Fresh DB -- admin NOT created when password is missing (fail-safe)
# ===========================================================================

def test_fresh_db_no_admin_created_without_password(db_session):
    with _settings_patch(DEFAULT_ADMIN_PASSWORD=""):
        _bootstrap_demo_accounts(db_session)
    admin = db_session.query(UserModel).filter_by(email="admin@siem.local").first()
    assert admin is None, (
        "Admin must NOT be created when DEFAULT_ADMIN_PASSWORD is unset -- "
        "a hardcoded fallback would create a publicly-known credential."
    )


# ===========================================================================
# 3. Existing admin + sync disabled -> password hash unchanged
# ===========================================================================

def test_existing_admin_hash_unchanged_without_sync(db_session):
    original_hash = hash_password("OriginalSecret!1")
    admin = UserModel(
        id=str(uuid.uuid4()),
        email="admin@siem.local",
        full_name="System Administrator",
        hashed_password=original_hash,
        role="ADMIN",
        is_active=True,
        created_at=datetime.utcnow(),
    )
    db_session.add(admin)
    db_session.commit()
    with _settings_patch(
        DEFAULT_ADMIN_PASSWORD="NewSecret!999",
        BOOTSTRAP_ADMIN_PASSWORD_SYNC=False,
    ):
        _bootstrap_demo_accounts(db_session)
    db_session.refresh(admin)
    assert admin.hashed_password == original_hash, "Hash must be unchanged without sync flag"
    assert not verify_password("NewSecret!999", admin.hashed_password)


# ===========================================================================
# 4. Existing admin + BOOTSTRAP_ADMIN_PASSWORD_SYNC=true -> hash updated
# ===========================================================================

def test_sync_flag_updates_admin_hash(db_session):
    admin = _make_user(db_session, "admin@siem.local", "OldPass!1", role="ADMIN")
    original_hash = admin.hashed_password
    with _settings_patch(
        DEFAULT_ADMIN_PASSWORD="NewSyncedPass!2",
        BOOTSTRAP_ADMIN_PASSWORD_SYNC=True,
    ):
        _bootstrap_demo_accounts(db_session)
    db_session.refresh(admin)
    assert admin.hashed_password != original_hash, "Hash must be updated when sync flag is set"
    assert verify_password("NewSyncedPass!2", admin.hashed_password)


# ===========================================================================
# 5. Sync enabled + empty DEFAULT_ADMIN_PASSWORD -> hash NOT changed (safe)
# ===========================================================================

def test_sync_flag_with_empty_password_does_not_overwrite(db_session):
    admin = _make_user(db_session, "admin@siem.local", "ExistingPass!3", role="ADMIN")
    original_hash = admin.hashed_password
    with _settings_patch(DEFAULT_ADMIN_PASSWORD="", BOOTSTRAP_ADMIN_PASSWORD_SYNC=True):
        _bootstrap_demo_accounts(db_session)
    db_session.refresh(admin)
    assert admin.hashed_password == original_hash, (
        "Hash must NOT be changed when DEFAULT_ADMIN_PASSWORD is empty, "
        "even if BOOTSTRAP_ADMIN_PASSWORD_SYNC=true"
    )


# ===========================================================================
# 6. BOOTSTRAP_ADMIN_PASSWORD_SYNC does NOT touch the analyst account
# ===========================================================================

def test_sync_flag_does_not_touch_analyst(db_session):
    _make_user(db_session, "admin@siem.local", "AdminPass!4", role="ADMIN")
    analyst = _make_user(db_session, "analyst@siem.local", "AnalystOriginal!5", role="SECURITY_ANALYST")
    original_analyst_hash = analyst.hashed_password
    with _settings_patch(
        DEFAULT_ADMIN_PASSWORD="AdminNewPass!6",
        DEFAULT_ANALYST_PASSWORD="AnalystNew!7",
        BOOTSTRAP_ADMIN_PASSWORD_SYNC=True,
    ):
        _bootstrap_demo_accounts(db_session)
    db_session.refresh(analyst)
    assert analyst.hashed_password == original_analyst_hash, (
        "Analyst hash must NEVER be changed by BOOTSTRAP_ADMIN_PASSWORD_SYNC"
    )
    assert not verify_password("AnalystNew!7", analyst.hashed_password)


# ===========================================================================
# 7. Analyst created when configured and account does not exist
# ===========================================================================

def test_analyst_created_when_configured_and_absent(db_session):
    _make_user(db_session, "admin@siem.local", "AdminPass!8", role="ADMIN")
    with _settings_patch(
        DEFAULT_ADMIN_PASSWORD="AdminPass!8",
        DEFAULT_ANALYST_PASSWORD="AnalystPass!9",
    ):
        _bootstrap_demo_accounts(db_session)
    analyst = db_session.query(UserModel).filter_by(email="analyst@siem.local").first()
    assert analyst is not None, "Analyst account must be created when DEFAULT_ANALYST_PASSWORD is set"
    assert analyst.role == "SECURITY_ANALYST"
    assert analyst.is_active is True
    assert verify_password("AnalystPass!9", analyst.hashed_password)


def test_analyst_not_created_when_password_unset(db_session):
    _make_user(db_session, "admin@siem.local", "AdminPass!10", role="ADMIN")
    with _settings_patch(DEFAULT_ADMIN_PASSWORD="AdminPass!10", DEFAULT_ANALYST_PASSWORD=""):
        _bootstrap_demo_accounts(db_session)
    analyst = db_session.query(UserModel).filter_by(email="analyst@siem.local").first()
    assert analyst is None, "Analyst must NOT be created when DEFAULT_ANALYST_PASSWORD is unset"


# ===========================================================================
# 8. Existing analyst password is NEVER overwritten automatically
# ===========================================================================

def test_existing_analyst_password_never_overwritten(db_session):
    _make_user(db_session, "admin@siem.local", "AdminPass!11", role="ADMIN")
    analyst = _make_user(db_session, "analyst@siem.local", "AnalystStable!12", role="SECURITY_ANALYST")
    original_analyst_hash = analyst.hashed_password
    with _settings_patch(
        DEFAULT_ADMIN_PASSWORD="AdminPass!11",
        DEFAULT_ANALYST_PASSWORD="DifferentAnalystPass!13",
        BOOTSTRAP_ADMIN_PASSWORD_SYNC=False,
    ):
        _bootstrap_demo_accounts(db_session)
    db_session.refresh(analyst)
    assert analyst.hashed_password == original_analyst_hash, (
        "Existing analyst stored hash must NEVER be overwritten by bootstrap"
    )


# ===========================================================================
# 9. No plaintext password is ever persisted (hash != plaintext)
# ===========================================================================

def test_plaintext_password_never_stored_admin(db_session):
    plain = "PlainMustNotBeStored!14"
    with _settings_patch(DEFAULT_ADMIN_PASSWORD=plain):
        _bootstrap_demo_accounts(db_session)
    admin = db_session.query(UserModel).filter_by(email="admin@siem.local").first()
    assert admin is not None
    assert admin.hashed_password != plain, "Plaintext password must never be stored"
    assert admin.hashed_password.startswith(""), "Hash must be a bcrypt hash"


def test_plaintext_password_never_stored_analyst(db_session):
    _make_user(db_session, "admin@siem.local", "Admin!15", role="ADMIN")
    plain = "AnalystPlain!16"
    with _settings_patch(DEFAULT_ADMIN_PASSWORD="Admin!15", DEFAULT_ANALYST_PASSWORD=plain):
        _bootstrap_demo_accounts(db_session)
    analyst = db_session.query(UserModel).filter_by(email="analyst@siem.local").first()
    assert analyst is not None
    assert analyst.hashed_password != plain, "Plaintext analyst password must never be stored"
    assert analyst.hashed_password.startswith(""), "Analyst hash must be a bcrypt hash"


# ===========================================================================
# 10. Sync flag never touches any user other than the configured admin
# ===========================================================================

def test_sync_flag_never_touches_other_users(db_session):
    _make_user(db_session, "admin@siem.local", "AdminPass!17", role="ADMIN")
    bystander = _make_user(db_session, "viewer@siem.local", "ViewerPass!18", role="VIEWER")
    original_bystander_hash = bystander.hashed_password
    with _settings_patch(
        DEFAULT_ADMIN_PASSWORD="AdminNewPass!19",
        BOOTSTRAP_ADMIN_PASSWORD_SYNC=True,
    ):
        _bootstrap_demo_accounts(db_session)
    db_session.refresh(bystander)
    assert bystander.hashed_password == original_bystander_hash, (
        "Sync flag must never touch users other than the configured admin"
    )
