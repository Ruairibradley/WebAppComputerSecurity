import datetime as dt
from typing import Optional
from . import db
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher()  # strong KDF, slow down offline attacks

class User(db.Model):
    """
    User model for authentication and profile.
    """
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, index=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    failed_logins = db.Column(db.Integer, default=0, nullable=False)
    lock_until = db.Column(db.DateTime, nullable=True)
    lock_count = db.Column(db.Integer, default=0, nullable=False)  # progressive account locks

    totp_secret = db.Column(db.String(64), nullable=True)

    # Email-2FA fallback
    email_otp_code = db.Column(db.String(6), nullable=True)
    email_otp_expires = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow, nullable=False)

    def set_password(self, raw: str) -> None:
        """
        Hash and store the password securely.
        args:
            raw: str
        returns:
            None
        """
        self.password_hash = ph.hash(raw)

    def verify_password(self, raw: str) -> bool:
        """
        Verify raw passwords against stored hash.
        args:
            raw: str
        returns:
            bool
        """
        try:
            return ph.verify(self.password_hash, raw)
        except VerifyMismatchError:
            return False
        except Exception:
            return False

    def is_locked(self) -> bool:
        """
        Check if the account is currently locked.
        args:
            None
        returns: 
            bool
        """
        
        return bool(self.lock_until and dt.datetime.utcnow() < self.lock_until)

    def lock_progressive(self, base_minutes: int = 15, cap_hours: int = 24) -> int:
        """
        Compute next lock duration using exponential backoff (capped).
        args:
            base_minutes: int  
            cap_hours: int
        returns:
            int: lock duration in minutes
        """
        self.lock_count = (self.lock_count or 0) + 1
        minutes = base_minutes * (2 ** (self.lock_count - 1))
        max_minutes = cap_hours * 60
        minutes = min(minutes, max_minutes)
        self.lock_until = dt.datetime.utcnow() + dt.timedelta(minutes=minutes)
        self.failed_logins = 0
        return minutes


class EvaluationRequest(db.Model):
    """Model for user-submitted evaluation requests."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    comment_sanitized = db.Column(db.Text, nullable=False)
    contact_method = db.Column(db.String(20), nullable=False)
    photo_filename = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow, nullable=False)
    user = db.relationship("User", backref="requests")
