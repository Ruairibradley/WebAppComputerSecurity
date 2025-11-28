import datetime as dt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from . import db

ph = PasswordHasher() # password hasher instance

class User(db.Model):
    """User model representing application users with authentication and security features."""
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, index=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(50), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    failed_logins = db.Column(db.Integer, default=0, nullable=False)
    lock_until = db.Column(db.DateTime, nullable=True)
    lock_count = db.Column(db.Integer, default=0, nullable=False)

    totp_secret = db.Column(db.String(64), nullable=True)  # TOTP 2FA secret

    email_otp_code = db.Column(db.String(6), nullable=True)       # email 2FA fallback
    email_otp_expires = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow, nullable=False)

    # password methods
    def set_password(self, raw: str) -> None:
        """Set the user's password by hashing the raw password.
        args:
            raw: The raw password string to hash and store.
        returns:
            None
        """
        self.password_hash = ph.hash(raw)

    def verify_password(self, raw: str) -> bool:
        """Verify a raw password against the stored password hash.
        args:
            raw: The raw password string to verify.
        returns:
            True if the password matches, False otherwise.
        """
        try:
            return ph.verify(self.password_hash, raw)
        except VerifyMismatchError:
            return False
        except Exception:
            return False

    # locking failed password attempts
    def is_locked(self) -> bool:
        """Check if the user account is currently locked.
        args:
            None
        returns:
            True if the account is locked, False otherwise.
        """
        return bool(self.lock_until and dt.datetime.utcnow() < self.lock_until)

    def lock_progressive(self, base_minutes: int = 15, cap_hours: int = 24) -> int:
        """Lock the user account with progressive delay.
        args:
            base_minutes: Base lock duration in minutes.
            cap_hours: Maximum lock duration in hours.
        returns:
            The number of minutes the account is locked for."""
        self.lock_count = (self.lock_count or 0) + 1
        minutes = min(base_minutes * (2 ** (self.lock_count - 1)), cap_hours * 60)
        self.lock_until = dt.datetime.utcnow() + dt.timedelta(minutes=minutes)
        self.failed_logins = 0
        return minutes


class EvaluationRequest(db.Model):
    """Model representing user-submitted evaluation requests."""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    comment_sanitized = db.Column(db.Text, nullable=False)
    contact_method = db.Column(db.String(20), nullable=False)
    photo_filename = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=dt.datetime.utcnow, nullable=False)
    user = db.relationship("User", backref="requests")
