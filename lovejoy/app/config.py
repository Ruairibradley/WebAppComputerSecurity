import os
from datetime import timedelta
from dotenv import load_dotenv

def _bool(env_value: str | None, default: bool) -> bool:
    if env_value is None:
        return default
    return env_value.strip().lower() in {"1", "true", "yes", "on"}

def load_config():
    """Central config. Prefers .env, falls back to safe defaults."""
    load_dotenv(override=False)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    proj_dir = os.path.dirname(base_dir)
    db_path = os.path.join(proj_dir, "lovejoy.db")
    upload_dir = os.path.join(proj_dir, "uploads")

    secret = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
    db_uri = os.environ.get("DATABASE_URL") or f"sqlite:///{db_path}"
    max_mb = int(os.environ.get("MAX_CONTENT_MB", "2"))

    same_site = os.environ.get("SESSION_COOKIE_SAMESITE", "Lax")
    secure_flag = _bool(os.environ.get("SESSION_COOKIE_SECURE"), False)
    lifetime_sec = int(os.environ.get("PERMANENT_SESSION_LIFETIME_SEC", "3600"))

    return {
        "SECRET_KEY": secret,
        "SQLALCHEMY_DATABASE_URI": db_uri,
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,

        "UPLOAD_FOLDER": upload_dir,
        "MAX_CONTENT_LENGTH": max_mb * 1024 * 1024,
        "WTF_CSRF_TIME_LIMIT": 3600,
        "ENFORCE_2FA": True,

        # Cookie/session hardening
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": same_site,
        "SESSION_COOKIE_SECURE": secure_flag,
        "PERMANENT_SESSION_LIFETIME": timedelta(seconds=lifetime_sec),
        "SESSION_REFRESH_EACH_REQUEST": True,

        # Flask-Mail (Mailtrap)
        "MAIL_SERVER": os.environ.get("MAIL_SERVER", "sandbox.smtp.mailtrap.io"),
        "MAIL_PORT": int(os.environ.get("MAIL_PORT", "2525")),
        "MAIL_USERNAME": os.environ.get("MAIL_USERNAME") or "",
        "MAIL_PASSWORD": (os.environ.get("MAIL_PASSWORD") or "").strip(),
        "MAIL_USE_TLS": _bool(os.environ.get("MAIL_USE_TLS"), True),
        "MAIL_USE_SSL": _bool(os.environ.get("MAIL_USE_SSL"), False),
        "MAIL_DEFAULT_SENDER": os.environ.get("MAIL_DEFAULT_SENDER", "lovejoy@app.local"),
    }
