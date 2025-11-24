import os
from dotenv import load_dotenv

def load_config():
    """
    Load configuration from environment or defaults.
    args:
        None
    retunrns:
        dict
    """
    load_dotenv(override=False)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    proj_dir = os.path.dirname(base_dir)
    db_path = os.path.join(proj_dir, "lovejoy.db")
    upload_dir = os.path.join(proj_dir, "uploads")

    secret = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
    db_uri = os.environ.get("DATABASE_URL") or f"sqlite:///{db_path}"
    max_mb = int(os.environ.get("MAX_CONTENT_MB", "2"))

    return {
        "SECRET_KEY": secret,
        "SQLALCHEMY_DATABASE_URI": db_uri,
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "UPLOAD_FOLDER": upload_dir,
        "MAX_CONTENT_LENGTH": max_mb * 1024 * 1024,   # early reject large uploads
        "WTF_CSRF_TIME_LIMIT": 3600,                  # CSRF lifetime ~1h
        "ENFORCE_2FA": True,                          # enforce 2FA before full login
    }


