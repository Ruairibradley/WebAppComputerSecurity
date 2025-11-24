import os
import re
import io
import secrets
from functools import wraps
from typing import Optional
from flask import session, redirect, url_for, abort
from itsdangerous import URLSafeTimedSerializer
import bleach
from PIL import Image
from . import db
from .models import User

# allowed image extensions 
ALLOWED_EXTENSIONS = {".jpg", ".jpeg", ".png"} 

def signer(secret_key: str) -> URLSafeTimedSerializer:
    """
    signs short lived tokens for email actions.
    args: 
        secret_key: str
    returns: 
        URLSafeTimedSerializer
    """
    return URLSafeTimedSerializer(secret_key, salt="lovejoy-email")

def require_login(view):
    """Gate for logged-in users only.
    args:
        view: function
    returns:
        function
    """
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapper

def admin_required(view):
    """Gate for admins, simple Boolean.
    args:
        view: function
    returns:
        function
    """
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user_id") or not session.get("is_admin"):
            abort(403)
        return view(*args, **kwargs)
    return wrapper

def get_current_user() -> Optional[User]:
    """
    Get the current user via their id.
    args:
        None
    returns:
        Optional[User]
    """
    uid = session.get("user_id")
    return db.session.get(User, uid) if uid else None

def random_filename(ext: str) -> str:
    """Randomised name avoids collisions and leaking original filenames.
    args:
        ext: str
    returns:
        str"""
    return f"{secrets.token_urlsafe(16)}{ext.lower()}"

def allowed_file(filename: str) -> Optional[str]:
    """Extension allow-list to stop obvious bad types.
    args:
        filename: str
    returns:    
        Optional[str]
    """
    _, ext = os.path.splitext(filename)
    return ext.lower() if ext.lower() in ALLOWED_EXTENSIONS else None

def sanitize_comment(text: str) -> str:
    """Strip HTML entirely → stored/reflective XSS becomes inert.
    args:
        text: str
    returns:
        str
    """
    return bleach.clean(text, tags=[], attributes={}, protocols=[], strip=True)

def validate_image_bytes(b: bytes) -> bool:
    """Verify the content is actually an image not just file named in style of image.
    args:
        b: bytes
    returns:
        bool
    """
    try:
        Image.open(io.BytesIO(b)).verify()
        return True
    except Exception:
        return False

def strong_password(pw: str) -> tuple[bool, str]:
    """
    Lightweight policy: 12+ chars, upper/lower/digit/special.
    Return (ok, human-readable hint) for UX.
    args:
        pw: str
    returns:
        tuple[bool, str]
    """
    msg = []; ok = True
    if len(pw) < 12: ok=False; msg.append("≥12 chars")
    if not re.search(r"[A-Z]", pw): ok=False; msg.append("uppercase")
    if not re.search(r"[a-z]", pw): ok=False; msg.append("lowercase")
    if not re.search(r"\d", pw): ok=False; msg.append("digit")
    if not re.search(r"[^A-Za-z0-9]", pw): ok=False; msg.append("special")
    return ok, "Need: " + ", ".join(msg) if msg else "Looks strong."