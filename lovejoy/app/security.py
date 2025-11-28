import os
import re
import secrets
from functools import wraps
from io import BytesIO
from typing import Tuple

from flask import session, redirect, url_for, flash, current_app, abort
import bleach
from itsdangerous import URLSafeTimedSerializer

try:
    from PIL import Image
except Exception:
    Image = None # pillow optional at upload time


def require_login(fn):
    """ Require logged in user, protect endpoints.
    args:
        fn: decorated function
    returns:
        wrapped function
    """
    @wraps(fn)
    def _inner(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in.", "error")
            return redirect(url_for("auth.login"))
        return fn(*args, **kwargs)
    return _inner


def admin_required(fn):
    """Require admin user, protect endpoints.
    args:
        fn: decorated function
    returns:
        wrapped function"""
    @wraps(fn)
    def _inner(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in.", "error")
            return redirect(url_for("auth.login"))
        if not session.get("is_admin"):
            abort(403) # 403 forbidden access page - ie not admin
        return fn(*args, **kwargs)
    return _inner


def signer(secret: str) -> URLSafeTimedSerializer:
    """Create a URL-safe timed signer.
    args:
        secret: app secret key
    returns:
        URLSafeTimedSerializer instance"""
    return URLSafeTimedSerializer(secret, salt="lovejoy.sign")




def strong_password(pw: str) -> Tuple[bool, str]:
    """Check password strength. Strong = >=12 chars, upper, lower, digit, special.
    args:
        pw: password string
    returns:
        tuple(bool, str): (is_strong, hint)"""
    if not pw:
        return False, "Empty password."
    rules = [
        (len(pw) >= 12, ">=12 characters"),
        (re.search(r"[A-Z]", pw) is not None, "uppercase letter"),
        (re.search(r"[a-z]", pw) is not None, "lowercase letter"),
        (re.search(r"\d", pw) is not None, "digit"),
        (re.search(r"[^A-Za-z0-9]", pw) is not None, "special character"),
    ]
    ok = all(r for r, _ in rules)
    hint = " / ".join([txt for ok_, txt in rules if not ok_]) if not ok else "Looks strong."
    return ok, hint



def sanitize_comment(text: str) -> str:
    """Sanitize user comment input to prevent XSS.
    args:
        text: user input string
    returns:
        sanitized string"""
    return bleach.clean(text or "", tags=[], attributes={}, strip=True)




_ALLOWED_EXTS = {".jpg", ".jpeg", ".png"} #img file types allowed

def allowed_file(filename: str) -> str | None:
    """Check if file extension is allowed.
    args:
        filename: name of the file
    returns:
        allowed extension or None"""
    _, ext = os.path.splitext(filename or "")
    ext = ext.lower()
    return ext if ext in _ALLOWED_EXTS else None


def validate_image_bytes(blob: bytes) -> bool:
    """Validate image bytes.
    args:
        blob: file bytes
    returns:
        True if valid image, False otherwise"""
    if not blob:
        return False
    if Image is None:
        return blob.startswith(b"\xFF\xD8") or blob.startswith(b"\x89PNG\r\n\x1a\n")
    try:
        with Image.open(BytesIO(blob)) as im:
            im.verify()
        return True
    except Exception:
        return False


def strip_image_exif(img_bytes: bytes) -> bytes:
    """Strip EXIF metadata from image bytes.
    args:
        img_bytes: original image bytes
    returns:
        image bytes without EXIF metadata"""
    if Image is None:
        return img_bytes
    try:
        with Image.open(BytesIO(img_bytes)) as im:
            if im.mode in ("RGBA", "P"):
                im = im.convert("RGB")
            out = BytesIO()
            im.save(out, format="JPEG", quality=90, optimize=True)
            return out.getvalue()
    except Exception:
        return img_bytes


def random_filename(ext: str) -> str:
    """Generate a random filename with the given extension.
    args:
        ext: file extension (including dot)
    returns:
        random filename string"""
    return f"{secrets.token_urlsafe(16)}{ext}"
