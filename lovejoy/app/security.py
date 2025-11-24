# app/security.py
# Minimal shared security helpers.
# WHY: add back admin_required (lost in the last patch).

import os
import re
import secrets
from functools import wraps
from io import BytesIO
from typing import Tuple

from flask import session, redirect, url_for, flash, current_app, abort
import bleach
from itsdangerous import URLSafeTimedSerializer

# Pillow is optional at import time
try:
    from PIL import Image
except Exception:
    Image = None


# ---------- Auth decorators ----------

def require_login(fn):
    """Require an authenticated session (WHY: protect private routes)."""
    @wraps(fn)
    def _inner(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in.", "error")
            return redirect(url_for("auth.login"))
        return fn(*args, **kwargs)
    return _inner


def admin_required(fn):
    """Require admin role (WHY: enforce least-privilege on admin endpoints)."""
    @wraps(fn)
    def _inner(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in.", "error")
            return redirect(url_for("auth.login"))
        if not session.get("is_admin"):
            # 403 instead of redirect so it's demonstrably forbidden.
            abort(403)
        return fn(*args, **kwargs)
    return _inner


# ---------- Token signer ----------

def signer(secret: str) -> URLSafeTimedSerializer:
    """Timed serializer for signed links (verify/reset)."""
    return URLSafeTimedSerializer(secret, salt="lovejoy.sign")


# ---------- Password policy ----------

def strong_password(pw: str) -> Tuple[bool, str]:
    """Policy: ≥12 chars, at least one upper/lower/digit/special."""
    if not pw:
        return False, "Empty password."
    rules = [
        (len(pw) >= 12, "≥12 characters"),
        (re.search(r"[A-Z]", pw) is not None, "uppercase letter"),
        (re.search(r"[a-z]", pw) is not None, "lowercase letter"),
        (re.search(r"\d", pw) is not None, "digit"),
        (re.search(r"[^A-Za-z0-9]", pw) is not None, "special character"),
    ]
    ok = all(r for r, _ in rules)
    hint = " / ".join([txt for ok_, txt in rules if not ok_]) if not ok else "Looks strong."
    return ok, hint


# ---------- Sanitisation ----------

def sanitize_comment(text: str) -> str:
    """Strip tags/attrs (WHY: kill stored XSS)."""
    return bleach.clean(text or "", tags=[], attributes={}, strip=True)


# ---------- File upload helpers ----------

_ALLOWED_EXTS = {".jpg", ".jpeg", ".png"}

def allowed_file(filename: str) -> str | None:
    """Allow-list extensions only."""
    _, ext = os.path.splitext(filename or "")
    ext = ext.lower()
    return ext if ext in _ALLOWED_EXTS else None


def validate_image_bytes(blob: bytes) -> bool:
    """Decode with Pillow or magic header check (WHY: stop disguised files)."""
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
    """Re-encode to drop EXIF/metadata (WHY: privacy)."""
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
    """Randomise filenames (WHY: avoid collisions/info leaks)."""
    return f"{secrets.token_urlsafe(16)}{ext}"
