# FILE: app/routes/twofa.py
# Adds: session rotation when enrol completes (session fixation defense).

import io
import qrcode
import pyotp
from flask import Blueprint, render_template, session, redirect, url_for, flash, send_file
from ..forms import TotpForm
from .. import db

bp = Blueprint("twofa", __name__, url_prefix="")

@bp.route("/enroll-2fa", methods=["GET", "POST"])
def enroll_2fa():
    """
    Pre-login 2FA enrolment; completes login after verifying a TOTP code.
    """
    from ..models import User

    pending_id = session.get("pending_user_id")
    if not pending_id:
        return redirect(url_for("auth.login"))

    user = db.session.get(User, pending_id)
    if not user:
        return redirect(url_for("auth.login"))

    if user.totp_secret:
        return redirect(url_for("auth.login_2fa"))

    secret = session.get("provision_secret") or pyotp.random_base32()
    session["provision_secret"] = secret

    form = TotpForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(secret)
        if totp.verify(form.totp.data, valid_window=1):
            user.totp_secret = secret
            db.session.commit()

            # rotate session on full auth
            session.clear()
            session["user_id"] = user.id
            session["user_email"] = user.email
            session["is_admin"] = bool(user.is_admin)

            flash("2FA enabled. Logged in.", "info")
            return redirect(url_for("main.index"))
        else:
            flash("Invalid code. Try again.", "error")

    return render_template("enroll_2fa.html", secret=secret, form=form)

@bp.route("/enroll-2fa/qrcode.png")
def enroll_qr():
    secret = session.get("provision_secret")
    if not session.get("pending_user_id") or not secret:
        return redirect(url_for("auth.login"))
    from ..models import User
    user = db.session.get(User, session["pending_user_id"])
    label = user.email if user else "user@example.com"
    uri = pyotp.TOTP(secret).provisioning_uri(name=label, issuer_name="Lovejoy")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG"); buf.seek(0)
    return send_file(buf, mimetype="image/png")
