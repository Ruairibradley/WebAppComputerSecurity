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
    Pre-login 2FA enrolment.
    - Requires session['pending_user_id'] (set after password verification).
    - Generates a temporary secret in session for enrol.
    - Verifies a TOTP code; on success, persists secret and completes login.
    args:
        None
    returns:
        Rendered template or redirect
    """
    from ..models import User

    pending_id = session.get("pending_user_id")
    if not pending_id:
        return redirect(url_for("auth.login"))

    user = db.session.get(User, pending_id)
    if not user:
        return redirect(url_for("auth.login"))

    # If already enrolled, go straight to the 2FA code step.
    if user.totp_secret:
        return redirect(url_for("auth.login_2fa"))

    # Keep a temporary secret in session until a valid code is entered.
    secret = session.get("provision_secret") or pyotp.random_base32()
    session["provision_secret"] = secret

    form = TotpForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(secret)
        # Verify with a 30s window before/after to allow for clock skew.
        if totp.verify(form.totp.data, valid_window=1):
            # Persist TOTP secret to the user record
            user.totp_secret = secret
            db.session.commit()

            # Clear temp + finish login
            session.pop("provision_secret", None)
            session["user_id"] = user.id
            session["user_email"] = user.email
            session["is_admin"] = bool(user.is_admin)
            session.pop("pending_user_id", None)

            flash("2FA enabled. Logged in.", "info")
            return redirect(url_for("main.index"))
        else:
            flash("Invalid code. Try again.", "error")

    return render_template("enroll_2fa.html", secret=secret, form=form)


@bp.route("/enroll-2fa/qrcode.png")
def enroll_qr():
    """
    QR code for pre-login enrolment.
    Uses the temporary session secret to render a PNG QR for authenticator apps.
    args:
        None
    returns:
        PNG image file
    """
    secret = session.get("provision_secret")
    if not session.get("pending_user_id") or not secret:
        return redirect(url_for("auth.login"))

    from ..models import User
    user = db.session.get(User, session["pending_user_id"])

    label = user.email if user else "user@example.com"
    uri = pyotp.TOTP(secret).provisioning_uri(name=label, issuer_name="Lovejoy")

    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")
