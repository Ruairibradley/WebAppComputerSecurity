import datetime as dt
import random
import time
from flask import Blueprint, render_template, redirect, url_for, flash, session, current_app, request
from email_validator import validate_email, EmailNotValidError
from itsdangerous import BadSignature, SignatureExpired

from .. import db
from ..models import User
from ..forms import RegisterForm, LoginForm, ForgotForm, ResetForm, TotpForm, DummyForm
from ..security import signer, strong_password
from ..email_utils import send_console_email  
from ..ratelimit import allow_action

bp = Blueprint("auth", __name__, url_prefix="")

@bp.route("/register", methods=["GET", "POST"])
def register():
    """User registration with policy enforcement + signed verify link."""
    if session.get("user_id"):
        return redirect(url_for("main.index"))

    form = RegisterForm()
    strength_hint = None

    if form.validate_on_submit():
        try:
            email = validate_email(form.email.data).email.lower()
        except EmailNotValidError as e:
            flash(str(e), "error")
            return render_template("register.html", form=form, strength_hint=strength_hint)

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "error")
            return render_template("register.html", form=form, strength_hint=strength_hint)

        ok, hint = strong_password(form.password.data)
        strength_hint = hint
        if not ok:
            flash("Password does not meet policy.", "error")
            return render_template("register.html", form=form, strength_hint=strength_hint)

        user = User(
            email=email,
            name=form.name.data.strip(),
            phone=form.phone.data.strip(),
            email_verified=False,
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        token = signer(current_app.config["SECRET_KEY"]).dumps({"uid": user.id, "email": user.email})
        link = url_for("auth.verify_email", token=token, _external=True)
        send_console_email(
            "Verify your email",
            user.email,
            f"Open the verification link below, then click the 'Confirm email' button on the page:\n\n{link}\n\n"
            "This link expires in 1 hour."
        )
        flash("Account created. Check the terminal or Outbox/Mailtrap for your verification link.", "info")
        return redirect(url_for("auth.login"))

    return render_template("register.html", form=form, strength_hint=strength_hint)


@bp.route("/verify/<token>", methods=["GET", "POST"])
def verify_email(token):
    """
    Two-step email verification to prevent auto-verification by link scanners.
    - GET: validate token and show a CSRF-protected confirm button (no state change).
    - POST: validate token again and flip email_verified=True.
    """
    form = DummyForm()

    try:
        data = signer(current_app.config["SECRET_KEY"]).loads(token, max_age=3600)
    except SignatureExpired:
        return render_template("verify_email.html", error="Verification link expired.", form=None)
    except BadSignature:
        return render_template("verify_email.html", error="Invalid verification link.", form=None)

    user = db.session.get(User, data.get("uid"))
    if not user or user.email != data.get("email"):
        return render_template("verify_email.html", error="Invalid verification link.", form=None)

    if user.email_verified:
        return render_template("verify_email.html", success="Email already verified. You can log in.", form=None)

    if request.method == "POST" and form.validate_on_submit():
        user.email_verified = True
        db.session.commit()
        return render_template("verify_email.html", success="Email verified. You can log in now.", form=None)

    return render_template("verify_email.html", form=form, email=user.email)


@bp.route("/login", methods=["GET", "POST"])
def login():
    """Login with rate limit, CAPTCHA after 3 fails, progressive lockout, 2FA gate."""
    if session.get("user_id"):
        return redirect(url_for("main.index"))

    # IP rate limit: 10/min
    ok, retry = allow_action(f"login:{request.remote_addr}", limit=10, per_seconds=60)
    if not ok:
        form = LoginForm()
        flash(f"Too many attempts. Try again in {retry}s.", "error")
        return render_template("login.html", form=form, show_captcha=False, captcha_a=0, captcha_b=0)

    form = LoginForm()
    fail_cnt = int(session.get("fail_cnt", 0))
    show_captcha = fail_cnt >= 3

    if show_captcha:
        if request.method == "GET" or "captcha_a" not in session or "captcha_b" not in session:
            session["captcha_a"] = random.randint(1, 9)
            session["captcha_b"] = random.randint(1, 9)
        if not session.get("captcha_notice_shown"):
            flash(f"{fail_cnt} login attempts failed — CAPTCHA required.", "error")
            session["captcha_notice_shown"] = True
    else:
        session.pop("captcha_a", None)
        session.pop("captcha_b", None)
        session.pop("captcha_notice_shown", None)

    captcha_a = session.get("captcha_a", 0)
    captcha_b = session.get("captcha_b", 0)

    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        user = User.query.filter_by(email=email).first()

        # Locked gate
        if user and user.is_locked():
            until = user.lock_until.strftime("%H:%M:%S")
            flash(f"Account locked. Try after {until} (UTC).", "error")
            time.sleep(random.uniform(0.10, 0.30))  # jitter
            return render_template("login.html", form=form, show_captcha=show_captcha, captcha_a=captcha_a, captcha_b=captcha_b)

        # CAPTCHA check (if shown)
        if show_captcha:
            try:
                answer = int((form.captcha.data or "").strip())
            except ValueError:
                answer = -1
            expected = captcha_a + captcha_b
            if answer != expected:
                session["fail_cnt"] = fail_cnt + 1
                session["captcha_a"] = random.randint(1, 9)
                session["captcha_b"] = random.randint(1, 9)
                flash("CAPTCHA incorrect.", "error")
                time.sleep(random.uniform(0.10, 0.30))  # jitter
                return render_template("login.html", form=form, show_captcha=True, captcha_a=session["captcha_a"], captcha_b=session["captcha_b"])

        # Password check
        if not user or not user.verify_password(form.password.data):
            session["fail_cnt"] = fail_cnt + 1
            if user:
                user.failed_logins = (user.failed_logins or 0) + 1
                if user.failed_logins >= 5:
                    minutes = user.lock_progressive(base_minutes=15, cap_hours=24)
                    db.session.commit()
                    send_console_email(
                        "Account locked due to failed logins",
                        user.email,
                        f"Your account was locked for {minutes} minutes due to repeated failed logins. "
                        f"If this wasn't you, please reset your password."
                    )
                else:
                    db.session.commit()

            if session["fail_cnt"] == 3:
                flash("3 login attempts failed — CAPTCHA required.", "error")
                session["captcha_notice_shown"] = True
                session["captcha_a"] = random.randint(1, 9)
                session["captcha_b"] = random.randint(1, 9)

            time.sleep(random.uniform(0.10, 0.30))  # jitter
            return render_template(
                "login.html",
                form=form,
                show_captcha=(session.get("fail_cnt", 0) >= 3),
                captcha_a=session.get("captcha_a", 0),
                captcha_b=session.get("captcha_b", 0),
            )

        if not user.email_verified:
            flash("Please verify your email first. Use 'Resend verification' if needed.", "error")
            time.sleep(random.uniform(0.10, 0.30))  # jitter
            return render_template("login.html", form=form, show_captcha=show_captcha, captcha_a=captcha_a, captcha_b=captcha_b)

        # Success: clear counters; continue to 2FA
        user.failed_logins = 0
        user.lock_until = None
        user.lock_count = 0
        db.session.commit()
        for k in ("fail_cnt", "captcha_a", "captcha_b", "captcha_notice_shown"):
            session.pop(k, None)

        session["pending_user_id"] = user.id
        if user.totp_secret:
            return redirect(url_for("auth.login_2fa"))
        if current_app.config.get("ENFORCE_2FA", True):
            return redirect(url_for("twofa.enroll_2fa"))

        # (fallback) complete session if 2FA not enforced
        session.clear()
        session["user_id"] = user.id
        session["user_email"] = user.email
        session["is_admin"] = bool(user.is_admin)
        flash("Logged in.", "info")
        return redirect(url_for("main.index"))

    return render_template("login.html", form=form, show_captcha=show_captcha, captcha_a=captcha_a, captcha_b=captcha_b)


@bp.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    """TOTP 2FA step after password and email verification."""
    from ..forms import TotpForm
    from ..models import User
    import pyotp

    pending_id = session.get("pending_user_id")
    if not pending_id:
        return redirect(url_for("auth.login"))

    user = db.session.get(User, pending_id)
    if not user or not user.totp_secret:
        return redirect(url_for("auth.login"))

    form = TotpForm()
    if form.validate_on_submit():
        code = form.totp.data.strip()
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(code, valid_window=1):
            # rotate session on full auth (fixation defence)
            session.clear()
            session["user_id"] = user.id
            session["user_email"] = user.email
            session["is_admin"] = bool(user.is_admin)
            flash("2FA passed. Logged in.", "info")
            return redirect(url_for("main.index"))

        flash("Invalid 2FA code.", "error")

    return render_template("login_2fa.html", form=form)


@bp.route("/login/2fa/email", methods=["GET", "POST"])
def login_2fa_email():
    """Email-based 2FA fallback with 10-minute OTP TTL."""
    pending_id = session.get("pending_user_id")
    if not pending_id:
        return redirect(url_for("auth.login"))

    user = db.session.get(User, pending_id)
    if not user:
        return redirect(url_for("auth.login"))

    # On GET, issue a 6-digit OTP valid for 10 min
    if request.method == "GET":
        code = f"{random.randint(0, 999999):06d}"
        user.email_otp_code = code
        user.email_otp_expires = dt.datetime.utcnow() + dt.timedelta(minutes=10)
        db.session.commit()
        send_console_email("Your login code", user.email, f"Use this 6-digit code to complete login: {code}\n(Valid for 10 minutes)")

    form = TotpForm()
    if form.validate_on_submit():
        code = form.totp.data.strip()
        if user.email_otp_code and user.email_otp_expires and dt.datetime.utcnow() < user.email_otp_expires:
            if code == user.email_otp_code:
                user.email_otp_code = None
                user.email_otp_expires = None
                db.session.commit()
                # rotate session on full auth
                session.clear()
                session["user_id"] = user.id
                session["user_email"] = user.email
                session["is_admin"] = bool(user.is_admin)
                flash("Email 2FA passed. Logged in.", "info")
                return redirect(url_for("main.index"))
        flash("Invalid or expired email code.", "error")

    return render_template("login_2fa_email.html", form=form)


@bp.route("/logout", methods=["POST"])
def logout():
    """POST-only logout (CSRF-protected)."""
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("main.index"))


@bp.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    """Non-enumerating reset request with IP rate limit."""
    if session.get("user_id"):
        return redirect(url_for("main.index"))

    ok, retry = allow_action(f"forgot:{request.remote_addr}", limit=5, per_seconds=60)
    if not ok:
        form = ForgotForm()
        flash(f"Too many requests. Try again in {retry}s.", "error")
        return render_template("forgot_password.html", form=form)

    form = ForgotForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        user = User.query.filter_by(email=email).first()
        if user:
            token = signer(current_app.config["SECRET_KEY"]).dumps({"uid": user.id, "email": user.email, "purpose": "reset"})
            link = url_for("auth.reset_password", token=token, _external=True)
            send_console_email("Password reset", user.email, f"Use the link below to reset your password (expires in 1 hour):\n\n{link}")
        flash("If the email exists, a link has been sent.", "info")
        return redirect(url_for("auth.login"))
    return render_template("forgot_password.html", form=form)


@bp.route("/resend-verification", methods=["GET", "POST"])
def resend_verification():
    """Non-enumerating resend flow with IP rate limit."""
    if session.get("user_id"):
        return redirect(url_for("main.index"))

    ok, retry = allow_action(f"resend:{request.remote_addr}", limit=5, per_seconds=60)
    if not ok:
        form = ForgotForm()
        flash(f"Too many requests. Try again in {retry}s.", "error")
        return render_template("forgot_password.html", form=form)

    form = ForgotForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        user = User.query.filter_by(email=email).first()
        if user and not user.email_verified:
            token = signer(current_app.config["SECRET_KEY"]).dumps({"uid": user.id, "email": user.email})
            link = url_for("auth.verify_email", token=token, _external=True)
            send_console_email(
                "Verify your email (resend)",
                user.email,
                f"Open the verification link below, then click the 'Confirm email' button on the page:\n\n{link}\n\n"
                "This link expires in 1 hour."
            )
        flash("If the account exists and is unverified, a link has been sent.", "info")
        return redirect(url_for("auth.login"))
    return render_template("forgot_password.html", form=form)


@bp.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    """Password reset with token TTL + policy + Argon2 store."""
    form = ResetForm()
    strength_hint = None
    try:
        data = signer(current_app.config["SECRET_KEY"]).loads(token, max_age=3600)
    except SignatureExpired:
        flash("Reset link expired.", "error")
        return redirect(url_for("auth.login"))
    except BadSignature:
        flash("Invalid reset link.", "error")
        return redirect(url_for("auth.login"))
    if data.get("purpose") != "reset":
        flash("Invalid reset link.", "error")
        return redirect(url_for("auth.login"))

    user = db.session.get(User, data.get("uid"))
    if not user or user.email != data.get("email"):
        flash("Invalid reset link.", "error")
        return redirect(url_for("auth.login"))

    if form.validate_on_submit():
        ok, hint = strong_password(form.password.data)
        strength_hint = hint
        if not ok:
            flash("Password does not meet policy.", "error")
            return render_template("reset_password.html", form=form, strength_hint=strength_hint)

        user.set_password(form.password.data)
        db.session.commit()
        flash("Password updated. Please log in.", "info")
        return redirect(url_for("auth.login"))

    return render_template("reset_password.html", form=form, strength_hint=strength_hint)
