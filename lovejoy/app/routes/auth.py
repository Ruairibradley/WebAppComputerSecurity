import datetime as dt
import random
from flask import Blueprint, render_template, redirect, url_for, flash, session, current_app, request
from email_validator import validate_email, EmailNotValidError
from itsdangerous import BadSignature, SignatureExpired
from .. import db
from ..models import User
from ..forms import RegisterForm, LoginForm, ForgotForm, ResetForm, TotpForm
from ..security import signer, strong_password
from ..email_utils import send_console_email
from ..ratelimit import allow_action

bp = Blueprint("auth", __name__, url_prefix="") 

# helpers
def _client_ip() -> str:
    """
    Get client IP considering possible reverse proxy.
    args:
        None
    returns:
        str
    """
    return request.headers.get("X-Real-IP") or request.remote_addr or "0.0.0.0"

def _rate_key(route: str, email: str = "") -> str:
    """
    Rate limit key per route + IP + (optional) account.
    args;"""
    ip = _client_ip()
    return f"{route}|ip:{ip}|acct:{(email or '').lower()}"


# routes 
@bp.route("/register", methods=["GET", "POST"])
def register():
    """
    Public registration:
    - Validates email format + uniqueness.
    - Enforces strong password policy.
    - Sends verification email (console + outbox.txt).
    args:
        None
    returns:
        Rendered template or redirect
    """
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
        send_console_email("Verify your email", user.email, f"Click to verify: {link}")
        flash("Account created. Check terminal or outbox.txt for your verification link.", "info")
        return redirect(url_for("auth.login"))

    return render_template("register.html", form=form, strength_hint=strength_hint)

@bp.route("/verify/<token>")
def verify_email(token):
    try:
        data = signer(current_app.config["SECRET_KEY"]).loads(token, max_age=3600)
    except SignatureExpired:
        return render_template("verify_email.html", message="Verification link expired.")
    except BadSignature:
        return render_template("verify_email.html", message="Invalid verification link.")

    user = db.session.get(User, data.get("uid"))
    if not user or user.email != data.get("email"):
        return render_template("verify_email.html", message="Invalid verification link.")
    if user.email_verified:
        return render_template("verify_email.html", message="Email already verified.")

    user.email_verified = True
    db.session.commit()
    return render_template("verify_email.html", message="Email verified. You can log in now.")

@bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("main.index"))

    # rate limit per ip and account
    if request.method == "POST":
        allowed, retry = allow_action(_rate_key("login", request.form.get("email","")), limit=5, per_seconds=60)
        if not allowed:
            flash(f"Too many login attempts. Try again in {retry}s.", "error")
            return render_template("login.html", form=LoginForm(), show_captcha=False, captcha_a=0, captcha_b=0)

    form = LoginForm()

    # failure counter, 3 = captcha, 5 = lockout
    fail_cnt = int(session.get("fail_cnt", 0))
    show_captcha = fail_cnt >= 3

    # Prepare math CAPTCHA when active. Keep stable for one POST.
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

        # User-level lockout check (progressive each failed attempt)
        if user and user.is_locked():
            until = user.lock_until.strftime("%H:%M:%S")
            flash(f"Account locked. Try after {until} (UTC).", "error")
            return render_template("login.html", form=form, show_captcha=show_captcha, captcha_a=captcha_a, captcha_b=captcha_b)

        # CAPTCHA gate when active
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
                return render_template(
                    "login.html", form=form, show_captcha=True,
                    captcha_a=session["captcha_a"], captcha_b=session["captcha_b"]
                )

        # Password check
        if not user or not user.verify_password(form.password.data):
            session["fail_cnt"] = fail_cnt + 1
            if user:
                user.failed_logins = (user.failed_logins or 0) + 1
                # Progressive lock on 5th failure
                if user.failed_logins >= 5:
                    minutes = user.lock_progressive(base_minutes=15, cap_hours=24)
                    db.session.commit()
                    send_console_email(
                        "Account locked due to failed logins",
                        user.email,
                        f"Your account was locked for {minutes} minutes due to repeated failed logins. If this wasn't you, reset your password."
                    )
                else:
                    db.session.commit()

            if session["fail_cnt"] == 3:
                flash("3 login attempts failed — CAPTCHA required.", "error")
                session["captcha_notice_shown"] = True
                session["captcha_a"] = random.randint(1, 9)
                session["captcha_b"] = random.randint(1, 9)

            return render_template(
                "login.html",
                form=form,
                show_captcha=(session.get("fail_cnt", 0) >= 3),
                captcha_a=session.get("captcha_a", 0),
                captcha_b=session.get("captcha_b", 0),
            )

        # Must verify email first
        if not user.email_verified:
            flash("Please verify your email first. Use 'Resend verification' if needed.", "error")
            return render_template("login.html", form=form, show_captcha=show_captcha, captcha_a=captcha_a, captcha_b=captcha_b)

        # Success = clear session counters and proceed to 2FA
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

        # Not expected since ENFORCE_2FA is True
        session["user_id"] = user.id
        session["user_email"] = user.email
        session["is_admin"] = bool(user.is_admin)
        flash("Logged in.", "info")
        return redirect(url_for("main.index"))

    return render_template("login.html", form=form, show_captcha=show_captcha, captcha_a=captcha_a, captcha_b=captcha_b)

@bp.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    """
    TOTP-based 2FA:
    - GET: render form.
    - POST: verify TOTP code; on success finalise login.
    args:
        None
    returns: 
        Rendered template or redirect"""
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
        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(form.totp.data, valid_window=1):
            session.pop("pending_user_id", None)
            session["user_id"] = user.id
            session["user_email"] = user.email
            session["is_admin"] = bool(user.is_admin)
            flash("2FA passed. Logged in.", "info")
            return redirect(url_for("main.index"))
        flash("Invalid 2FA code.", "error")

    return render_template("login_2fa.html", form=form)

@bp.route("/login/2fa/email", methods=["GET", "POST"])
def login_2fa_email():
    """
    Email-based 2FA fallback:
    - GET: rate-limited send of 6-digit code (10 min TTL) + render form.
    - POST: verify code; on success finalise login.
    args:
        None
    returns:
        Rendered template or redirect
    """
    pending_id = session.get("pending_user_id")
    if not pending_id:
        return redirect(url_for("auth.login"))

    user = db.session.get(User, pending_id)
    if not user:
        return redirect(url_for("auth.login"))

    # Rate limit sending per ip and acc
    if request.method == "GET":
        allowed, retry = allow_action(_rate_key("2fa_email", user.email), limit=3, per_seconds=300)
        if not allowed:
            flash(f"Too many code requests. Try again in {retry}s.", "error")
        else:
            code = f"{random.randint(0, 999999):06d}"
            user.email_otp_code = code
            user.email_otp_expires = dt.datetime.utcnow() + dt.timedelta(minutes=10)
            db.session.commit()
            send_console_email("Your login code", user.email, f"Use this code to complete login: {code}\n(Valid for 10 minutes)")

    form = TotpForm()  # 6-digit validator
    if form.validate_on_submit():
        code = form.totp.data.strip()
        if user.email_otp_code and user.email_otp_expires and dt.datetime.utcnow() < user.email_otp_expires:
            if code == user.email_otp_code:
                user.email_otp_code = None
                user.email_otp_expires = None
                db.session.commit()
                session.pop("pending_user_id", None)
                session["user_id"] = user.id
                session["user_email"] = user.email
                session["is_admin"] = bool(user.is_admin)
                flash("Email 2FA passed. Logged in.", "info")
                return redirect(url_for("main.index"))
        flash("Invalid or expired email code.", "error")

    return render_template("login_2fa_email.html", form=form)

@bp.route("/logout")
def logout():
    """
    Log out the current user.
    args:
        None
    returns:
        Redirect to main index
    """
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("main.index"))

@bp.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    """
    Public password reset request:
    - Rate-limited to prevent abuse.
    - Sends reset email (console + outbox.txt) if account exists.
    args:
        None
    returns:
        Rendered template or redirect"""
    if session.get("user_id"):
        return redirect(url_for("main.index"))

    # Rate limit
    if request.method == "POST":
        allowed, retry = allow_action(_rate_key("forgot", request.form.get("email","")), limit=5, per_seconds=600)
        if not allowed:
            flash(f"Too many reset requests. Try again in {retry}s.", "error")
            return redirect(url_for("auth.login"))

    form = ForgotForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        user = User.query.filter_by(email=email).first()
        if user:
            token = signer(current_app.config["SECRET_KEY"]).dumps({"uid": user.id, "email": user.email, "purpose": "reset"})
            link = url_for("auth.reset_password", token=token, _external=True)
            send_console_email("Password reset", user.email, f"Reset link: {link}\n(Expires in 1 hour)")
        flash("If the email exists, a link has been sent.", "info")
        return redirect(url_for("auth.login"))
    return render_template("forgot_password.html", form=form)

@bp.route("/resend-verification", methods=["GET", "POST"])
def resend_verification():
    """
    Public email verification resend:
    - Rate-limited to prevent abuse.
    - Sends verification email (console + outbox.txt) if account exists and unverified.
    args:
        None
    returns:
        Rendered template or redirect"""
    if session.get("user_id"):
        return redirect(url_for("main.index"))

    # Rate limit
    if request.method == "POST":
        allowed, retry = allow_action(_rate_key("resend", request.form.get("email","")), limit=5, per_seconds=600)
        if not allowed:
            flash(f"Too many requests. Try again in {retry}s.", "error")
            return redirect(url_for("auth.login"))

    form = ForgotForm()
    if form.validate_on_submit():
        email = form.email.data.lower().strip()
        user = User.query.filter_by(email=email).first()
        if user and not user.email_verified:
            token = signer(current_app.config["SECRET_KEY"]).dumps({"uid": user.id, "email": user.email})
            link = url_for("auth.verify_email", token=token, _external=True)
            send_console_email("Verify your email (resend)", user.email, f"Click to verify: {link}")
        flash("If the account exists and is unverified, a link has been sent.", "info")
        return redirect(url_for("auth.login"))
    return render_template("forgot_password.html", form=form)

@bp.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    """
    Public password reset via emailed link:
    - Validates token (1 hour TTL).
    - Enforces strong password policy.
    args:
        token: str
    returns:
        Rendered template or redirect
        """
    form = ResetForm()
    strength_hint = None
    try:
        data = signer(current_app.config["SECRET_KEY"]).loads(token, max_age=3600)
    except SignatureExpired:
        flash("Reset link expired.", "error"); return redirect(url_for("auth.login"))
    except BadSignature:
        flash("Invalid reset link.", "error"); return redirect(url_for("auth.login"))
    if data.get("purpose") != "reset":
        flash("Invalid reset link.", "error"); return redirect(url_for("auth.login"))

    user = db.session.get(User, data.get("uid"))
    if not user or user.email != data.get("email"):
        flash("Invalid reset link.", "error"); return redirect(url_for("auth.login"))

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
