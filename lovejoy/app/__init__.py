import os
import secrets
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import CSRFProtect

db = SQLAlchemy() # Database instance - SQLAlchemy ORM prevent SQL injection***
csrf = CSRFProtect() # CSRF protection for forms

def create_app():
    """Factory to create and configure the Flask application. 
    args:
        None
    returns:
        Flask app instance"""
    from .config import load_config
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.update(load_config())

    db.init_app(app)
    csrf.init_app(app)

    @app.after_request
    def set_security_headers(resp):
        """Set security-related HTTP headers on each response.
        args:
            resp: Flask response object
        returns:
            Modified Flask response object with security headers set."""
        
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "img-src 'self' data:; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'; "
            "form-action 'self'"
        )
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-XSS-Protection"] = "0"
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp # mitigate various attacks / vulnerabilities

    @app.errorhandler(403)
    def forbidden(e):
        """ Render custom 403 Forbidden error page.
        args:
            e: Exception object
        returns:
            Rendered 403 error page with status code 403."""
        return render_template("403.html"), 403 # non admin user tries to access admin page for example = forbidden

    @app.context_processor
    def expose_security_flags():
        """Expose security-related configuration flags to templates.
        args:
            None
        returns:
            Dictionary of security flags for template context."""
        max_bytes = int(app.config.get("MAX_CONTENT_LENGTH", 0))
        return {"SEC_FLAGS": {"UploadLimitMB": max_bytes // (1024 * 1024) if max_bytes else 0}}

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    from .routes.main import bp as main_bp
    from .routes.auth import bp as auth_bp
    from .routes.twofa import bp as twofa_bp
    from .routes.evaluation import bp as eval_bp
    from .routes.admin import bp as admin_bp
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(twofa_bp)
    app.register_blueprint(eval_bp)
    app.register_blueprint(admin_bp)

    return app


def _ensure_schema(app: Flask) -> None:
    """Ensure the database schema is up to date, adding missing columns if necessary.
    args:
        app: Flask application instance
    returns:
        None"""
    from sqlalchemy import inspect, text
    with app.app_context():
        insp = inspect(db.engine)
        cols = {c['name'] for c in insp.get_columns('user')}
        with db.engine.begin() as conn:
            if "lock_count" not in cols:
                conn.execute(text("ALTER TABLE user ADD COLUMN lock_count INTEGER DEFAULT 0"))
            if "email_otp_code" not in cols:
                conn.execute(text("ALTER TABLE user ADD COLUMN email_otp_code VARCHAR(6)"))
            if "email_otp_expires" not in cols:
                conn.execute(text("ALTER TABLE user ADD COLUMN email_otp_expires DATETIME"))


def bootstrap(app):
    """Bootstrap the database and create an initial admin user if none exists.
    args:
        app: Flask application instance
    returns:
        None"""
    from .models import User
    with app.app_context():
        db.create_all()
        _ensure_schema(app)
        if not User.query.filter_by(is_admin=True).first():
            admin_email = "admin@example.com"
            admin_pw = "Admin#" + secrets.token_urlsafe(6)
            admin = User(
                email=admin_email,
                name="Admin",
                phone="+440000000000",
                is_admin=True,
                email_verified=True,
            )
            admin.set_password(admin_pw)
            db.session.add(admin)
            db.session.commit()
            print(f"[Seed Admin] {admin_email} / {admin_pw}")
