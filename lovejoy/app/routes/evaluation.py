import os
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app, session
from ..forms import RequestEvalForm
from ..security import (
    require_login,
    sanitize_comment,
    allowed_file,
    validate_image_bytes,
    random_filename,
)
from .. import db
from ..models import EvaluationRequest

bp = Blueprint("evaluation", __name__, url_prefix="")

@bp.route("/request", methods=["GET", "POST"])
@require_login
def request_evaluation():
    """
    Request an evaluation:
    - GET: render form.
    - POST: validate, store, confirm via email.
    args:
        None
    returns:
        Rendered template or redirect
    """
    form = RequestEvalForm()
    if form.validate_on_submit():
        comment = sanitize_comment(form.comment.data)
        contact_method = form.contact_method.data

        filename_on_disk = None
        file = request.files.get("photo")
        if file and file.filename:
            ext = allowed_file(file.filename)       # verify extension allow-list
            if not ext:
                flash("Only .jpg/.jpeg/.png allowed.", "error")
                return render_template("request_eval.html", form=form)

            blob = file.read()
            if not validate_image_bytes(blob):      # verify actual image content
                flash("Invalid image file.", "error")
                return render_template("request_eval.html", form=form)

            filename_on_disk = random_filename(ext) # avoid collisions / info-leaks
            with open(os.path.join(current_app.config["UPLOAD_FOLDER"], filename_on_disk), "wb") as f:
                f.write(blob)

        req = EvaluationRequest(
            user_id=session["user_id"],
            comment_sanitized=comment,
            contact_method=contact_method,
            photo_filename=filename_on_disk,
        )
        db.session.add(req)
        db.session.commit()

        # Confirmation email, print and append to outbox.txt
        from ..email_utils import send_console_email
        send_console_email(
            "Evaluation request received",
            session.get("user_email", "unknown@example.com"),
            f"Thanks! Your request ID is {req.id}. We'll review it shortly."
        )

        flash(f"Request submitted (ID {req.id}).", "info")
        return redirect(url_for("evaluation.my_requests"))

    return render_template("request_eval.html", form=form)


@bp.route("/my-requests")
@require_login
def my_requests():
    """
    View current user's evaluation requests.
    args:
        None
    returns:
        Rendered template
    """
    rows = (
        EvaluationRequest.query
        .filter_by(user_id=session["user_id"])
        .order_by(EvaluationRequest.created_at.desc())
        .all()
    )
    return render_template("my_requests.html", rows=rows)
