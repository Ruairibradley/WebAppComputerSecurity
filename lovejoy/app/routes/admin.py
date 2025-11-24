import os
from flask import Blueprint, render_template, request, abort, send_file, current_app
from ..security import admin_required
from ..models import EvaluationRequest

bp = Blueprint("admin", __name__, url_prefix="") # no prefix for simplicity

@bp.route("/admin/requests")
@admin_required
def admin_requests():
    """
    Admin view: list of evaluation requests with pagination.
    args:
        None
    returns:
        Rendered template
    """
    page = max(int(request.args.get("page", 1)), 1)
    q = EvaluationRequest.query.order_by(EvaluationRequest.created_at.desc())
    items = q.limit(25).offset((page - 1) * 25).all()
    return render_template("admin_requests.html", requests=items)

@bp.route("/uploads/<filename>")
@admin_required
def download_photo(filename):
    """
    Admin view: download uploaded photos by filenames.
    args:
        filename: str
    returns:
        File download response
    """
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], filename)
    if not os.path.isfile(path):
        abort(404)
    return send_file(path, as_attachment=True)
