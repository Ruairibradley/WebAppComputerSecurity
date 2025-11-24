# FILE: app/routes/admin.py
# Changes: safer download route by request ID (no raw filename), keeps admin_required.

import os
from flask import Blueprint, render_template, abort, send_file, current_app
from ..security import admin_required
from ..models import EvaluationRequest

bp = Blueprint("admin", __name__, url_prefix="")

@bp.route("/admin/requests")
@admin_required
def admin_requests():
    rows = EvaluationRequest.query.order_by(EvaluationRequest.created_at.desc()).limit(100).all()
    return render_template("admin_requests.html", requests=rows)

@bp.route("/admin/request/<int:rid>/photo")
@admin_required
def request_photo(rid: int):
    req = EvaluationRequest.query.get_or_404(rid)
    if not req.photo_filename:
        abort(404)
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], req.photo_filename)
    if not os.path.isfile(path):
        abort(404)
    # why: non-public storage; served only to admins via this guarded route
    return send_file(path, as_attachment=True)
