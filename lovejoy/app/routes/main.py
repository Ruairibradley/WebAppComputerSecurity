from flask import Blueprint, render_template

bp = Blueprint("main", __name__)

@bp.route("/")
def index():
    """
    Minimal landing page.
    args:
        None
    returns:
        Rendered template
    """
    return render_template("index.html")