from flask import Blueprint

snippets_bp = Blueprint('snippets', __name__, url_prefix='/snippets')

from app.snippets import routes
