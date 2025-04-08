from flask import Blueprint, render_template, current_app
from flask_login import login_required, current_user
from app.utils.decorators import permission_required, active_required

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return render_template('main/index.html')

@main_bp.route('/dashboard')
@login_required
@active_required
def dashboard():
    return render_template('main/dashboard.html')

@main_bp.route('/protected')
@login_required
@active_required
@permission_required(0x02)  # Nécessite une permission spécifique
def protected_page():
    return render_template('main/protected.html')

@main_bp.route('/admin')
@login_required
@active_required
@permission_required(0xff)  # Nécessite des permissions d'administrateur
def admin_page():
    return render_template('main/admin.html')

@main_bp.after_request
def add_security_headers(response):
    """Ajoute des en-têtes de sécurité à toutes les réponses du blueprint"""
    return response
