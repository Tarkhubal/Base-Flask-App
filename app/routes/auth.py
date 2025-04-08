from flask import Blueprint, render_template, redirect, url_for, flash, request, session, abort
from flask_login import login_user, logout_user, login_required, current_user
from urllib.parse import urlparse  # remplacer werkzeug.urls par urllib.parse
from app import db, limiter
from app.models.user import User
from app.services.user_service import UserService
from app.utils.decorators import throttle, verified_client_required
from datetime import datetime
import uuid

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10/minute")
@verified_client_required
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        # vérification csrf (déjà gérée par flask-wtf ou le middleware csrf)
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember') == 'on'
        
        user = UserService.get_by_username(username)
        
        # vérification si le compte est verrouillé
        if user and UserService.is_account_locked(user):
            flash("Compte temporairement verrouillé suite à plusieurs tentatives de connexion échouées.", "danger")
            return render_template('auth/login.html')
        
        # vérification des identifiants
        if user and user.verify_password(password):
            # si le compte n'est pas actif
            if not user.active:
                flash("Ce compte a été désactivé.", "danger")
                return render_template('auth/login.html')
            
            # connexion réussie
            UserService.update_login_attempt(user, success=True)
            login_user(user, remember=remember)
            
            # générer un nouvel id de session pour éviter les attaques de fixation de session
            session.regenerate()
            
            next_page = request.args.get('next')
            if not next_page or urlparse(next_page).netloc != '':  # utiliser urlparse de urllib.parse
                next_page = url_for('main.index')
                
            return redirect(next_page)
        
        # connexion échouée
        if user:
            UserService.update_login_attempt(user, success=False)
        
        flash("Nom d'utilisateur ou mot de passe incorrect.", "danger")
        return render_template('auth/login.html')
    
    return render_template('auth/login.html')

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Vous avez été déconnecté.", "success")
    return redirect(url_for('main.index'))

@auth_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("5/hour")
@verified_client_required
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        
        # Validation de base côté serveur
        if not username or not email or not password:
            flash("Tous les champs sont obligatoires", "danger")
            return render_template('auth/register.html')
            
        if password != password_confirm:
            flash("Les mots de passe ne correspondent pas", "danger")
            return render_template('auth/register.html')
        
        # Force du mot de passe (à implémenter plus en détail selon les besoins)
        if len(password) < 8:
            flash("Le mot de passe doit contenir au moins 8 caractères", "danger")
            return render_template('auth/register.html')
            
        # Création de l'utilisateur
        user, message = UserService.create_user(username, email, password)
        
        if user:
            flash(message, "success")
            # Ici, on pourrait envoyer un email de confirmation
            # Pour l'exemple, on confirme directement le compte
            UserService.confirm_user(user)
            return redirect(url_for('auth.login'))
        else:
            flash(message, "danger")
            return render_template('auth/register.html')
    
    return render_template('auth/register.html')

@auth_bp.route('/profile')
@login_required
def profile():
    return render_template('auth/profile.html')
