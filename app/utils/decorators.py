from functools import wraps
from flask import abort, request, current_app
from flask_login import current_user
import time
import hashlib
from app.services.user_service import UserService

def permission_required(permission):
    """
    décorateur vérifiant si l'utilisateur a la permission requise
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                abort(401)  # non authentifié
            if not current_user.has_permission(permission):
                abort(403)  # accès refusé
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    """
    décorateur vérifiant si l'utilisateur est un administrateur
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        if not current_user.is_administrator():
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def confirmed_required(f):
    """
    décorateur vérifiant si l'utilisateur a confirmé son compte
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        if not current_user.confirmed:
            abort(403, description="Compte non confirmé. Veuillez confirmer votre email.")
        return f(*args, **kwargs)
    return decorated_function

def active_required(f):
    """
    décorateur vérifiant si le compte de l'utilisateur est actif
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            abort(401)
        if not current_user.active:
            abort(403, description="Ce compte a été désactivé.")
        return f(*args, **kwargs)
    return decorated_function

def throttle(limit=100, per=60, key_func=None):
    """
    décorateur pour limiter le taux d'accès à une fonction
    """
    def decorator(f):
        # dictionnaire pour stocker les timestamps des appels par clé
        request_history = {}
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # fonction par défaut pour générer une clé basée sur l'ip et le chemin
            if key_func is None:
                key = f"{request.remote_addr}:{request.path}"
            else:
                key = key_func()
            
            # hasher la clé pour la confidentialité
            hashed_key = hashlib.md5(key.encode()).hexdigest()
            
            now = time.time()
            
            # initialiser l'historique si nécessaire
            if hashed_key not in request_history:
                request_history[hashed_key] = []
            
            # nettoyer les anciennes entrées
            request_history[hashed_key] = [t for t in request_history[hashed_key] if now - t < per]
            
            # vérifier la limite
            if len(request_history[hashed_key]) >= limit:
                abort(429, description="Trop de requêtes. Veuillez réessayer plus tard.")
            
            # enregistrer cette requête
            request_history[hashed_key].append(now)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def verified_client_required(f):
    """
    décorateur pour vérifier si le client est un navigateur légitime 
    et non un script d'automatisation ou un bot
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_agent = request.headers.get('User-Agent', '').lower()
        
        # vérifier les signes d'un bot ou d'un scraper
        suspicious_agents = ['bot', 'crawl', 'spider', 'scrape', 'headless', 'phantomjs', 'selenium']
        
        if any(agent in user_agent for agent in suspicious_agents):
            current_app.logger.warning(f"suspicious user agent detected: {user_agent}")
            abort(403)
        
        # vérifier les en-têtes attendus d'un navigateur normal
        if not request.headers.get('Accept') or not request.headers.get('Accept-Language'):
            current_app.logger.warning("missing standard browser headers")
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function
