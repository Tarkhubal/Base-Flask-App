from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, current_user
from flask_jwt_extended import JWTManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman

from config import config

# initialisation des extensions sans l'app
db = SQLAlchemy()
migrate = Migrate()
bcrypt = Bcrypt()
login_manager = LoginManager()
jwt = JWTManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)

def create_app(config_name='default'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    
    # initialisation des extensions avec l'app
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    login_manager.init_app(app)
    jwt.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    
    # configuration du login_manager
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Veuillez vous connecter pour accéder à cette page.'
    login_manager.login_message_category = 'info'
    login_manager.session_protection = 'strong'
    
    # application des en-têtes de sécurité avec talisman
    csp = app.config['SECURITY_HEADERS'].get('Content-Security-Policy', None)
    Talisman(app,
             content_security_policy=csp,
             content_security_policy_nonce_in=['script-src'],
             force_https=app.config['ENV'] != 'development',
             session_cookie_secure=app.config['SESSION_COOKIE_SECURE'],
             strict_transport_security=True)
    
    # middleware anti-ddos et anti-scraping
    @app.after_request
    def apply_security_headers(response):
        for header, value in app.config['SECURITY_HEADERS'].items():
            if header != 'Content-Security-Policy':  # déjà géré par talisman
                response.headers[header] = value
        
        # anti-scraping headers
        response.headers['X-Robots-Tag'] = 'noindex, nofollow'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        return response
    
    @app.context_processor
    def inject_user():
        return dict(current_user=current_user)
    
    # importation et enregistrement des blueprints
    from app.routes.main import main_bp
    from app.routes.auth import auth_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    
    # importation du modèle utilisateur pour le login_manager
    from app.models.user import User
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    return app
