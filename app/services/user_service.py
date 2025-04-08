from datetime import datetime, timedelta
from app import db
from app.models.user import User, Role
from sqlalchemy.exc import SQLAlchemyError
import logging

logger = logging.getLogger(__name__)

class UserService:
    @staticmethod
    def get_by_id(user_id):
        try:
            return User.query.get(user_id)
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving user by ID {user_id}: {e}")
            return None

    @staticmethod
    def get_by_username(username):
        try:
            return User.query.filter_by(username=username).first()
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving user by username {username}: {e}")
            return None

    @staticmethod
    def get_by_email(email):
        try:
            return User.query.filter_by(email=email).first()
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving user by email {email}: {e}")
            return None

    @staticmethod
    def get_by_public_id(public_id):
        try:
            return User.query.filter_by(public_id=public_id).first()
        except SQLAlchemyError as e:
            logger.error(f"Database error retrieving user by public ID {public_id}: {e}")
            return None

    @staticmethod
    def create_user(username, email, password):
        try:
            # Vérifier si l'utilisateur existe déjà
            if User.query.filter_by(username=username).first():
                return None, "Ce nom d'utilisateur est déjà pris."
            
            if User.query.filter_by(email=email).first():
                return None, "Cette adresse email est déjà utilisée."
            
            # Créer le nouvel utilisateur
            user = User(username=username, email=email, password=password)
            
            # Assigner le rôle par défaut
            default_role = Role.query.filter_by(name='user').first()
            if not default_role:
                default_role = Role(name='user', permissions=0x01)
                db.session.add(default_role)
            
            user.role = default_role
            
            db.session.add(user)
            db.session.commit()
            
            return user, "Compte créé avec succès."
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error creating user {username}: {e}")
            return None, "Une erreur est survenue lors de la création du compte."

    @staticmethod
    def update_login_attempt(user, success=True):
        try:
            if success:
                user.login_attempts = 0
                user.last_failed_login = None
                user.locked_until = None
            else:
                user.login_attempts += 1
                user.last_failed_login = datetime.utcnow()
                
                # Verrouiller le compte après 5 tentatives échouées
                if user.login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                    
            user.last_seen = datetime.utcnow()
            db.session.commit()
            
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error updating login attempts for user {user.id}: {e}")

    @staticmethod
    def is_account_locked(user):
        if not user.locked_until:
            return False
        
        if user.locked_until > datetime.utcnow():
            return True
        
        # Si la période de verrouillage est passée, réinitialiser les tentatives
        user.login_attempts = 0
        user.locked_until = None
        db.session.commit()
        return False

    @staticmethod
    def confirm_user(user):
        try:
            user.confirmed = True
            db.session.commit()
            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error confirming user {user.id}: {e}")
            return False
