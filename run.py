from app import create_app
import os
from dotenv import load_dotenv

# charger les variables d'environnement depuis le fichier .env
load_dotenv()

app = create_app(os.getenv('FLASK_ENV', 'development'))

if __name__ == "__main__":
    # en production, utilisez un serveur wsgi comme gunicorn
    if app.config['ENV'] == 'development':
        app.run(debug=True)
    else:
        app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
