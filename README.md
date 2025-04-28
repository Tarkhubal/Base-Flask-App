# Base Flask APP using Flask-Limiter, Flask-WTF and Flask-SQLAlchemy

Base .env :
```env
FLASK_APP=run.py
FLASK_ENV=development

SECRET_KEY=ADD_SECRET_KEY_HERE
JWT_SECRET_KEY=ADD_ANOTHER_KEY_HERE

# DATABASE CONFIGS
DATABASE_URL=sqlite:///dev.db

# REDIS_URL=redis://localhost:6379/0

# if you want to "lock" the access (unauthorized page everywhere...)
SITE_LOCKED=true

# ADMIN ACCOUNT
ADMIN_USERNAME=admin
ADMIN_PASSWORD=yesitsapassword
ADMIN_EMAIL=gigaadmin@madebyafrench.fr
```

License : MIT (c) Thomas BLANC 2025
