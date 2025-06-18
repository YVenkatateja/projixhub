# extensions.py

from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail
from flask_pymongo import PyMongo

db = SQLAlchemy()
mail = Mail()
mongo = PyMongo()  # ✅ Add this line for MongoDB

# Optional helper to initialize all extensions
def init_extensions(app):
    app.config["MONGO_URI"] = os.getenv("MONGO_URI")  # ✅ Uses .env config
    db.init_app(app)
    mail.init_app(app)
    mongo.init_app(app)
