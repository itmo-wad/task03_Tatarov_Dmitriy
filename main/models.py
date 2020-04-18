from flask_sqlalchemy import SQLAlchemy
from main import app
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, index=True)
    password = db.Column(db.String(50))
    salt = db.Column(db.String(100))
    
    def __init__(self, username, password, salt):
        self.username = username
        self.password = password
        self.salt = salt

    def __repr__(self):
        return '<User %r>' % self.username