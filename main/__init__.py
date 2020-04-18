from flask import Flask

app = Flask(__name__)
app.secret_key = 'hello_world'
app.config.from_object(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
SQLALCHEMY_TRACK_MODIFICATIONS = False

from main import models
from main import views
