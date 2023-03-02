from functools import wraps
from flask import Flask

app = Flask(__name__)

# New imports
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

from os import environ
import mysql.connector

# force loading of environment variables
from dotenv import load_dotenv

load_dotenv('.flaskenv')

# Get the environment variables from .flaskenv
IP = environ.get('MYSQL_IP')
USERNAME = environ.get('MYSQL_USER')
PASSWORD = environ.get('MYSQL_PASS')
DB_NAME = environ.get('MYSQL_DB')


app.config['SECRET_KEY'] = 'CSC330'

# Specify the connection parameters/credentials for the database
DB_CONFIG_STR = f"mysql+mysqlconnector://{USERNAME}:{PASSWORD}@{IP}/{DB_NAME}"
app.config['SQLALCHEMY_DATABASE_URI'] = DB_CONFIG_STR
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]= True

# Create database connection and associate it with the Flask application
db = SQLAlchemy(app)

login = LoginManager(app)

# Add models
from app import routes, models
from app.models import Assignments, Roles, Users
import sqlalchemy as sa

with app.app_context():
    user = Users.query.filter_by(username='test').first()
    if user is None:
        users = db.session.query(Users).all()
        for user in users:
            user.set_password(user.password)
        db.session.commit()
        user_test = Users(username='test', firstname='test', lastname='test01', email='test@email.com')
        user_test.set_password('csc330')
        db.session.add(user_test)
        db.session.commit()
        db.session.add(Roles(rank='Leader', id=9, pid=1))
        db.session.add(Roles(rank='Owner', id=9, pid=2))
        db.session.add(Roles(rank='Member', id=9, pid=3))
        db.session.flush()
        db.session.add(Assignments(id=9, tid=1, request=None))
        db.session.add(Assignments(id=9, tid=3, request=None))
        db.session.add(Assignments(id=9, tid=5, request=None))
        db.session.commit()
