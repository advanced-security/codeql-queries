#!/usr/bin/env python3

from flask import Flask, request
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
db = SQLAlchemy(app)


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80))


class SecureUser(db.Model, UserMixin):
    __tablename__ = 'secure_users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80))

    def __init__(self, username, password):
        self.username = username
        self.password = generate_password_hash(password)


@app.route("/register")
def reg1():
    username = request.json['username']
    password = request.json['password']

    user = User(username, password)


@app.route("/register-secure")
def reg1():
    username = request.json['username']
    password = request.json['password']

    user = SecureUser(username, password)
