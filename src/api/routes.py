"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_jwt_extended import jwt_required, get_jwt_identity

api = Blueprint('api', __name__)

user[]

    @api.route('/singup', methods=['POST'])
    def singup():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    user = User()
    user.email = username
    user.password = password
    user.is_active = True
    db.session.add(user)
    db.session.commit()
    return jsonify(user), 200
    

    @api.route('/login', methods=['POST'])
    def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    user = User.filter.query(username=username, password=password).first()
    if user is None:
          # el usuario no se encontró en la base de datos
    return jsonify({"msg": "Bad username or password"}), 401
    
    # crea un nuevo token con el id de usuario dentro
    access_token = create_access_token(identity=user.id)
    return jsonify({ "token": access_token, "user_id": user.id })
    pass



    @api.route('/private', methods=['GET'])
    @jwt_requiered()
    def private():
    return "esta es una ruta protegida joder!!", 200
    