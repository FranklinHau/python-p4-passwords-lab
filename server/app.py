#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api
from models import User

class ClearSession(Resource):

    def delete(self):
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204

class Signup(Resource):
    
    def post(self):
        json_data = request.get_json()
        user = User(username=json_data['username'])
        user.password_hash = json_data['password']

        db.session.add(user)
        db.session.commit()
        return {"id": user.id, "username": user.username}, 201


class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.filter_by(id=user_id).first()
            if user:
                return {"id": user.id, "username": user.username}, 200
        return {}, 204


class Login(Resource):
    def post(self):
        json_data = request.get_json()
        user = User.query.filter(User.username == json_data['username']).first()

        if user and user.authenticate(json_data['password']):
            session['user_id'] = user.id 
            return {"id": user.id, "username": user.username}, 200
        
        return {'message': 'Invalid credentials'}, 401
        

class Logout(Resource):
    def delete(self):
        session['user_id'] = None
        return {}, 204

    
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')    
api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
