#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        username = request.json.get('username')
        password = request.json.get('password')
        image_url = request.json.get('image_url')
        bio = request.json.get('bio')

        if not all([username, password, image_url, bio]):
            return {"error": "All fields are required."}, 400

        if User.query.filter_by(username=username).first():
            return {"error": "Username already exists."}, 400

        try:
            user = User(username=username, password=password, image_url=image_url, bio=bio)
            db.session.add(user)
            db.session.commit()

            return {"message": "User created successfully."}, 201

        except IntegrityError as e:
            return {"error": str(e)}, 400

class CheckSession(Resource):
    def get(self):
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            return {"user": user.serialize}, 200

        return {"error": "No active session."}, 401

class Login(Resource):
    def post(self):
        username = request.json.get('username')
        password = request.json.get('password')

        if not all([username, password]):
            return {"error": "Username and password are required."}, 400

        user = User.query.filter_by(username=username).first()

        if user and user.verify_password(password):  # assuming `verify_password` method exists in the User model
            session['user_id'] = user.id
            return {
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "image_url": user.image_url,
                    "bio": user.bio
                }
            }, 200

        return {"error": "Invalid credentials."}, 401


class Logout(Resource):
    def delete(self):
        if 'user_id' in session:
            session.pop('user_id')
            return {}, 204  # No Content

        return {"error": "No user logged in."}, 401


class RecipeIndex(Resource):
    def get(self):
        if 'user_id' in session:
            recipes = Recipe.query.all()
            return [{
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user": {
                    "id": recipe.user.id,
                    "username": recipe.user.username
                }
            } for recipe in recipes], 200

        return {"error": "Unauthorized access."}, 401

    def post(self):
        if 'user_id' not in session:
            return {"error": "Unauthorized access."}, 401

        title = request.json.get('title')
        instructions = request.json.get('instructions')
        minutes_to_complete = request.json.get('minutes_to_complete')

        if not all([title, instructions, minutes_to_complete]):
            return {"error": "All fields are required."}, 400

        if len(instructions) < 50:
            return {"error": "Instructions must be at least 50 characters long."}, 400

        recipe = Recipe(
            title=title,
            instructions=instructions,
            minutes_to_complete=minutes_to_complete,
            user_id=session['user_id']
        )

        db.session.add(recipe)
        db.session.commit()

        return {
            "recipe": {
                "title": recipe.title,
                "instructions": recipe.instructions,
                "minutes_to_complete": recipe.minutes_to_complete,
                "user": {
                    "id": recipe.user.id,
                    "username": recipe.user.username
                }
            }
        }, 201


api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)