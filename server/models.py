from sqlalchemy.orm import validates, relationship
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)  
    username = db.Column(db.String, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    image_url = db.Column(db.String, nullable=False)
    bio = db.Column(db.Text, nullable=False)

    # Define relationship to Recipe
    recipes = relationship("Recipe", backref="user", lazy=True)
    
    @hybrid_property
    def password(self):
        raise AttributeError("Password is not a readable attribute.")
    
    @password.setter
    def password(self, password):
        self._password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
        
    def verify_password(self, password):
        return bcrypt.check_password_hash(self._password_hash, password)
    
    @validates('username')
    def validate_username(self, key, username):
        assert username is not None, "Username must be provided."
        return username

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.Text, nullable=False)
    minutes_to_complete = db.Column(db.Integer, nullable=False)
    
    # Add a foreign key to associate Recipe with User
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    @validates('instructions')
    def validate_instructions(self, key, instructions):
        assert len(instructions) >= 50, "Instructions must be at least 50 characters long."
        return instructions