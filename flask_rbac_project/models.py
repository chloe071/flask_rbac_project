from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy

#Scenario table
class Scenario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    injects = db.relationship('Inject', beckref='scenario', cascade='all, delete-orphan')

#Inject table - timed events or alerts within scenarios
class Inject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scenario_id = db.Column(db.Integer, db.ForeignKey('scenario.id'), nullable=False)
    time_offset_seconds = db.Column(db.Integer, nullable=False) #time delay from scenario start
    message = db.Column(db.Text, nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.Datetime, default=datetime.utcnow)