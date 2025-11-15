import eventlet
eventlet.monkey_patch()

from cryptography.fernet import Fernet
import logging
from flask import (
    Flask, render_template, redirect, url_for, request, flash, abort, jsonify, Response
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_required, logout_user,
    current_user, login_user
)
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from functools import wraps
from datetime import datetime
from collections import Counter
from flask_socketio import SocketIO, emit, join_room, leave_room
import random
import requests
from flask_caching import Cache
from sqlalchemy.orm import joinedload

import os

# Setup config, cache, logging
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "replace-with-secure-secret")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///users.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["CACHE_TYPE"] = "SimpleCache"
app.config["CACHE_DEFAULT_TIMEOUT"] = 300
cache = Cache(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
migrate = Migrate(app, db)
socketio = SocketIO(app)

API_TOKEN = os.getenv("API_TOKEN", "your-secure-api-token")

# User loader callback
@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except Exception as e:
        app.logger.error(f"Error loading user {user_id}: {e}")
        return None

# Decorators for roles and API token validation
def roles_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or not current_user.check_role(role):
                abort(403)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.check_role('lead'):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def require_api_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('X-API-Token')
        if not token or token != API_TOKEN:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated_function

# Models with explicit foreign keys to fix ambiguity

user_roles = db.Table(
    'user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'))
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    roles = db.relationship('Role', secondary=user_roles, back_populates='users')
    user_badges = db.relationship('UserBadge', back_populates='user')
    def check_role(self, role_name):
        return any(role.name == role_name for role in self.roles)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    users = db.relationship('User', secondary=user_roles, back_populates='roles')

class Scenario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    injects = db.relationship('Inject', backref='scenario', cascade='all, delete-orphan')
    action_logs = db.relationship('ActionLog', backref='scenario')
    forensic_logs = db.relationship('ForensicLog', backref='scenario')

    paths = db.relationship(
        'ScenarioPath', back_populates='parent_scenario',
        foreign_keys='ScenarioPath.scenario_id'
    )

class ScenarioPath(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scenario_id = db.Column(db.Integer, db.ForeignKey('scenario.id'), nullable=False)
    description = db.Column(db.Text, nullable=False)
    condition = db.Column(db.String(100), nullable=False)
    next_scenario_id = db.Column(db.Integer, db.ForeignKey('scenario.id'), nullable=True)

    parent_scenario = db.relationship(
        'Scenario', back_populates='paths',
        foreign_keys=[scenario_id]
    )
    next_scenario = db.relationship(
        'Scenario',
        foreign_keys=[next_scenario_id]
    )

class Inject(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scenario_id = db.Column(db.Integer, db.ForeignKey('scenario.id'), nullable=False)
    time_offset_seconds = db.Column(db.Integer, nullable=False)
    message = db.Column(db.Text, nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ActionLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scenario_id = db.Column(db.Integer, db.ForeignKey('scenario.id'), nullable=False)
    action_type = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class ForensicLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scenario_id = db.Column(db.Integer, db.ForeignKey('scenario.id'), nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    severity = db.Column(db.String(20))

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_role = db.Column(db.String(80), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_predefined = db.Column(db.Boolean, default=False)
    secure = db.Column(db.Boolean, default=False)
    audited = db.Column(db.Boolean, default=False)
    sender = db.relationship('User', backref='sent_messages')

class Playbook(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    description = db.Column(db.Text)
    json_data = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class DecisionTree(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), unique=True, nullable=False)
    description = db.Column(db.Text)
    json_data = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Badge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text, nullable=False)
    criteria = db.Column(db.String(200), nullable=False)


class UserBadge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    badge_id = db.Column(db.Integer, db.ForeignKey('badge.id'), nullable=False)
    awarded_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', back_populates='user_badges')
    badge = db.relationship('Badge', backref='user_badges')


# Utility functions


def serialize_timeline(timeline):
    serialized = []
    for item in timeline:
        new_item = {}
        for k, v in item.items():
            if isinstance(v, datetime):
                new_item[k] = v.isoformat()
            else:
                new_item[k] = v
        serialized.append(new_item)
    return serialized


THREAT_IOC_POOL = [
    {"type": "IP", "value": "185.83.214.197", "desc": "Known C2 IP associated with Emotet"},
    {"type": "Domain", "value": "malicious-domain.biz", "desc": "Ransomware distribution site"},
    {"type": "SHA256", "value": "2fcf5ffd9e6b3aad10155c...", "desc": "Ryuk ransomware signature"},
    {"type": "URL", "value": "https://hackedsite.news/payload.exe", "desc": "Current phishing campaign dropper"},
    {"type": "IP", "value": "89.45.67.123", "desc": "Recent massive brute-force source"},
]

# Utility functions
@cache.cached(timeout=300)
def fetch_live_headlines():
    try:
        url = (
            'https://newsapi.org/v2/everything?'
            'q=cybersecurity OR ransomware OR malware OR threat&'
            'sortBy=publishedAt&'
            'pageSize=5&'
            'apiKey=4fe052f7b09240beb2334b93dd160bd2'
        )
        resp = requests.get(url, timeout=5)
        articles = resp.json().get("articles", [])
        return [
            {"type": "Headline", "value": a["title"], "desc": a.get("description") or ""}
            for a in articles if a.get("title")
        ]
    except Exception as ex:
        logger.error(f"Error fetching headlines: {ex}")
        return []


# Badges awarding function
def award_badges_for_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return

    containment_logs = ActionLog.query.filter_by(user_id=user_id, action_type='containment').all()
    for log in containment_logs:
        scenario_start = log.scenario.created_at
        if (log.timestamp - scenario_start).total_seconds() <= 300:
            badge = Badge.query.filter_by(criteria='quick_containment').first()
            if badge and badge not in [ub.badge for ub in user.user_badges]:
                user_badge = UserBadge(user_id=user_id, badge_id=badge.id)
                db.session.add(user_badge)
                db.session.commit()

    forensic_count = ForensicLog.query.filter(ForensicLog.scenario.has(action_logs.any(user_id=user_id))).count()
    if forensic_count >= 10:
        badge = Badge.query.filter_by(criteria='thorough_forensics').first()
        if badge and badge not in [ub.badge for ub in user.user_badges]:
            user_badge = UserBadge(user_id=user_id, badge_id=badge.id)
            db.session.add(user_badge)
            db.session.commit()


# Scenario branching helper functions
def evaluate_branch_condition(condition_str, scenario_id):
    if condition_str == "containment_logged":
        return ActionLog.query.filter_by(scenario_id=scenario_id, action_type="containment").count() > 0
    elif condition_str == "communication_logged":
        return ActionLog.query.filter_by(scenario_id=scenario_id, action_type="communication").count() > 0
    return False


def evaluate_and_branch_scenario(scenario):
    paths = scenario.paths
    for path in paths:
        if evaluate_branch_condition(path.condition, scenario.id):
            return path.next_scenario_id
    return None


def generate_explanation(log):
    explanations = {
        "containment": "This action is to contain the threat and prevent spread.",
        "isolation": "Isolating impacted hosts to avoid further infection.",
        "communication": "Notifying stakeholders about incident status.",
        "escalate_to_lead": "Escalated issue to incident lead for further handling.",
        "investigation": "Performed detailed investigation of suspicious artifacts."
    }
    return explanations.get(log.action_type, "No explanation available for this action.")


# Routes


@app.route('/')
def index():
    return render_template('base.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        role_name = request.form.get('role')
        user_check = User.query.filter_by(username=username).first()
        if user_check:
            flash('Username already exists.')
            return redirect(url_for('register'))
        user = User(username=username, password_hash=password)
        role = Role.query.filter_by(name=role_name).first()
        if not role:
            role = Role(name=role_name)
            db.session.add(role)
        user.roles.append(role)
        db.session.add(user)
        db.session.commit()
        flash('Registration successful! You can now login.')
        return redirect(url_for('login'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if not username or not password:
            flash("Username and password required.")
            return redirect(url_for('login'))
        try:
            user = User.query.filter_by(username=username).first()
            if user and bcrypt.check_password_hash(user.password_hash, password):
                login_user(user)
                return redirect(url_for('dashboard'))
            flash("Invalid username or password.")
        except Exception as e:
            logger.error(f"Login error for {username}: {e}")
            flash("An error occurred.")
        return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/dashboard')
@login_required
def dashboard():
    return f"Hello, {current_user.username}! Your roles: {', '.join([r.name for r in current_user.roles])}"


@app.route('/analyst-dashboard')
@login_required
@roles_required('analyst')
def analyst_dashboard():
    return render_template('dashboard.html', role_name='analyst')


@app.route('/lead-dashboard')
@login_required
@roles_required('lead')
def lead_dashboard():
    return render_template('dashboard.html', role_name='lead')


@app.route('/observer-dashboard')
@login_required
@roles_required('observer')
def observer_dashboard():
    return render_template('dashboard.html', role_name='observer')


@app.route('/threat_feed')
@login_required
def threat_feed():
    try:
        news_iocs = fetch_live_headlines()
        pool = THREAT_IOC_POOL + news_iocs
        random.shuffle(pool)
        feed_items = pool[:5]
        return jsonify(feed_items)
    except Exception as e:
        logger.error(f"Error in threat_feed route: {e}")
        return jsonify({"error": "Failed to load threat feed"}), 500


@app.route('/threat_feed/view')
@login_required
def threat_feed_view():
    return render_template('threat_feed.html')


@app.route('/badges')
@login_required
def view_badges():
    user_badges = current_user.user_badges
    return render_template('badges.html', user_badges=user_badges)


@app.route('/chat/<role>')
@login_required
def chat(role):
    if role not in ('lead', 'analyst', 'observer'):
        abort(403)
    namespace = '/secure' if role == 'lead' else '/public'
    room = f"{role}_room"
    return render_template('chat.html', room=room, namespace=namespace, role=role)


# Scenario routes

@app.route('/scenarios', methods=['GET'])
@login_required
def list_scenarios():
    try:
        page = int(request.args.get('page', 1))
        per_page = int(request.args.get('per_page', 10))

        scenarios_paginated = Scenario.query.order_by(Scenario.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
        scenarios = [{
            "id": s.id,
            "name": s.name,
            "description": s.description,
            "created_at": s.created_at.isoformat()
        } for s in scenarios_paginated.items]
        return jsonify({
            "scenarios": scenarios,
            "total": scenarios_paginated.total,
            "pages": scenarios_paginated.pages,
            "page": scenarios_paginated.page
        })
    except Exception as e:
        logger.error(f"Error in list_scenarios route: {e}")
        return jsonify({"error": "Failed to load scenarios"}), 500


@app.route('/scenarios', methods=['POST'])
@admin_required
def create_scenario():
    data = request.json
    if not data.get('name'):
        return jsonify({"error": "Scenario name required"}), 400
    if Scenario.query.filter_by(name=data['name']).first():
        return jsonify({"error": "Scenario exists"}), 400
    scenario = Scenario(name=data['name'], description=data.get('description'))
    db.session.add(scenario)
    db.session.commit()
    return jsonify({"id": scenario.id, "name": scenario.name}), 201


@app.route('/scenarios/<int:scenario_id>/injects', methods=['GET'])
@login_required
def get_injects_for_scenario(scenario_id):
    scenario = Scenario.query.get_or_404(scenario_id)
    injects = [{
        "id": i.id,
        "time_offset_seconds": i.time_offset_seconds,
        "message": i.message,
        "event_type": i.event_type,
        "created_at": i.created_at.isoformat()
    } for i in scenario.injects]
    return jsonify(injects)


@app.route('/scenarios/<int:scenario_id>/injects', methods=['POST'])
@admin_required
def add_inject(scenario_id):
    scenario = Scenario.query.get_or_404(scenario_id)
    data = request.json
    required_fields = ['time_offset_seconds', 'message', 'event_type']
    if not all(k in data for k in required_fields):
        return jsonify({"error": "Missing fields"}), 400
    inject = Inject(
        scenario_id=scenario.id,
        time_offset_seconds=data['time_offset_seconds'],
        message=data['message'],
        event_type=data['event_type']
    )
    db.session.add(inject)
    db.session.commit()
    return jsonify({"id": inject.id}), 201


@app.route('/injects/<int:inject_id>', methods=['DELETE'])
@admin_required
def delete_inject(inject_id):
    inject = Inject.query.get_or_404(inject_id)
    db.session.delete(inject)
    db.session.commit()
    return jsonify({"message": "Inject deleted"}), 200

@app.route('/admin/report/<int:scenario_id>/pdf')
@login_required
@admin_required
def generate_pdf_report(scenario_id):
    try:
        scenario = Scenario.query.options(joinedload(Scenario.injects)).get_or_404(scenario_id)
        rendered_html = render_template('report.html', scenario=scenario)

        resp = requests.post("http://localhost:3000/generate-pdf", json={"html": rendered_html}, timeout=10)
        resp.raise_for_status()

        return Response(
            resp.content,
            mimetype="application/pdf",
            headers={"Content-Disposition": f"inline; filename=scenario_{scenario_id}.pdf"}
        )
    except requests.RequestException as re:
        logger.error(f"PDF generation error: {re}")
        return "Failed to generate PDF", 500
    except Exception as e:
        logger.error(f"General error in PDF route: {e}")
        return "Internal Server Error", 500

@app.route('/scenarios/<int:scenario_id>/injects/due', methods=['GET'])
@login_required
def get_due_injects(scenario_id):
    scenario = Scenario.query.get_or_404(scenario_id)
    start_str = request.args.get('start_time')
    if not start_str:
        return jsonify({"error": "Missing start_time"}), 400
    try:
        start_time = datetime.fromisoformat(start_str)
    except ValueError:
        return jsonify({"error": "Invalid start_time format"}), 400
    now = datetime.utcnow()
    elapsed = (now - start_time).total_seconds()
    due_injects = [
        {
            "id": inject.id,
            "message": inject.message,
            "event_type": inject.event_type,
            "time_offset_seconds": inject.time_offset_seconds
        }
        for inject in scenario.injects if inject.time_offset_seconds <= elapsed
    ]
    return jsonify(due_injects)


@app.route('/scenarios/<int:scenario_id>/replay')
@login_required
def replay_scenario(scenario_id):
    scenario = Scenario.query.get_or_404(scenario_id)
    action_logs = ActionLog.query.filter_by(scenario_id=scenario_id).order_by(ActionLog.timestamp).all()
    forensic_logs = ForensicLog.query.filter_by(scenario_id=scenario_id).order_by(ForensicLog.created_at).all()

    timeline = []
    for log in action_logs:
        timeline.append({
            "type": "action",
            "timestamp": log.timestamp.isoformat(),
            "user": log.user.username,
            "action_type": log.action_type,
            "details": log.details,
            "explanation": generate_explanation(log)
        })

    for fl in forensic_logs:
        timeline.append({
            "type": "forensic",
            "timestamp": fl.created_at.isoformat(),
            "severity": fl.severity,
            "description": fl.description
        })
    timeline.sort(key=lambda x: x["timestamp"])

    serialized_timeline = serialize_timeline(timeline)
    return render_template('replay.html', scenario=scenario, timeline=serialized_timeline)


@app.route('/dashboard/<int:scenario_id>/log_action', methods=['POST'])
@login_required
def log_action(scenario_id):
    data = request.json
    if not data.get('action_type') or not data.get('details'):
        return jsonify({"error": "Missing action_type or details"}), 400
    new_log = ActionLog(
        user_id=current_user.id,
        scenario_id=scenario_id,
        action_type=data['action_type'],
        details=data['details']
    )
    db.session.add(new_log)
    db.session.commit()

    award_badges_for_user(current_user.id)

    return jsonify({"message": "Action logged", "id": new_log.id})


@app.route('/dashboard/<int:scenario_id>/action_logs')
@login_required
def get_action_logs(scenario_id):
    logs = ActionLog.query.filter_by(scenario_id=scenario_id).order_by(ActionLog.timestamp.desc()).all()
    return jsonify([{
        "id": log.id,
        "user": User.query.get(log.user_id).username,
        "action_type": log.action_type,
        "details": log.details,
        "timestamp": log.timestamp.isoformat()
    } for log in logs])


@app.route('/scenarios/<int:scenario_id>/branch', methods=['GET'])
@login_required
def branch_scenario(scenario_id):
    scenario = Scenario.query.get_or_404(scenario_id)
    next_scenario_id = evaluate_and_branch_scenario(scenario)
    if next_scenario_id:
        return redirect(url_for('scenario_dashboard', scenario_id=next_scenario_id))
    flash("No branching condition met, staying in current scenario.")
    return redirect(url_for('scenario_dashboard', scenario_id=scenario_id))


PREDEFINED_MESSAGES = [
    {"id": 1, "content": "All systems are secure and being monitored."},
    {"id": 2, "content": "Incident response is underway, stakeholders notified."},
    {"id": 3, "content": "Awaiting further instructions from authorities."},
]


@app.route('/api/scenario', methods=['POST'])
@require_api_token
def api_create_scenario():
    data = request.json
    name = data.get('name')
    description = data.get('description', '')
    if not name:
        return jsonify({"error": "Scenario name required"}), 400
    if Scenario.query.filter_by(name=name).first():
        return jsonify({"error": "Scenario already exists"}), 409

    scenario = Scenario(name=name, description=description)
    db.session.add(scenario)
    db.session.commit()

    return jsonify({"message": "Scenario created", "scenario_id": scenario.id}), 201


@app.route('/api/scenario/<int:scenario_id>/forensic_log', methods=['POST'])
@require_api_token
def api_add_forensic_log(scenario_id):
    scenario = Scenario.query.get_or_404(scenario_id)
    data = request.json
    description = data.get('description')
    severity = data.get('severity')
    if not description or not severity:
        return jsonify({"error": "Descriptionand severity required"}), 400

    forensic_log = ForensicLog(scenario_id=scenario.id, description=description, severity=severity)
    db.session.add(forensic_log)
    db.session.commit()

    return jsonify({"message": "Forensic log added", "id": forensic_log.id}), 201


@app.route('/api/scenario/<int:scenario_id>/log_action', methods=['POST'])
@require_api_token
def api_log_action(scenario_id):
    data = request.json
    required_fields = ['user_id', 'action_type', 'details']
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing fields"}), 400

    user = User.query.get(data['user_id'])
    if not user:
        return jsonify({"error": "User not found"}), 404

    action_log = ActionLog(
        user_id=user.id,
        scenario_id=scenario_id,
        action_type=data['action_type'],
        details=data['details']
    )
    db.session.add(action_log)
    db.session.commit()
    return jsonify({"message": "Action logged", "id": action_log.id}), 201


@app.route('/api/scenario/<int:scenario_id>/performance')
@require_api_token
def api_performance(scenario_id):
    scenario = Scenario.query.get_or_404(scenario_id)
    logs = ActionLog.query.filter_by(scenario_id=scenario_id).all()

    total_actions = len(logs)
    containment_actions = sum(1 for log in logs if log.action_type == 'containment')
    communication_actions = sum(1 for log in logs if log.action_type == 'communication')

    return jsonify(
        {
            "scenario_id": scenario_id,
            "total_actions": total_actions,
            "containment_actions": containment_actions,
            "communication_actions": communication_actions,
        }
    )


@app.route('/communications/<receiver_role>', methods=['GET'])
@login_required
def get_messages(receiver_role):
    messages = Message.query.filter_by(receiver_role=receiver_role).order_by(Message.timestamp).all()
    return jsonify(
        [
            {
                "id": m.id,
                "sender": m.sender.username,
                "content": m.content,
                "timestamp": m.timestamp.isoformat(),
                "predefined": m.is_predefined,
            }
            for m in messages
        ]
    )


@app.route('/communications/<receiver_role>/send', methods=['POST'])
@login_required
def send_message(receiver_role):
    data = request.json
    content = data.get("content")
    predefined = data.get("predefined", False)
    if not content:
        return jsonify({"error": "Message content required"}), 400
    msg = Message(
        sender_id=current_user.id,
        receiver_role=receiver_role,
        content=content,
        is_predefined=predefined,
    )
    db.session.add(msg)
    db.session.commit()
    return jsonify({"message": "Sent successfully", "id": msg.id})


@app.route("/communications/<receiver_role>/chat")
@login_required
def communications_page(receiver_role):
    return render_template(
        "communications.html", receiver_role=receiver_role, predefined_messages=PREDEFINED_MESSAGES
    )


@app.route("/analysis/<int:scenario_id>")
@login_required
def analysis(scenario_id):
    scenario = Scenario.query.get_or_404(scenario_id)
    return render_template("analysis.html", scenario=scenario)


@app.route("/analysis/<int:scenario_id>/data")
@login_required
def analysis_data(scenario_id):
    logs = ActionLog.query.filter_by(scenario_id=scenario_id).order_by(ActionLog.timestamp).all()
    total_actions = len(logs)
    containment_actions = sum(1 for log in logs if log.action_type == "containment")
    isolation_actions = sum(1 for log in logs if log.action_type == "isolation")
    communication_actions = sum(1 for log in logs if log.action_type == "communication")
    user_actions = Counter(log.user.username for log in logs)
    timeline = [
        {"timestamp": log.timestamp.isoformat(), "user": log.user.username, "action_type": log.action_type, "details": log.details}
        for log in logs
    ]
    analysis_result = {
        "total_actions": total_actions,
        "breakdown": {"containment": containment_actions, "isolation": isolation_actions, "communication": communication_actions},
        "user_actions": dict(user_actions),
        "timeline": timeline,
    }
    return jsonify(analysis_result)


@app.route("/collaborate/<room>")
@login_required
def collaborate(room):
    return render_template("collaborate.html", room=room)


@socketio.on("join")
def handle_join(data):
    room = data["room"]
    join_room(room)
    emit("status", {"msg": f"{data['user']} has entered the room."}, room=room)


@socketio.on("leave")
def handle_leave(data):
    room = data["room"]
    leave_room(room)
    emit("status", {"msg": f"{data['user']} has left the room."}, room=room)


@socketio.on("send_message")
def handle_send_message(data):
    room = data["room"]
    emit(
        "receive_message",
        {"user": data["user"], "message": data["message"], "timestamp": data["timestamp"]},
        room=room,
    )


# Secure and Public Chat

SECURE_CHAT_KEY = Fernet.generate_key()
cipher_suite = Fernet(SECURE_CHAT_KEY)

ROLE_NAMESPACES = {"lead": "/secure", "analyst": "/public", "observer": "/public"}


@socketio.on("join", namespace="/public")
def public_join(data):
    room = data["room"]
    join_room(room)
    emit("status", {"msg": f"{data['user']} joined the public chat."}, room=room)


@socketio.on("send_message", namespace="/public")
def public_message(data):
    room = data["room"]
    message_text = data["message"]
    emit("receive_message", {"user": data["user"], "message": message_text, "timestamp": data["timestamp"]}, room=room)
    msg = Message(sender_id=data["user_id"], receiver_role="public", content=message_text)
    db.session.add(msg)
    db.session.commit()


@socketio.on("join", namespace="/secure")
def secure_join(data):
    room = data["room"]
    join_room(room)
    emit("status", {"msg": f"{data['user']} joined the secure chat."}, room=room)


@socketio.on("send_message", namespace="/secure")
def secure_message(data):
    room = data["room"]
    encrypted_message = cipher_suite.encrypt(data["message"].encode()).decode()
    emit("receive_message", {"user": data["user"], "message": encrypted_message, "timestamp": data["timestamp"]}, room=room)
    msg = Message(sender_id=data["user_id"], receiver_role="lead", content=encrypted_message, secure=True, audited=True)
    db.session.add(msg)
    db.session.commit()


if __name__ == "__main__":
    socketio.run(app, debug=True)