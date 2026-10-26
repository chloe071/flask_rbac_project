import os
import tempfile

# Use a throwaway database so tests never touch instance/users.db
os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(tempfile.mkdtemp(), "test.db")
os.environ.setdefault("API_TOKEN", "test-token")

import pytest
from app import app, db
from flask_login import current_user

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            # Insert roles upfront
            from app import Role
            for role_name in ['lead', 'analyst', 'observer']:
                if not Role.query.filter_by(name=role_name).first():
                    db.session.add(Role(name=role_name))
            db.session.commit()
        yield client
        with app.app_context():
            db.drop_all()

@pytest.fixture
def logged_in_client(client):
    # Register as analyst, then promote to lead the way an operator would
    client.post('/register', data={'username': 'admin', 'password': 'adminpass', 'role': 'analyst'})
    result = app.test_cli_runner().invoke(args=['make-lead', 'admin'])
    assert 'is now a lead' in result.output
    rv = client.post('/login', data={'username': 'admin', 'password': 'adminpass'}, follow_redirects=True)
    assert rv.status_code == 200
    yield client

@pytest.fixture
def logged_in_analyst_client(client):
    # Register and login analyst
    client.post('/register', data={'username': 'analyst_user', 'password': 'analystpass', 'role': 'analyst'})
    rv = client.post('/login', data={'username': 'analyst_user', 'password': 'analystpass'}, follow_redirects=True)
    assert rv.status_code == 200
    yield client

@pytest.fixture
def logged_in_observer_client(client):
    # Register and login observer
    client.post('/register', data={'username': 'observer_user', 'password': 'observerpass', 'role': 'observer'})
    rv = client.post('/login', data={'username': 'observer_user', 'password': 'observerpass'}, follow_redirects=True)
    assert rv.status_code == 200
    yield client

def test_public_routes(client):
    public_routes = [
        ('GET', '/'),
        ('GET', '/login'),
        ('GET', '/register'),
    ]
    for method, url, *data in public_routes:
        if method == 'GET':
            resp = client.get(url)
        elif method == 'POST':
            resp = client.post(url, data=data[0] if data else {})
        else:
            continue
        assert resp.status_code in [200, 201, 302], f"Failed on {method} {url}"

def test_lead_protected_routes(logged_in_client):
    lead_routes = [
        ('GET', '/dashboard'),
        ('GET', '/lead-dashboard'),
        ('GET', '/scenarios'),
        ('POST', '/scenarios', {"name": "Test Scenario", "description": "Sample"}),
        # Add other lead/admin routes here...
    ]
    for method, url, *data in lead_routes:
        if method == 'GET':
            resp = logged_in_client.get(url)
        elif method == 'POST':
            resp = logged_in_client.post(url, json=data[0] if data else {})
        else:
            continue
        assert resp.status_code in [200, 201, 302], f"Failed on {method} {url}"

def test_analyst_protected_routes(logged_in_analyst_client):
    analyst_routes = [
        ('GET', '/dashboard'),
        ('GET', '/analyst-dashboard'),
        # Add other analyst-restricted routes here...
    ]
    for method, url, *data in analyst_routes:
        if method == 'GET':
            resp = logged_in_analyst_client.get(url)
        elif method == 'POST':
            resp = logged_in_analyst_client.post(url, data=data[0] if data else {})
        else:
            continue
        assert resp.status_code in [200, 201, 302], f"Failed on {method} {url}"

def test_observer_protected_routes(logged_in_observer_client):
    observer_routes = [
        ('GET', '/dashboard'),
        ('GET', '/observer-dashboard'),
        # Add other observer-restricted routes here...
    ]
    for method, url, *data in observer_routes:
        if method == 'GET':
            resp = logged_in_observer_client.get(url)
        elif method == 'POST':
            resp = logged_in_observer_client.post(url, data=data[0] if data else {})
        else:
            continue
        assert resp.status_code in [200, 201, 302], f"Failed on {method} {url}"


# ---------- Security regression tests ----------

def test_cannot_self_register_as_lead(client):
    client.post('/register', data={'username': 'sneaky', 'password': 'sneakypass', 'role': 'lead'})
    rv = client.post('/login', data={'username': 'sneaky', 'password': 'sneakypass'})
    assert rv.status_code == 302 and '/login' in rv.headers['Location']  # account was never created


def test_analyst_cannot_open_lead_dashboard(logged_in_analyst_client):
    assert logged_in_analyst_client.get('/lead-dashboard').status_code == 403


def test_analyst_cannot_create_scenario(logged_in_analyst_client):
    rv = logged_in_analyst_client.post('/scenarios', json={'name': 'x'})
    assert rv.status_code == 403


def test_analyst_cannot_open_secure_lead_chat(logged_in_analyst_client):
    assert logged_in_analyst_client.get('/chat/lead').status_code == 403


def test_analyst_cannot_read_lead_messages(logged_in_analyst_client):
    assert logged_in_analyst_client.get('/communications/lead').status_code == 403


def test_anonymous_redirected_from_dashboard(client):
    rv = client.get('/dashboard')
    assert rv.status_code == 302 and '/login' in rv.headers['Location']


def test_api_rejects_missing_or_wrong_token(client):
    assert client.post('/api/scenario', json={'name': 'x'}).status_code == 401
    rv = client.post('/api/scenario', json={'name': 'x'}, headers={'X-API-Token': 'wrong'})
    assert rv.status_code == 401


def test_api_accepts_valid_token(client):
    rv = client.post('/api/scenario', json={'name': 'api-made'}, headers={'X-API-Token': 'test-token'})
    assert rv.status_code == 201
