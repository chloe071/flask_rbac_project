import pytest
from app import app, db
from flask_login import current_user

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'

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
    # Register and login admin (lead)
    client.post('/register', data={'username': 'admin', 'password': 'adminpass', 'role': 'lead'})
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
        assert resp.status_code in [200, 302], f"Failed on {method} {url}"

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
            resp = logged_in_client.post(url, data=data[0] if data else {})
        else:
            continue
        assert resp.status_code in [200, 302], f"Failed on {method} {url}"

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
        assert resp.status_code in [200, 302], f"Failed on {method} {url}"

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
        assert resp.status_code in [200, 302], f"Failed on {method} {url}"