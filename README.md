Flask RBAC Cyber Simulation Suite
Overview
This project is a role-based access control (RBAC) Flask web application that simulates real-world cybersecurity operations. It features user authentication, fine-grained roles, secure chat, scenario workflows, action logs, and threat feeds. Technologies used include Flask, SQLAlchemy, Bootstrap, Celery (for background jobs), and Redis.​

Features
User registration/login/logout with role selection (lead, analyst, observer)

Role-protected dashboards and scenario management

Secure and public chat (real-time)

Threat intelligence feed

Action and forensic logging per scenario

Badges awarded for achievements

PDF report generation (background/async)

PDF report generation (background/async)

REST API endpoints secured with API tokens

Caching for faster performance

Bootstrap-based clean UI

Setup & Installation
Clone the repository:

text
git clone https://github.com/yourusername/flask_rbac_project.git
cd flask_rbac_project
Create virtual environment and install dependencies:

text
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

Set up environment variables:

text
export FLASK_SECRET_KEY="your-secret-key"
export API_TOKEN="your-api-token"
# For Celery/Redis:
export CELERY_BROKER_URL="redis://localhost:6379/0"
export CELERY_RESULT_BACKEND="redis://localhost:6379/0"
Run the Flask app:

text
flask db upgrade  # If using Flask-Migrate
flask run
Start Redis (for asynchronous jobs):

text
redis-server

Run Celery worker (for async PDF/report tasks):

text
celery -A tasks.celery_app worker --loglevel=info

Known Issues & Future Improvements
Testing: test_app.py has some failing tests especially for protected POST routes and Celery async integration. Fixes planned: improved test setup for roles, better client/test configuration.​

Background Jobs: Celery job triggers for PDF may require further debugging for full reliability and proper app context usage.

UI/UX: The interface uses Bootstrap and is clean, but could be made even more comprehensive and user-friendly—roadmap includes better scenario dashboards, alerts, visualizations, and onboarding flows.

Deployment: Not yet containerized (Docker), but instructions provided for local runs.

How to Contribute
Fork this repo.

Open issues for bugs or features.

Submit pull requests with thorough descriptions.

Write tests for new features.

Technologies Used
Flask (Backend Web Framework)

Flask-Login, Flask-Bcrypt, Flask-SQLAlchemy, Flask-Migrate

Flask-SocketIO for real-time chat

Flask-Caching and Redis

Celery for background tasks

Bootstrap 5 (UI)

SQLAlchemy (ORM)

pytest (Testing)

Credits
Project based on personal learning, code reviews, and help from the open-source community.

Special thanks to [RealPython] and other resources on Python/Flask best practices.​

License
MIT License

Author
Chloe Cedano

Notes for Recruiters:
This project is designed to demonstrate full-stack development skills, with focus on scalable structure, security, async logic, UI, and realistic workflow simulation. 
While not bug-free, it reflects persistence, ability to research and solve problems, and a solid codebase ready for further polishing. 
Please see “Known Issues” and “Future Improvements” for transparency about current limitations and plans for the next steps.

Want help or have questions? [Open an issue!]
