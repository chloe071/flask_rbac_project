from celery import Celery
import os

#configure a celery app instance with the broker
celery_app = Celery(
    'tasks',
    broker=os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/0'),
    backend=os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/0'),
    include=['tasks']
)

if __name__ == '__main__':
    celery_app.start()