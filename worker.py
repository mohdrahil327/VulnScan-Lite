import os
from celery import Celery
from scanner.scan import scan_website

REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")

celery_app = Celery(
    "scanlite",
    broker=REDIS_URL,
    backend=REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    task_track_started=True,
    worker_send_task_events=True,
)

@celery_app.task(bind=True)
def run_scan(self, url: str):
    return scan_website(url)
