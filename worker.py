from celery import Celery
from scanner.scan import scan_website

celery_app = Celery(
    "worker",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
)

@celery_app.task
def run_scan(url):
    return scan_website(url)