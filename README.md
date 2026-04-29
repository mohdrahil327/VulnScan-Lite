# VulnScan Lite / Scanlitee

A web vulnerability scanner built with an asynchronous FastAPI backend, Redis-backed Celery worker, and React user interface.

## What changed after review

This version fixes the critical submission issues identified by AntIntern:
- Added the missing scanner core in /scanner
- Populated requirements.txt with all backend dependencies
- Rewired backend to use Celery and Redis for async scanning
- Removed the conflicting FastAPI BackgroundTasks implementation
- Replaced in-memory result storage with Redis-backed Celery task state
- Added URL validation and SSRF protections for scan requests
- Restricted CORS to known frontend origins
- Added IP-based rate limiting for /api/scan
- Included frontend UI code under /frontend

## Architecture

- main.py - FastAPI API server with scanning endpoints
- worker.py - Celery worker executing scanner.scan.scan_website
- /scanner - core scanner modules for header analysis, TLS inspection, CMS detection, and URL validation
- /frontend - React dashboard and PDF export UI

## Local setup

1. Install Python dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```

2. Install frontend dependencies:
   ```bash
   cd frontend
   npm install
   ```

3. Start Redis locally:
   ```bash
   redis-server
   ```

4. Start the Celery worker:
   ```bash
   celery -A worker worker --loglevel=info
   ```

5. Start the backend API:
   ```bash
   uvicorn main:app --reload --host 127.0.0.1 --port 8000
   ```

6. Start the frontend app:
   ```bash
   npm run frontend:start
   ```

## Docker deployment

For a public deployment or hosted environment, use Docker and a separate Redis service.

Build the container image:
```bash
npm run docker:build
```

Run the whole stack locally with Docker Compose:
```bash
npm run docker:compose:up
```

Then visit http://localhost:8000 to access the app. The backend will serve the built React frontend at the root path, and the API is available at /api.

If Docker is installed on Windows, run:
```powershell
./deploy.ps1 -Up
```

## Public hosting

This project can be deployed publicly on any container platform that supports Docker, including Render, Railway, Fly.io, or a VPS.

### Render

1. Push the repo to GitHub.
2. Create a new Render web service.
3. Choose Docker deploy and connect your GitHub repo.
4. Install a Redis add-on in Render or use a hosted Redis service.
5. Set these environment variables in Render:
   - `REDIS_URL` = your Redis connection string
   - `FRONTEND_ORIGINS` = your deployed app URL (for example `https://your-app.onrender.com`)

### Railway

1. Push the repo to GitHub.
2. Create a new Railway project and connect the repository.

The render.yaml manifest and Procfile are included so hosted platforms can detect the app structure and run the backend and worker.

## Environment variables

- `REDIS_URL` - Redis connection string, default: `redis://localhost:6379/0`
- `FRONTEND_ORIGINS` - comma-separated list of allowed CORS origins
- `REACT_APP_API_URL` - frontend API base URL, default: `http://localhost:8000/api`

## API

- `POST /api/scan` - enqueue a new site scan
- `GET /api/scan/{scan_id}/status` - poll scan status
- `GET /api/result/{scan_id}` - retrieve the finished report

## Security improvements

- Input validation for `url` to reject localhost and private IPs
- CORS restricted to known frontend origins
- Rate limiting applied to the scan endpoint
- Redis-backed scanning state so task results survive process restarts
