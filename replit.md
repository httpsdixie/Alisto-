# Alisto! - EVSU-OC Campus Safety Reporting System

## Overview
Alisto! is a campus safety reporting system built with FastAPI for Eastern Visayas State University - Ormoc Campus (EVSU-OC). It allows students and faculty to report safety concerns and maintenance issues, track report status, and receive email notifications.

## Tech Stack
- **Backend**: FastAPI (Python 3.11)
- **Database**: PostgreSQL (via SQLAlchemy ORM)
- **Authentication**: JWT token-based authentication (cookies)
- **Templates**: Jinja2
- **Frontend**: Bootstrap 5 with custom CSS
- **Email**: Resend API

## Project Structure
```
├── app.py              # Main FastAPI application with all routes
├── config.py           # Application configuration
├── database.py         # Database connection and session management
├── models.py           # SQLAlchemy models (User, Report, Feedback, etc.)
├── schemas.py          # Pydantic schemas for validation
├── auth.py             # Authentication utilities (JWT, rate limiting)
├── email_service.py    # Email notification service
├── templates/          # Jinja2 HTML templates
│   ├── base.html       # Base template with navigation
│   ├── index.html      # Homepage
│   ├── auth/           # Login, Register, Password reset
│   ├── dashboard/      # User and Admin dashboards
│   ├── reports/        # Report management
│   ├── admin/          # Admin-only pages
│   └── errors/         # Error pages (404, 500)
├── static/
│   ├── css/style.css   # Custom styles
│   ├── js/main.js      # JavaScript utilities
│   ├── favicon.svg     # App favicon
│   └── uploads/        # User uploaded images
└── .gitignore
```

## Features
- **User Authentication**: Student/Faculty registration, login, password reset
- **Report Submission**: Submit safety reports with photo evidence, QR code scanning, camera capture
- **Report Tracking**: Track reports via ticket ID or user dashboard
- **Admin Dashboard**: View all reports, manage users, analytics charts
- **Email Notifications**: Report confirmation, status updates, feedback requests
- **Feedback System**: Users rate resolved reports

## Environment Variables
- `DATABASE_URL` - PostgreSQL connection string (auto-configured)
- `SESSION_SECRET` - Secret key for JWT tokens
- `RESEND_API_KEY` - (Optional) For email notifications
- `ADMIN_STUDENT_IDS` - Comma-separated list of admin IDs

## Running the Application
The application runs on port 5000 with uvicorn:
```bash
python -m uvicorn app:app --host 0.0.0.0 --port 5000 --reload
```

## Key Routes
- `/` - Homepage with public statistics
- `/login`, `/register` - Authentication
- `/dashboard` - User dashboard
- `/report/new` - Submit new report
- `/my-reports` - View user's reports
- `/track-report` - Track report by ticket ID
- `/admin/dashboard` - Admin analytics
- `/admin/reports` - Manage all reports
- `/admin/users` - User management
- `/help` - FAQ and help

## Recent Changes
- 2025-12-05: Converted from Flask to FastAPI
  - Replaced Flask-Login with JWT token authentication
  - Replaced WTForms with Pydantic schemas
  - Updated templates for FastAPI's Jinja2
  - Added security middleware (CSP, HSTS, etc.)
  - Preserved all original features

## User Preferences
- Clean, modern UI with university colors (maroon/gold)
- Mobile-responsive design
- Comprehensive admin analytics
