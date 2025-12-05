import os
import uuid
import html
import re
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Request, Depends, HTTPException, status, Form, UploadFile, File, Query
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func, case
from werkzeug.utils import secure_filename
from PIL import Image

from config import settings
from database import engine, get_db, Base
from models import User, Report, StatusHistory, Feedback, Notification
from schemas import (
    LoginRequest, RegistrationRequest, ForgotPasswordRequest, ResetPasswordRequest,
    ReportCreate, ReportUpdate, FeedbackCreate, UpdateProfileRequest, HomeStats
)
from auth import (
    get_current_user, get_current_user_optional, get_current_admin,
    create_access_token, check_rate_limit, record_failed_login, reset_login_attempts
)
from email_service import (
    init_resend, send_report_confirmation, send_status_update, 
    send_feedback_request, send_password_reset, send_admin_new_report_notification
)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Alisto! - EVSU-OC Campus Safety Reporting System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

os.makedirs(settings.UPLOAD_FOLDER, exist_ok=True)
os.makedirs('static/css', exist_ok=True)
os.makedirs('static/js', exist_ok=True)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Add timezone conversion filter for Philippine Time (UTC+8)
def to_philippine_time(utc_dt):
    if utc_dt is None:
        return None
    # Add 8 hours to convert UTC to Philippine Time
    philippine_dt = utc_dt + timedelta(hours=8)
    return philippine_dt

templates.env.filters['philippine_time'] = to_philippine_time

init_resend()

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net fonts.googleapis.com; img-src 'self' data:; font-src 'self' cdn.jsdelivr.net fonts.gstatic.com"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    return response

def sanitize_input(text: str) -> str:
    if not text:
        return text
    text = html.escape(text)
    text = text.replace('\x00', '')
    return text.strip()

def sanitize_filename_custom(filename: str) -> str:
    filename = secure_filename(filename)
    filename = re.sub(r'[^\w\s.-]', '', filename)
    return filename[:255]

def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in settings.ALLOWED_EXTENSIONS

async def save_photo(file: UploadFile) -> Optional[str]:
    try:
        if file and file.filename and allowed_file(file.filename):
            filename = sanitize_filename_custom(file.filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            filepath = os.path.join(settings.UPLOAD_FOLDER, unique_filename)
            
            contents = await file.read()
            if len(contents) > 5 * 1024 * 1024:
                return None
            
            import io
            img = Image.open(io.BytesIO(contents))
            img.thumbnail((1200, 1200))
            img.save(filepath, quality=85, optimize=True)
            
            return unique_filename
    except Exception as e:
        print(f"Error saving photo: {str(e)}")
        return None
    return None

def get_notifications(db: Session, user: Optional[User]) -> list:
    if user and user.is_admin:
        return db.query(Notification).order_by(Notification.created_at.desc()).limit(20).all()
    return []

def get_unread_notifications_count(db: Session, user: Optional[User]) -> int:
    if user and user.is_admin:
        return db.query(Notification).filter_by(is_read=False).count()
    return 0

def get_flash_messages(request: Request) -> list:
    messages = request.cookies.get("flash_messages", "")
    if messages:
        return messages.split("|")
    return []

def add_flash_message(response, message: str, category: str = "info"):
    current = response.headers.get("Set-Cookie", "")
    response.set_cookie("flash_message", f"{category}:{message}", max_age=5)

@app.get("/favicon.ico")
async def favicon():
    return FileResponse("static/favicon.svg", media_type="image/svg+xml")

@app.get("/", response_class=HTMLResponse)
async def index(
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    if current_user:
        return RedirectResponse(url="/dashboard", status_code=302)
    flash_message = request.cookies.get("flash_message", "")
    return templates.TemplateResponse("index.html", {
        "request": request,
        "current_user": None,
        "flash_message": flash_message
    })

@app.get("/api/home-stats")
async def get_home_stats(db: Session = Depends(get_db)):
    try:
        total_reports = db.query(Report).count()
        pending = db.query(Report).filter_by(status='Pending').count()
        in_progress = db.query(Report).filter_by(status='In Progress').count()
        resolved = db.query(Report).filter_by(status='Resolved').count()
        
        recently_resolved = db.query(Report).filter_by(status='Resolved').order_by(
            Report.updated_at.desc()
        ).limit(6).all()
        
        resolved_data = []
        for report in recently_resolved:
            resolved_data.append({
                'ticket_id': report.ticket_id,
                'title': report.title[:50],
                'category': report.category,
                'resolved_at': report.updated_at.strftime('%b %d, %Y')
            })
        
        categories = ['Infrastructure', 'Electrical', 'Plumbing', 'Sanitation', 'Safety Hazard', 'Security', 'Other']
        category_updates = []
        for category in categories:
            latest = db.query(Report).filter_by(category=category).order_by(Report.updated_at.desc()).first()
            if latest:
                category_updates.append({
                    'category': category,
                    'last_update': latest.updated_at.strftime('%b %d, %Y %I:%M %p')
                })
            else:
                category_updates.append({
                    'category': category,
                    'last_update': 'No reports yet'
                })
        
        priorities = ['High', 'Medium', 'Low']
        priority_data = []
        for priority in priorities:
            count = db.query(Report).filter_by(priority=priority).count()
            priority_data.append({
                'priority': priority,
                'count': count
            })
        
        avg_rating_result = db.query(func.avg(Feedback.rating)).filter(Feedback.rating > 0).first()
        avg_rating = float(avg_rating_result[0]) if avg_rating_result and avg_rating_result[0] else 0.0
        avg_rating = round(avg_rating, 1) if avg_rating > 0 else 4.8
        
        rounded_stars = round(avg_rating)
        filled_stars = min(5, max(0, rounded_stars))
        empty_stars = 5 - filled_stars
        star_display = ('★' * filled_stars) + ('☆' * empty_stars)
        
        return {
            'total': total_reports,
            'pending': pending,
            'in_progress': in_progress,
            'resolved': resolved,
            'rating': avg_rating,
            'stars': star_display,
            'recently_resolved': resolved_data,
            'category_updates': category_updates,
            'priority_data': priority_data
        }
    except Exception as e:
        print(f"Error getting home stats: {str(e)}")
        return {
            'total': 0, 'pending': 0, 'in_progress': 0, 'resolved': 0,
            'recently_resolved': [],
            'category_updates': [],
            'priority_data': []
        }

@app.get("/login", response_class=HTMLResponse)
async def login_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    if current_user:
        return RedirectResponse(url="/dashboard", status_code=302)
    flash_message = request.cookies.get("flash_message", "")
    return templates.TemplateResponse("auth/login.html", {
        "request": request,
        "current_user": None,
        "flash_message": flash_message
    })

@app.post("/login")
async def login(
    request: Request,
    db: Session = Depends(get_db),
    student_id: str = Form(...),
    password: str = Form(...),
    remember_me: bool = Form(False)
):
    client_ip = request.client.host
    
    if not check_rate_limit(client_ip):
        response = RedirectResponse(url="/login", status_code=302)
        response.set_cookie("flash_message", "danger:Too many failed login attempts. Please try again in 15 minutes.", max_age=5)
        return response
    
    user = db.query(User).filter_by(student_id=student_id).first()
    if user and user.check_password(password):
        reset_login_attempts(client_ip)
        
        if not user.is_active:
            response = RedirectResponse(url="/login", status_code=302)
            response.set_cookie("flash_message", "danger:Your account has been deactivated. Please contact admin.", max_age=5)
            return response
        
        expires_delta = timedelta(days=7) if remember_me else timedelta(hours=24)
        access_token = create_access_token(data={"sub": str(user.id)}, expires_delta=expires_delta)
        
        response = RedirectResponse(url="/dashboard", status_code=302)
        response.set_cookie(
            key="access_token",
            value=f"Bearer {access_token}",
            httponly=True,
            max_age=expires_delta.total_seconds(),
            samesite="lax"
        )
        response.set_cookie("flash_message", f"success:Welcome back, {user.full_name}!", max_age=5)
        return response
    
    record_failed_login(client_ip)
    response = RedirectResponse(url="/login", status_code=302)
    response.set_cookie("flash_message", "danger:Invalid ID or password.", max_age=5)
    return response

@app.get("/register", response_class=HTMLResponse)
async def register_page(
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    if current_user:
        return RedirectResponse(url="/dashboard", status_code=302)
    flash_message = request.cookies.get("flash_message", "")
    return templates.TemplateResponse("auth/register.html", {
        "request": request,
        "current_user": None,
        "flash_message": flash_message
    })

@app.post("/register")
async def register(
    request: Request,
    db: Session = Depends(get_db),
    user_type: str = Form(...),
    student_id: str = Form(...),
    username: str = Form(...),
    full_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...)
):
    student_id = sanitize_input(student_id)
    email = sanitize_input(email)
    username = sanitize_input(username)
    full_name = sanitize_input(full_name)
    
    pattern = r'^\d{4}-\d{5}$'
    if not re.match(pattern, student_id):
        response = RedirectResponse(url="/register", status_code=302)
        response.set_cookie("flash_message", "danger:ID must be in format YYYY-NNNNN (e.g., 2024-12345)", max_age=5)
        return response
    
    if password != confirm_password:
        response = RedirectResponse(url="/register", status_code=302)
        response.set_cookie("flash_message", "danger:Passwords must match.", max_age=5)
        return response
    
    if db.query(User).filter_by(student_id=student_id).first():
        response = RedirectResponse(url="/register", status_code=302)
        response.set_cookie("flash_message", "danger:ID already registered.", max_age=5)
        return response
    
    if db.query(User).filter_by(email=email).first():
        response = RedirectResponse(url="/register", status_code=302)
        response.set_cookie("flash_message", "danger:Email already registered.", max_age=5)
        return response
    
    if db.query(User).filter_by(username=username).first():
        response = RedirectResponse(url="/register", status_code=302)
        response.set_cookie("flash_message", "danger:Username already taken.", max_age=5)
        return response
    
    is_admin = student_id in settings.ADMIN_STUDENT_IDS
    
    user = User(
        student_id=student_id,
        user_type=user_type,
        username=username,
        full_name=full_name,
        email=email,
        is_admin=is_admin
    )
    user.set_password(password)
    
    db.add(user)
    db.commit()
    
    response = RedirectResponse(url="/login", status_code=302)
    response.set_cookie("flash_message", "success:Registration successful! Please log in.", max_age=5)
    return response

@app.get("/logout")
async def logout(current_user: User = Depends(get_current_user)):
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("access_token")
    response.set_cookie("flash_message", "info:You have been logged out.", max_age=5)
    return response

@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    if current_user:
        return RedirectResponse(url="/dashboard", status_code=302)
    flash_message = request.cookies.get("flash_message", "")
    return templates.TemplateResponse("auth/forgot_password.html", {
        "request": request,
        "current_user": None,
        "flash_message": flash_message
    })

@app.post("/forgot-password")
async def forgot_password(
    request: Request,
    db: Session = Depends(get_db),
    email: str = Form(...)
):
    user = db.query(User).filter_by(email=email).first()
    if user:
        token = user.generate_reset_token(settings.SECRET_KEY)
        reset_url = str(request.url_for('reset_password_page', token=token))
        send_password_reset(user, reset_url)
    
    response = RedirectResponse(url="/login", status_code=302)
    response.set_cookie("flash_message", "info:If an account with that email exists, a password reset link has been sent.", max_age=5)
    return response

@app.get("/reset-password/{token}", response_class=HTMLResponse)
async def reset_password_page(
    request: Request,
    token: str,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    if current_user:
        return RedirectResponse(url="/dashboard", status_code=302)
    
    email = User.verify_reset_token(token, settings.SECRET_KEY)
    if not email:
        response = RedirectResponse(url="/forgot-password", status_code=302)
        response.set_cookie("flash_message", "danger:The password reset link is invalid or has expired.", max_age=5)
        return response
    
    flash_message = request.cookies.get("flash_message", "")
    return templates.TemplateResponse("auth/reset_password.html", {
        "request": request,
        "current_user": None,
        "token": token,
        "flash_message": flash_message
    })

@app.post("/reset-password/{token}")
async def reset_password(
    token: str,
    db: Session = Depends(get_db),
    password: str = Form(...),
    confirm_password: str = Form(...)
):
    email = User.verify_reset_token(token, settings.SECRET_KEY)
    if not email:
        response = RedirectResponse(url="/forgot-password", status_code=302)
        response.set_cookie("flash_message", "danger:The password reset link is invalid or has expired.", max_age=5)
        return response
    
    if password != confirm_password:
        response = RedirectResponse(url=f"/reset-password/{token}", status_code=302)
        response.set_cookie("flash_message", "danger:Passwords must match.", max_age=5)
        return response
    
    user = db.query(User).filter_by(email=email).first()
    if user:
        user.set_password(password)
        db.commit()
    
    response = RedirectResponse(url="/login", status_code=302)
    response.set_cookie("flash_message", "success:Your password has been reset successfully! You can now log in.", max_age=5)
    return response

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if current_user.is_admin:
        return RedirectResponse(url="/admin/dashboard", status_code=302)
    
    reports = db.query(Report).filter_by(user_id=current_user.id).order_by(Report.created_at.desc()).limit(5).all()
    
    pending_count = db.query(Report).filter_by(user_id=current_user.id, status='Pending').count()
    in_progress_count = db.query(Report).filter_by(user_id=current_user.id, status='In Progress').count()
    resolved_count = db.query(Report).filter_by(user_id=current_user.id, status='Resolved').count()
    
    flash_message = request.cookies.get("flash_message", "")
    return templates.TemplateResponse("dashboard/user_dashboard.html", {
        "request": request,
        "current_user": current_user,
        "reports": reports,
        "pending_count": pending_count,
        "in_progress_count": in_progress_count,
        "resolved_count": resolved_count,
        "flash_message": flash_message
    })

@app.get("/admin/dashboard", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    db.query(Notification).filter(Notification.created_at < seven_days_ago).delete()
    
    notification_count = db.query(Notification).count()
    if notification_count > 20:
        oldest = db.query(Notification).order_by(Notification.created_at.asc()).first()
        if oldest:
            db.delete(oldest)
    db.commit()
    
    reports = db.query(Report).order_by(Report.updated_at.desc()).limit(10).all()
    
    pending_count = db.query(Report).filter_by(status='Pending').count()
    in_progress_count = db.query(Report).filter_by(status='In Progress').count()
    resolved_count = db.query(Report).filter_by(status='Resolved').count()
    total_users = db.query(User).count()
    
    total_feedbacks = db.query(Feedback).count()
    avg_rating = 0
    satisfaction_percentage = 0
    if total_feedbacks > 0:
        avg_rating = db.query(func.avg(Feedback.rating)).scalar() or 0
        avg_rating = round(float(avg_rating), 2)
        satisfaction_percentage = round((avg_rating / 5.0) * 100, 1)
    
    # Get category and priority stats for charts
    categories = {}
    for category in ['Infrastructure', 'Safety Hazard', 'Electrical', 'Plumbing', 'Sanitation', 'Security', 'Other']:
        count = db.query(Report).filter_by(category=category).count()
        if count > 0:
            categories[category] = count
    
    priorities = {}
    for priority in ['Low', 'Medium', 'High']:
        count = db.query(Report).filter_by(priority=priority).count()
        priorities[priority] = count
    
    flash_message = request.cookies.get("flash_message", "")
    return templates.TemplateResponse("dashboard/admin_dashboard.html", {
        "request": request,
        "current_user": current_user,
        "reports": reports,
        "pending_count": pending_count,
        "in_progress_count": in_progress_count,
        "resolved_count": resolved_count,
        "total_users": total_users,
        "total_feedbacks": total_feedbacks,
        "avg_rating": avg_rating,
        "satisfaction_percentage": satisfaction_percentage,
        "categories": categories,
        "priorities": priorities,
        "flash_message": flash_message
    })

@app.get("/report/new", response_class=HTMLResponse)
async def new_report_page(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    flash_message = request.cookies.get("flash_message", "")
    return templates.TemplateResponse("reports/new_report.html", {
        "request": request,
        "current_user": current_user,
        "flash_message": flash_message
    })

@app.post("/report/new")
async def new_report(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    title: str = Form(...),
    location: str = Form(...),
    description: str = Form(...),
    category: str = Form(...),
    priority: str = Form(default="Medium"),
    photo: UploadFile = File(default=None)
):
    print(f"DEBUG: Report submission started for user {current_user.student_id}")
    print(f"DEBUG: Title={title}, Location={location}, Category={category}, Priority={priority}")
    print(f"DEBUG: Photo={photo}, Photo filename={photo.filename if photo else 'None'}")
    
    last_24_hours = datetime.utcnow() - timedelta(hours=24)
    
    reports_today = db.query(Report).filter_by(user_id=current_user.id).filter(
        Report.created_at >= last_24_hours
    ).count()
    
    if reports_today >= 5:
        response = RedirectResponse(url="/report/new", status_code=302)
        response.set_cookie("flash_message", "warning:You have reached the daily limit of 5 reports. Please try again tomorrow.", max_age=5)
        return response
    
    duplicate = db.query(Report).filter_by(
        user_id=current_user.id,
        title=title,
        location=location
    ).filter(Report.created_at >= last_24_hours).first()
    
    if duplicate:
        response = RedirectResponse(url="/report/new", status_code=302)
        response.set_cookie("flash_message", "warning:You already submitted a similar report recently.", max_age=5)
        return response
    
    photo_filename = None
    if photo and photo.filename:
        photo_filename = await save_photo(photo)
    
    try:
        report = Report(
            title=sanitize_input(title),
            location=sanitize_input(location),
            description=sanitize_input(description),
            category=category,
            priority=priority,
            photo_path=photo_filename,
            user_id=current_user.id
        )
        
        db.add(report)
        db.commit()
        db.refresh(report)
    except Exception as e:
        print(f"Error creating report: {str(e)}")
        db.rollback()
        response = RedirectResponse(url="/report/new", status_code=302)
        response.set_cookie("flash_message", f"danger:Error submitting report: {str(e)}", max_age=5)
        return response
    
    try:
        status_history = StatusHistory(
            report_id=report.id,
            old_status=None,
            new_status='Pending',
            notes='Report submitted',
            changed_by_id=current_user.id
        )
        db.add(status_history)
        
        notification = Notification(
            type='report_submitted',
            user_student_id=current_user.student_id,
            user_name=current_user.full_name,
            report_ticket_id=report.ticket_id,
            report_title=report.title,
            deletion_reason=None,
            is_read=False
        )
        db.add(notification)
        db.commit()
        
        notification_count = db.query(Notification).count()
        if notification_count > 20:
            oldest = db.query(Notification).order_by(Notification.created_at.asc()).first()
            if oldest:
                db.delete(oldest)
                db.commit()
        
        try:
            # Send confirmation email to user
            send_report_confirmation(current_user, report)
        except Exception as email_error:
            print(f"Email sending failed: {str(email_error)}")
    except Exception as e:
        print(f"Error creating status history/notification: {str(e)}")
        db.rollback()
    
    response = RedirectResponse(url="/my-reports", status_code=302)
    response.set_cookie("flash_message", f"success:Report submitted successfully! Your Ticket ID: {report.ticket_id}", max_age=5)
    return response

@app.get("/my-reports", response_class=HTMLResponse)
async def my_reports(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1),
    keyword: str = Query("", alias="keyword"),
    category: str = Query("", alias="category"),
    priority: str = Query("", alias="priority"),
    status: str = Query("", alias="status"),
    sort_by: str = Query("newest", alias="sort_by")
):
    query = db.query(Report).filter_by(user_id=current_user.id)
    
    if keyword:
        query = query.filter(
            (Report.title.ilike(f'%{keyword}%')) | 
            (Report.description.ilike(f'%{keyword}%')) |
            (Report.location.ilike(f'%{keyword}%')) |
            (Report.ticket_id.ilike(f'%{keyword}%'))
        )
    if category:
        query = query.filter_by(category=category)
    if priority:
        query = query.filter_by(priority=priority)
    if status:
        query = query.filter_by(status=status)
    
    if sort_by == 'oldest':
        query = query.order_by(Report.created_at.asc())
    elif sort_by == 'priority_high':
        query = query.order_by(case(
            (Report.priority == 'High', 1),
            (Report.priority == 'Medium', 2),
            (Report.priority == 'Low', 3)
        ))
    elif sort_by == 'priority_low':
        query = query.order_by(case(
            (Report.priority == 'Low', 1),
            (Report.priority == 'Medium', 2),
            (Report.priority == 'High', 3)
        ))
    else:
        query = query.order_by(Report.created_at.desc())
    
    total = query.count()
    per_page = 10
    total_pages = (total + per_page - 1) // per_page
    reports = query.offset((page - 1) * per_page).limit(per_page).all()
    
    flash_message = request.cookies.get("flash_message", "")
    return templates.TemplateResponse("reports/my_reports.html", {
        "request": request,
        "current_user": current_user,
        "reports": reports,
        "page": page,
        "total_pages": total_pages,
        "total": total,
        "keyword": keyword,
        "category": category,
        "priority": priority,
        "status": status,
        "sort_by": sort_by,
        "flash_message": flash_message
    })

@app.get("/report/{report_id}", response_class=HTMLResponse)
async def view_report(
    request: Request,
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    report = db.query(Report).filter_by(id=report_id).first()
    
    if not report:
        response = RedirectResponse(url="/my-reports", status_code=302)
        response.set_cookie("flash_message", "warning:This report has been deleted and cannot be retrieved.", max_age=5)
        return response
    
    if not current_user.is_admin and report.user_id != current_user.id:
        response = RedirectResponse(url="/dashboard", status_code=302)
        response.set_cookie("flash_message", "danger:Access denied.", max_age=5)
        return response
    
    status_history = db.query(StatusHistory).filter_by(report_id=report_id).order_by(StatusHistory.created_at.desc()).all()
    reporter = db.query(User).filter_by(id=report.user_id).first()
    
    flash_message = request.cookies.get("flash_message", "")
    return templates.TemplateResponse("reports/view_report.html", {
        "request": request,
        "current_user": current_user,
        "report": report,
        "reporter": reporter,
        "status_history": status_history,
        "flash_message": flash_message
    })

@app.post("/report/{report_id}/feedback")
async def submit_feedback(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    rating: int = Form(...),
    comments: str = Form("")
):
    report = db.query(Report).filter_by(id=report_id).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    if report.user_id != current_user.id:
        response = RedirectResponse(url="/dashboard", status_code=302)
        response.set_cookie("flash_message", "danger:Access denied.", max_age=5)
        return response
    
    if report.status != 'Resolved':
        response = RedirectResponse(url=f"/report/{report_id}", status_code=302)
        response.set_cookie("flash_message", "warning:Feedback can only be submitted for resolved reports.", max_age=5)
        return response
    
    existing_feedback = db.query(Feedback).filter_by(report_id=report_id).first()
    if existing_feedback:
        response = RedirectResponse(url=f"/report/{report_id}", status_code=302)
        response.set_cookie("flash_message", "info:You have already submitted feedback for this report.", max_age=5)
        return response
    
    feedback = Feedback(
        report_id=report_id,
        user_id=current_user.id,
        rating=rating,
        comments=sanitize_input(comments),
        resolution_confirmed=True
    )
    db.add(feedback)
    db.commit()
    
    response = RedirectResponse(url=f"/report/{report_id}", status_code=302)
    response.set_cookie("flash_message", "success:Thank you for your feedback!", max_age=5)
    return response

@app.post("/report/{report_id}/delete")
async def delete_report(
    report_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    deletion_reason: str = Form(...)
):
    try:
        print(f"DELETE ROUTE CALLED: report_id={report_id}, user_id={current_user.id}, deletion_reason={deletion_reason}")
        report = db.query(Report).filter_by(id=report_id).first()
        
        if not report:
            print(f"ERROR: Report {report_id} not found in database")
            response = RedirectResponse(url="/my-reports", status_code=302)
            response.set_cookie("flash_message", "warning:Report not found.", max_age=5)
            return response
        
        if report.user_id != current_user.id:
            response = RedirectResponse(url="/dashboard", status_code=302)
            response.set_cookie("flash_message", "danger:Access denied.", max_age=5)
            return response
        
        if report.status != 'Pending':
            response = RedirectResponse(url=f"/report/{report_id}", status_code=302)
            response.set_cookie("flash_message", "warning:Only pending reports can be deleted.", max_age=5)
            return response
        
        if len(deletion_reason.strip()) < 5:
            response = RedirectResponse(url=f"/report/{report_id}", status_code=302)
            response.set_cookie("flash_message", "danger:Deletion reason must be at least 5 characters.", max_age=5)
            return response
        
        # Create notification for admin
        notification = Notification(
            type='report_deleted',
            user_student_id=current_user.student_id,
            user_name=current_user.full_name,
            report_ticket_id=report.ticket_id,
        report_title=report.title,
        deletion_reason=sanitize_input(deletion_reason),
        is_read=False
    )
        db.add(notification)
        
        # Delete associated records
        db.query(StatusHistory).filter_by(report_id=report_id).delete()
        db.query(Feedback).filter_by(report_id=report_id).delete()
        
        # Delete the report
        db.delete(report)
        db.commit()
        
        print(f"SUCCESS: Report {report_id} deleted successfully")
        response = RedirectResponse(url="/my-reports", status_code=302)
        response.set_cookie("flash_message", "success:Report deleted successfully.", max_age=5)
        return response
    except Exception as e:
        print(f"ERROR deleting report: {str(e)}")
        db.rollback()
        response = RedirectResponse(url="/my-reports", status_code=302)
        response.set_cookie("flash_message", "danger:Failed to delete report. Please try again.", max_age=5)
        return response

@app.get("/track-report", response_class=HTMLResponse)
async def track_report_page(
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    flash_message = request.cookies.get("flash_message", "")
    return templates.TemplateResponse("reports/track_report.html", {
        "request": request,
        "current_user": current_user,
        "report": None,
        "status_history": None,
        "flash_message": flash_message
    })

@app.post("/track-report", response_class=HTMLResponse)
async def track_report(
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user_optional),
    ticket_id: str = Form(...)
):
    report = db.query(Report).filter_by(ticket_id=ticket_id.strip().upper()).first()
    status_history = None
    
    if report:
        status_history = db.query(StatusHistory).filter_by(report_id=report.id).order_by(StatusHistory.created_at.desc()).all()
    
    flash_message = request.cookies.get("flash_message", "")
    if not report:
        flash_message = "warning:No report found with that Ticket ID."
    
    return templates.TemplateResponse("reports/track_report.html", {
        "request": request,
        "current_user": current_user,
        "report": report,
        "status_history": status_history,
        "flash_message": flash_message
    })

@app.get("/admin/reports", response_class=HTMLResponse)
async def admin_reports(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin),
    page: int = Query(1, ge=1),
    keyword: str = Query("", alias="keyword"),
    category: str = Query("", alias="category"),
    priority: str = Query("", alias="priority"),
    status: str = Query("", alias="status"),
    sort_by: str = Query("newest", alias="sort_by")
):
    query = db.query(Report)
    
    if keyword:
        query = query.filter(
            (Report.title.ilike(f'%{keyword}%')) | 
            (Report.description.ilike(f'%{keyword}%')) |
            (Report.location.ilike(f'%{keyword}%')) |
            (Report.ticket_id.ilike(f'%{keyword}%'))
        )
    if category:
        query = query.filter_by(category=category)
    if priority:
        query = query.filter_by(priority=priority)
    if status:
        query = query.filter_by(status=status)
    
    if sort_by == 'oldest':
        query = query.order_by(Report.created_at.asc())
    elif sort_by == 'priority_high':
        query = query.order_by(case(
            (Report.priority == 'High', 1),
            (Report.priority == 'Medium', 2),
            (Report.priority == 'Low', 3)
        ))
    elif sort_by == 'priority_low':
        query = query.order_by(case(
            (Report.priority == 'Low', 1),
            (Report.priority == 'Medium', 2),
            (Report.priority == 'High', 3)
        ))
    else:
        query = query.order_by(Report.created_at.desc())
    
    total = query.count()
    per_page = 10
    total_pages = (total + per_page - 1) // per_page
    reports = query.offset((page - 1) * per_page).limit(per_page).all()
    
    flash_message = request.cookies.get("flash_message", "")
    return templates.TemplateResponse("admin/reports.html", {
        "request": request,
        "current_user": current_user,
        "reports": reports,
        "page": page,
        "total_pages": total_pages,
        "total": total,
        "keyword": keyword,
        "category": category,
        "priority": priority,
        "status": status,
        "sort_by": sort_by,
        "flash_message": flash_message
    })

@app.get("/admin/report/{report_id}", response_class=HTMLResponse)
async def admin_view_report(
    request: Request,
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    report = db.query(Report).filter_by(id=report_id).first()
    
    if not report:
        response = RedirectResponse(url="/admin/reports", status_code=302)
        response.set_cookie("flash_message", "warning:Report not found.", max_age=5)
        return response
    
    status_history = db.query(StatusHistory).filter_by(report_id=report_id).order_by(StatusHistory.created_at.desc()).all()
    reporter = db.query(User).filter_by(id=report.user_id).first()
    feedback = db.query(Feedback).filter_by(report_id=report_id).first()
    
    flash_message = request.cookies.get("flash_message", "")
    return templates.TemplateResponse("admin/view_report.html", {
        "request": request,
        "current_user": current_user,
        "report": report,
        "reporter": reporter,
        "status_history": status_history,
        "feedback": feedback,
        "flash_message": flash_message
    })

@app.post("/admin/report/{report_id}")
async def admin_update_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin),
    status: str = Form(...),
    priority: str = Form(...),
    admin_notes: str = Form(""),
    proof: Optional[UploadFile] = File(None)
):
    report = db.query(Report).filter_by(id=report_id).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    old_status = report.status
    
    if status != old_status:
        status_history = StatusHistory(
            report_id=report.id,
            old_status=old_status,
            new_status=status,
            notes=admin_notes,
            changed_by_id=current_user.id
        )
        db.add(status_history)
        
        if status == 'Resolved':
            report.resolved_at = datetime.utcnow()
        
        reporter = db.query(User).filter_by(id=report.user_id).first()
        if reporter:
            send_status_update(reporter, report, old_status, status)
            if status == 'Resolved':
                send_feedback_request(reporter, report)
    
    report.status = status
    report.priority = priority
    report.admin_notes = sanitize_input(admin_notes)
    report.assigned_admin_id = current_user.id
    
    if proof and proof.filename:
        proof_filename = await save_photo(proof)
        if proof_filename:
            report.proof_path = proof_filename
    
    db.commit()
    
    response = RedirectResponse(url=f"/admin/report/{report_id}", status_code=302)
    response.set_cookie("flash_message", "success:Report updated successfully!", max_age=5)
    return response

@app.get("/admin/users", response_class=HTMLResponse)
async def admin_users(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin),
    page: int = Query(1, ge=1),
    category: str = Query("all", alias="category"),
    keyword: str = Query("", alias="keyword")
):
    query = db.query(User)
    
    # Filter by category
    if category == "students":
        query = query.filter_by(user_type='Student', is_admin=False)
    elif category == "faculty":
        query = query.filter_by(user_type='Faculty', is_admin=False)
    elif category == "admin":
        query = query.filter_by(is_admin=True)
    
    if keyword:
        query = query.filter(
            (User.student_id.ilike(f'%{keyword}%')) | 
            (User.username.ilike(f'%{keyword}%')) |
            (User.full_name.ilike(f'%{keyword}%')) |
            (User.email.ilike(f'%{keyword}%'))
        )
    
    query = query.order_by(User.created_at.desc())
    
    total = query.count()
    per_page = 10
    total_pages = (total + per_page - 1) // per_page
    users = query.offset((page - 1) * per_page).limit(per_page).all()
    
    # Get notification counts for each user
    user_notifications = {}
    for user in users:
        user_notifications[user.id] = db.query(Notification).filter_by(user_student_id=user.student_id, is_read=False).count()
    
    flash_message = request.cookies.get("flash_message", "")
    return templates.TemplateResponse("admin/users.html", {
        "request": request,
        "current_user": current_user,
        "users": users,
        "user_notifications": user_notifications,
        "page": page,
        "total_pages": total_pages,
        "total": total,
        "category": category,
        "keyword": keyword,
        "flash_message": flash_message
    })

@app.post("/admin/user/{user_id}/toggle-status")
async def toggle_user_status(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    user = db.query(User).filter_by(id=user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.id == current_user.id:
        response = RedirectResponse(url="/admin/users", status_code=302)
        response.set_cookie("flash_message", "danger:You cannot deactivate your own account.", max_age=5)
        return response
    
    user.is_active = not user.is_active
    db.commit()
    
    status_text = "activated" if user.is_active else "deactivated"
    response = RedirectResponse(url="/admin/users", status_code=302)
    response.set_cookie("flash_message", f"success:User {user.full_name} has been {status_text}.", max_age=5)
    return response

@app.post("/admin/user/{user_id}/toggle-admin")
async def toggle_admin_status(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    user = db.query(User).filter_by(id=user_id).first()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.id == current_user.id:
        response = RedirectResponse(url="/admin/users", status_code=302)
        response.set_cookie("flash_message", "danger:You cannot change your own admin status.", max_age=5)
        return response
    
    user.is_admin = not user.is_admin
    db.commit()
    
    status_text = "granted admin privileges" if user.is_admin else "removed admin privileges"
    response = RedirectResponse(url="/admin/users", status_code=302)
    response.set_cookie("flash_message", f"success:User {user.full_name} has been {status_text}.", max_age=5)
    return response

@app.post("/notifications/mark-read")
async def mark_notifications_read(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    try:
        db.query(Notification).filter_by(is_read=False).update({'is_read': True})
        db.commit()
        return {"success": True}
    except Exception as e:
        db.rollback()
        print(f"Error marking notifications as read: {str(e)}")
        return JSONResponse(status_code=500, content={"success": False, "error": "Failed to update notifications"})

@app.get("/api/report-stats")
async def get_report_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    categories = ['Infrastructure', 'Electrical', 'Plumbing', 'Sanitation', 'Safety Hazard', 'Security', 'Other']
    by_category = {}
    for category in categories:
        by_category[category] = db.query(Report).filter_by(category=category).count()
    
    priorities = ['High', 'Medium', 'Low']
    by_priority = {}
    for priority in priorities:
        by_priority[priority] = db.query(Report).filter_by(priority=priority).count()
    
    by_status = {
        'Pending': db.query(Report).filter_by(status='Pending').count(),
        'In Progress': db.query(Report).filter_by(status='In Progress').count(),
        'Resolved': db.query(Report).filter_by(status='Resolved').count()
    }
    
    return {
        'by_category': by_category,
        'by_priority': by_priority,
        'by_status': by_status
    }

@app.get("/api/recent-reports")
async def get_recent_reports(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    reports = db.query(Report).order_by(Report.created_at.desc()).limit(10).all()
    return [{
        'id': r.id,
        'ticket_id': r.ticket_id,
        'title': r.title[:50],
        'category': r.category,
        'priority': r.priority,
        'status': r.status,
        'created_at': r.created_at.strftime('%b %d, %Y %I:%M %p')
    } for r in reports]

@app.get("/api/user/report-updates")
async def get_user_report_updates(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    reports = db.query(Report).filter_by(user_id=current_user.id).order_by(Report.updated_at.desc()).all()
    return {
        'updates': [{
            'ticket_id': r.ticket_id,
            'title': r.title,
            'status': r.status,
            'updated': r.updated_at.isoformat() if r.updated_at else r.created_at.isoformat()
        } for r in reports]
    }

@app.get("/api/reports/stats")
async def get_reports_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    try:
        # Check if user is admin - return all stats, otherwise return user-specific stats
        if current_user.is_admin:
            pending = db.query(Report).filter_by(status='Pending').count()
            in_progress = db.query(Report).filter_by(status='In Progress').count()
            resolved = db.query(Report).filter_by(status='Resolved').count()
            
            # Get satisfaction data for admin
            total_feedbacks = db.query(Feedback).count()
            avg_rating = 0
            satisfaction_percentage = 0
            if total_feedbacks > 0:
                avg_rating = db.query(func.avg(Feedback.rating)).scalar() or 0
                avg_rating = round(float(avg_rating), 2)
                satisfaction_percentage = round((avg_rating / 5.0) * 100, 1)
            
            # Get category and priority stats
            categories = {}
            for category in ['Infrastructure', 'Security', 'Health & Safety', 'Environmental', 'Technology', 'Other']:
                count = db.query(Report).filter_by(category=category).count()
                if count > 0:
                    categories[category] = count
            
            priorities = {}
            for priority in ['Low', 'Medium', 'High']:
                count = db.query(Report).filter_by(priority=priority).count()
                priorities[priority] = count
            
            return {
                'status': {
                    'pending': pending,
                    'in_progress': in_progress,
                    'resolved': resolved
                },
                'satisfaction': {
                    'avg_rating': avg_rating,
                    'total_feedbacks': total_feedbacks,
                    'percentage': satisfaction_percentage
                },
                'categories': categories,
                'priorities': priorities
            }
        else:
            # Regular user - only their reports
            pending = db.query(Report).filter_by(user_id=current_user.id, status='Pending').count()
            in_progress = db.query(Report).filter_by(user_id=current_user.id, status='In Progress').count()
            resolved = db.query(Report).filter_by(user_id=current_user.id, status='Resolved').count()
            
            return {
                'status': {
                    'pending': pending,
                    'in_progress': in_progress,
                    'resolved': resolved
                }
            }
    except Exception as e:
        print(f"Error getting report stats: {str(e)}")
        return {
            'status': {
                'pending': 0,
                'in_progress': 0,
                'resolved': 0
            }
        }

@app.get("/api/admin/notifications")
async def get_admin_notifications(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    notifications = db.query(Notification).order_by(Notification.created_at.desc()).limit(20).all()
    unread_count = db.query(Notification).filter_by(is_read=False).count()
    
    return {
        'notifications': [{
            'id': n.id,
            'type': n.type,
            'user_name': n.user_name,
            'user_student_id': n.user_student_id,
            'report_ticket_id': n.report_ticket_id,
            'report_title': n.report_title,
            'deletion_reason': n.deletion_reason,
            'is_read': n.is_read,
            'created_at': n.created_at.isoformat()
        } for n in notifications],
        'unread_count': unread_count
    }

@app.post("/api/admin/notifications/mark-read")
async def mark_admin_notifications_read(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin)
):
    db.query(Notification).update({'is_read': True})
    db.commit()
    return {'success': True}

@app.get("/profile", response_class=HTMLResponse)
async def profile_page(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    total_reports = db.query(Report).filter_by(user_id=current_user.id).count()
    pending_reports = db.query(Report).filter_by(user_id=current_user.id, status='Pending').count()
    resolved_reports = db.query(Report).filter_by(user_id=current_user.id, status='Resolved').count()
    
    flash_message = request.cookies.get("flash_message", "")
    return templates.TemplateResponse("profile.html", {
        "request": request,
        "current_user": current_user,
        "total_reports": total_reports,
        "pending_reports": pending_reports,
        "resolved_reports": resolved_reports,
        "flash_message": flash_message
    })

@app.post("/profile/update")
async def update_profile(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    full_name: str = Form(...),
    email: str = Form(...)
):
    existing = db.query(User).filter(User.email == email, User.id != current_user.id).first()
    if existing:
        response = RedirectResponse(url="/profile", status_code=302)
        response.set_cookie("flash_message", "danger:Email already registered by another user.", max_age=5)
        return response
    
    current_user.full_name = sanitize_input(full_name)
    current_user.email = sanitize_input(email)
    db.commit()
    
    response = RedirectResponse(url="/profile", status_code=302)
    response.set_cookie("flash_message", "success:Profile updated successfully!", max_age=5)
    return response

@app.get("/about", response_class=HTMLResponse)
async def about_page(
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    flash_message = request.cookies.get("flash_message", "")
    return templates.TemplateResponse("about.html", {
        "request": request,
        "current_user": current_user,
        "flash_message": flash_message
    })

@app.get("/help", response_class=HTMLResponse)
async def help_page(
    request: Request,
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    flash_message = request.cookies.get("flash_message", "")
    return templates.TemplateResponse("help.html", {
        "request": request,
        "current_user": current_user,
        "flash_message": flash_message
    })

@app.get("/admin/guide", response_class=HTMLResponse)
async def admin_guide(
    request: Request,
    current_user: User = Depends(get_current_admin)
):
    flash_message = request.cookies.get("flash_message", "")
    return templates.TemplateResponse("admin/guide.html", {
        "request": request,
        "current_user": current_user,
        "flash_message": flash_message
    })

@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc):
    import traceback
    print("=" * 80)
    print("UNHANDLED EXCEPTION:")
    print(f"Exception type: {type(exc).__name__}")
    print(f"Exception message: {str(exc)}")
    print("Traceback:")
    traceback.print_exc()
    print("=" * 80)
    
    current_user = None
    try:
        db = next(get_db())
        current_user = await get_current_user_optional(request, db)
    except:
        pass
    return templates.TemplateResponse("errors/500.html", {
        "request": request,
        "current_user": current_user
    }, status_code=500)

@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    current_user = None
    try:
        db = next(get_db())
        current_user = await get_current_user_optional(request, db)
    except:
        pass
    return templates.TemplateResponse("errors/404.html", {
        "request": request,
        "current_user": current_user
    }, status_code=404)

@app.exception_handler(500)
async def internal_error_handler(request: Request, exc):
    import traceback
    print("=" * 80)
    print("500 ERROR OCCURRED:")
    print(f"Exception type: {type(exc).__name__}")
    print(f"Exception message: {str(exc)}")
    print("Traceback:")
    traceback.print_exc()
    print("=" * 80)
    
    current_user = None
    try:
        db = next(get_db())
        current_user = await get_current_user_optional(request, db)
    except:
        pass
    return templates.TemplateResponse("errors/500.html", {
        "request": request,
        "current_user": current_user
    }, status_code=500)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=5000)
