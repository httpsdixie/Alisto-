import os
import uuid
from datetime import datetime, timedelta
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename
from PIL import Image
from functools import wraps
import html
import re

from config import Config
from models import db, User, Report, StatusHistory, Feedback, Notification
from forms import (LoginForm, RegistrationForm, ReportForm, AdminReportUpdateForm, 
                   FeedbackForm, TrackReportForm, SearchForm, ForgotPasswordForm, ResetPasswordForm)
from email_service import init_resend, send_report_confirmation, send_status_update, send_feedback_request, send_password_reset

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
csrf = CSRFProtect(app)
init_resend(app)

# Security headers for all responses
@app.after_request
def set_security_headers(response):
    """Add security headers to prevent common attacks"""
    response.headers['X-Content-Type-Options'] = 'nosniff'  # Prevent MIME sniffing
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'  # Prevent clickjacking
    response.headers['X-XSS-Protection'] = '1; mode=block'  # Enable XSS filter
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'  # HSTS
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net bootstrap.min.css; img-src 'self' data:; font-src 'self' cdn.jsdelivr.net"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

def sanitize_input(text):
    """Sanitize user input to prevent injection attacks"""
    if not text:
        return text
    # Remove potentially harmful characters but allow normal text
    text = html.escape(text)
    # Remove null bytes
    text = text.replace('\x00', '')
    return text.strip()

def sanitize_filename(filename):
    """Sanitize filenames to prevent directory traversal"""
    filename = secure_filename(filename)
    # Remove any remaining potentially dangerous characters
    filename = re.sub(r'[^\w\s.-]', '', filename)
    return filename[:255]  # Limit filename length

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Login attempt tracking for rate limiting
login_attempts = {}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def get_notifications():
    """Get all notifications for use in templates"""
    if current_user.is_authenticated and current_user.is_admin:
        return Notification.query.order_by(Notification.created_at.desc()).limit(20).all()
    return []

def get_unread_notifications_count():
    """Get count of unread notifications"""
    if current_user.is_authenticated and current_user.is_admin:
        return Notification.query.filter_by(is_read=False).count()
    return 0

@app.context_processor
def inject_notifications():
    """Make notification functions available in all templates"""
    return {
        'get_notifications': get_notifications,
        'get_unread_notifications_count': get_unread_notifications_count
    }

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def save_photo(file):
    try:
        if file and allowed_file(file.filename):
            filename = sanitize_filename(file.filename)
            unique_filename = f"{uuid.uuid4().hex}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            
            # Verify file size before processing (5MB max)
            file.seek(0, 2)  # Seek to end
            file_size = file.tell()
            file.seek(0)  # Reset to start
            if file_size > 5 * 1024 * 1024:  # 5MB
                return None
            
            img = Image.open(file)
            img.thumbnail((1200, 1200))
            img.save(filepath, quality=85, optimize=True)
            
            return unique_filename
    except Exception as e:
        print(f"Error saving photo: {str(e)}")
        return None
    return None

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/notifications/mark-read', methods=['POST'])
@login_required
@admin_required
@csrf.exempt
def mark_notifications_read():
    """Mark all notifications as read"""
    try:
        Notification.query.filter_by(is_read=False).update({'is_read': True})
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        print(f"Error marking notifications as read: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to update notifications'}), 500

with app.app_context():
    db.create_all()

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.svg', mimetype='image/svg+xml')

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/api/home-stats')
def get_home_stats():
    """Get statistics for the home page"""
    try:
        total_reports = Report.query.count()
        pending = Report.query.filter_by(status='Pending').count()
        in_progress = Report.query.filter_by(status='In Progress').count()
        resolved = Report.query.filter_by(status='Resolved').count()
        
        # Get recently resolved reports
        recently_resolved = Report.query.filter_by(status='Resolved').order_by(
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
        
        # Get last update for each category
        categories = ['Infrastructure', 'Electrical', 'Plumbing', 'Sanitation', 'Safety Hazard', 'Security', 'Other']
        category_updates = []
        for category in categories:
            latest = Report.query.filter_by(category=category).order_by(Report.updated_at.desc()).first()
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
        
        # Get reports by priority
        priorities = ['High', 'Medium', 'Low']
        priority_data = []
        for priority in priorities:
            count = Report.query.filter_by(priority=priority).count()
            priority_data.append({
                'priority': priority,
                'count': count
            })
        
        # Calculate average rating from feedbacks
        avg_rating_result = db.session.query(db.func.avg(Feedback.rating)).filter(Feedback.rating > 0).first()
        avg_rating = float(avg_rating_result[0]) if avg_rating_result and avg_rating_result[0] else 0.0
        avg_rating = round(avg_rating, 1) if avg_rating > 0 else 4.8
        
        # Generate star display (filled and empty stars)
        rounded_stars = round(avg_rating)
        filled_stars = min(5, max(0, rounded_stars))
        empty_stars = 5 - filled_stars
        star_display = ('★' * filled_stars) + ('☆' * empty_stars)
        
        return jsonify({
            'total': total_reports,
            'pending': pending,
            'in_progress': in_progress,
            'resolved': resolved,
            'rating': avg_rating,
            'stars': star_display,
            'recently_resolved': resolved_data,
            'category_updates': category_updates,
            'priority_data': priority_data
        })
    except Exception as e:
        print(f"Error getting home stats: {str(e)}")
        return jsonify({
            'total': 0, 'pending': 0, 'in_progress': 0, 'resolved': 0,
            'recently_resolved': [],
            'category_updates': [],
            'priority_data': []
        }), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    # Rate limiting check
    client_ip = request.remote_addr
    now = datetime.utcnow()
    
    if client_ip in login_attempts:
        attempts, last_attempt = login_attempts[client_ip]
        if attempts >= 5 and (now - last_attempt).seconds < 900:  # 5 attempts in 15 minutes
            flash('Too many failed login attempts. Please try again in 15 minutes.', 'danger')
            return render_template('auth/login.html', form=LoginForm())
        elif (now - last_attempt).seconds > 900:
            login_attempts[client_ip] = (0, now)
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(student_id=form.student_id.data).first()
        if user and user.check_password(form.password.data):
            # Reset login attempts on successful login
            if client_ip in login_attempts:
                del login_attempts[client_ip]
            
            if not user.is_active:
                flash('Your account has been deactivated. Please contact admin.', 'danger')
                return render_template('auth/login.html', form=form)
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            flash(f'Welcome back, {user.full_name}!', 'success')
            return redirect(next_page if next_page else url_for('dashboard'))
        
        # Track failed login attempts
        if client_ip in login_attempts:
            attempts, _ = login_attempts[client_ip]
            login_attempts[client_ip] = (attempts + 1, now)
        else:
            login_attempts[client_ip] = (1, now)
        
        flash('Invalid ID or password.', 'danger')
    return render_template('auth/login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        # Sanitize user inputs
        student_id = sanitize_input(form.student_id.data)
        email = sanitize_input(form.email.data)
        username = sanitize_input(form.username.data)
        full_name = sanitize_input(form.full_name.data)
        if User.query.filter_by(student_id=form.student_id.data).first():
            flash('ID already registered.', 'danger')
            return render_template('auth/register.html', form=form)
        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered.', 'danger')
            return render_template('auth/register.html', form=form)
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already taken.', 'danger')
            return render_template('auth/register.html', form=form)
        
        is_admin = form.student_id.data in app.config['ADMIN_STUDENT_IDS']
        
        user = User(
            student_id=form.student_id.data,
            user_type=form.user_type.data,
            username=form.username.data,
            full_name=form.full_name.data,
            email=form.email.data,
            is_admin=is_admin
        )
        user.set_password(form.password.data)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('auth/register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.generate_reset_token(app.config['SECRET_KEY'])
            reset_url = url_for('reset_password', token=token, _external=True)
            send_password_reset(user, reset_url)
        flash('If an account with that email exists, a password reset link has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('auth/forgot_password.html', form=form)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    user = User.verify_reset_token(token, app.config['SECRET_KEY'])
    if not user:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('auth/reset_password.html', form=form, token=token)


@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.created_at.desc()).limit(5).all()
    
    pending_count = Report.query.filter_by(user_id=current_user.id, status='Pending').count()
    in_progress_count = Report.query.filter_by(user_id=current_user.id, status='In Progress').count()
    resolved_count = Report.query.filter_by(user_id=current_user.id, status='Resolved').count()
    
    return render_template('dashboard/user_dashboard.html', 
                         reports=reports,
                         pending_count=pending_count,
                         in_progress_count=in_progress_count,
                         resolved_count=resolved_count)

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    from datetime import timedelta
    
    # Delete notifications older than 7 days
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    Notification.query.filter(Notification.created_at < seven_days_ago).delete()
    
    # Also limit to 20 notifications total
    notification_count = Notification.query.count()
    if notification_count > 20:
        oldest = Notification.query.order_by(Notification.created_at.asc()).first()
        if oldest:
            db.session.delete(oldest)
    db.session.commit()
    
    reports = Report.query.order_by(Report.updated_at.desc()).limit(10).all()
    notifications = Notification.query.order_by(Notification.created_at.desc()).all()
    
    pending_count = Report.query.filter_by(status='Pending').count()
    in_progress_count = Report.query.filter_by(status='In Progress').count()
    resolved_count = Report.query.filter_by(status='Resolved').count()
    total_users = User.query.count()
    
    # Satisfaction statistics
    total_feedbacks = Feedback.query.count()
    avg_rating = 0
    satisfaction_percentage = 0
    if total_feedbacks > 0:
        avg_rating = db.session.query(db.func.avg(Feedback.rating)).scalar() or 0
        avg_rating = round(float(avg_rating), 2)
        satisfaction_percentage = round((avg_rating / 5.0) * 100, 1)
    
    return render_template('dashboard/admin_dashboard.html',
                         reports=reports,
                         notifications=notifications,
                         pending_count=pending_count,
                         in_progress_count=in_progress_count,
                         resolved_count=resolved_count,
                         total_users=total_users,
                         total_feedbacks=total_feedbacks,
                         avg_rating=avg_rating,
                         satisfaction_percentage=satisfaction_percentage)

@app.route('/report/new', methods=['GET', 'POST'])
@login_required
def new_report():
    form = ReportForm()
    if form.validate_on_submit():
        from datetime import timedelta
        last_24_hours = datetime.utcnow() - timedelta(hours=24)
        
        # Check daily limit (5 reports per user per day)
        reports_today = Report.query.filter_by(user_id=current_user.id).filter(
            Report.created_at >= last_24_hours
        ).count()
        
        if reports_today >= 5:
            flash('You have reached the daily limit of 5 reports. Please try again tomorrow.', 'warning')
            return redirect(url_for('new_report'))
        
        # Check for duplicate report (same title and location within last 24 hours)
        duplicate = Report.query.filter_by(
            user_id=current_user.id,
            title=form.title.data,
            location=form.location.data
        ).filter(Report.created_at >= last_24_hours).first()
        
        if duplicate:
            flash('You already submitted a similar report recently. Please check your existing reports or wait before resubmitting.', 'warning')
            return redirect(url_for('new_report'))
        
        photo_filename = None
        if form.photo.data:
            photo_filename = save_photo(form.photo.data)
        
        report = Report(
            title=form.title.data,
            location=form.location.data,
            description=form.description.data,
            category=form.category.data,
            priority=form.priority.data,
            photo_path=photo_filename,
            user_id=current_user.id
        )
        
        db.session.add(report)
        db.session.commit()
        
        status_history = StatusHistory(
            report_id=report.id,
            old_status=None,
            new_status='Pending',
            notes='Report submitted',
            changed_by_id=current_user.id
        )
        db.session.add(status_history)
        db.session.commit()
        
        # Create admin notification about new report submission
        notification = Notification(
            type='report_submitted',
            user_student_id=current_user.student_id,
            user_name=current_user.full_name,
            report_ticket_id=report.ticket_id,
            report_title=report.title,
            deletion_reason=None,
            is_read=False
        )
        db.session.add(notification)
        db.session.commit()
        
        # Limit notifications to 20 - delete oldest if exceeded
        notification_count = Notification.query.count()
        if notification_count > 20:
            oldest = Notification.query.order_by(Notification.created_at.asc()).first()
            if oldest:
                db.session.delete(oldest)
                db.session.commit()
        
        send_report_confirmation(current_user, report)
        flash(f'Report submitted successfully! Your Ticket ID: {report.ticket_id}', 'success')
        return redirect(url_for('my_reports'))
    
    return render_template('reports/new_report.html', form=form)

@app.route('/my-reports')
@login_required
def my_reports():
    form = SearchForm()
    page = request.args.get('page', 1, type=int)
    
    query = Report.query.filter_by(user_id=current_user.id)
    
    keyword = request.args.get('keyword', '')
    category = request.args.get('category', '')
    priority = request.args.get('priority', '')
    status = request.args.get('status', '')
    sort_by = request.args.get('sort_by', 'newest')
    
    if keyword:
        query = query.filter(
            (Report.title.ilike(f'%{keyword}%')) | 
            (Report.description.ilike(f'%{keyword}%')) |
            (Report.location.ilike(f'%{keyword}%'))
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
        query = query.order_by(db.case(
            (Report.priority == 'High', 1),
            (Report.priority == 'Medium', 2),
            (Report.priority == 'Low', 3)
        ))
    elif sort_by == 'priority_low':
        query = query.order_by(db.case(
            (Report.priority == 'Low', 1),
            (Report.priority == 'Medium', 2),
            (Report.priority == 'High', 3)
        ))
    else:
        query = query.order_by(Report.created_at.desc())
    
    reports = query.paginate(page=page, per_page=10)
    
    return render_template('reports/my_reports.html', reports=reports, form=form)

@app.route('/report/<int:report_id>')
@login_required
def view_report(report_id):
    report = Report.query.filter_by(id=report_id).first()
    
    if not report:
        flash('This report has been deleted and cannot be retrieved.', 'warning')
        return redirect(url_for('my_reports'))
    
    if not current_user.is_admin and report.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    feedback_form = FeedbackForm()
    status_history = StatusHistory.query.filter_by(report_id=report_id).order_by(StatusHistory.created_at.desc()).all()
    
    return render_template('reports/view_report.html', 
                         report=report, 
                         feedback_form=feedback_form,
                         status_history=status_history)

@app.route('/report/<int:report_id>/feedback', methods=['POST'])
@login_required
def submit_feedback(report_id):
    report = Report.query.get_or_404(report_id)
    
    if report.user_id != current_user.id:
        flash('Access denied.', 'danger')
        return redirect(url_for('dashboard'))
    
    if report.status != 'Resolved':
        flash('Feedback can only be submitted for resolved reports.', 'warning')
        return redirect(url_for('view_report', report_id=report_id))
    
    if report.feedback:
        flash('Feedback already submitted for this report.', 'info')
        return redirect(url_for('view_report', report_id=report_id))
    
    form = FeedbackForm()
    if form.validate_on_submit():
        feedback = Feedback(
            report_id=report_id,
            user_id=current_user.id,
            rating=form.rating.data,
            comments=form.comments.data,
            resolution_confirmed=form.resolution_confirmed.data
        )
        db.session.add(feedback)
        db.session.commit()
        
        flash('Thank you for your feedback!', 'success')
    
    return redirect(url_for('view_report', report_id=report_id))

@app.route('/report/<int:report_id>/delete', methods=['POST'])
@login_required
def delete_report(report_id):
    report = Report.query.get_or_404(report_id)
    
    if report.user_id != current_user.id:
        flash('You can only delete your own reports.', 'danger')
        return redirect(url_for('my_reports'))
    
    if report.status == 'Resolved':
        flash('Cannot delete resolved reports.', 'danger')
        return redirect(url_for('view_report', report_id=report_id))
    
    deletion_reason = request.form.get('deletion_reason', '').strip()
    
    if not deletion_reason or len(deletion_reason) < 5:
        flash('Please provide a reason for deletion (at least 5 characters).', 'danger')
        return redirect(url_for('view_report', report_id=report_id))
    
    ticket_id = report.ticket_id
    user = current_user
    
    # Delete related status history
    StatusHistory.query.filter_by(report_id=report_id).delete()
    
    # Delete related feedback
    Feedback.query.filter_by(report_id=report_id).delete()
    
    # Delete the report itself
    db.session.delete(report)
    db.session.commit()
    
    # Check if notification for this report already exists - no duplicates
    existing_notif = Notification.query.filter_by(
        type='report_deleted',
        report_ticket_id=ticket_id
    ).first()
    
    if not existing_notif:
        # Create admin notification about the deletion
        notification = Notification(
            type='report_deleted',
            user_student_id=user.student_id,
            user_name=user.full_name,
            report_ticket_id=ticket_id,
            report_title=report.title,
            deletion_reason=deletion_reason,
            is_read=False
        )
        db.session.add(notification)
        db.session.commit()
        
        # Limit notifications to 20 - delete oldest if exceeded
        notification_count = Notification.query.count()
        if notification_count > 20:
            oldest = Notification.query.order_by(Notification.created_at.asc()).first()
            if oldest:
                db.session.delete(oldest)
                db.session.commit()
    
    flash(f'Report {ticket_id} has been permanently deleted.', 'success')
    return redirect(url_for('my_reports'))

@app.route('/track', methods=['GET', 'POST'])
@login_required
def track_report():
    form = TrackReportForm()
    report = None
    
    if form.validate_on_submit():
        report = Report.query.filter_by(ticket_id=form.ticket_id.data).first()
        if not report:
            flash('Report not found. Please check your Ticket ID.', 'danger')
    
    return render_template('reports/track_report.html', form=form, report=report)

@app.route('/admin/reports')
@login_required
@admin_required
def admin_reports():
    form = SearchForm()
    page = request.args.get('page', 1, type=int)
    
    query = Report.query
    
    keyword = request.args.get('keyword', '')
    category = request.args.get('category', '')
    priority = request.args.get('priority', '')
    status = request.args.get('status', '')
    user_type = request.args.get('user_type', '')
    sort_by = request.args.get('sort_by', 'newest')
    
    if keyword:
        query = query.filter(
            (Report.title.contains(keyword)) | 
            (Report.description.contains(keyword)) |
            (Report.location.contains(keyword)) |
            (Report.ticket_id.contains(keyword))
        )
    if category:
        query = query.filter_by(category=category)
    if priority:
        query = query.filter_by(priority=priority)
    if status:
        query = query.filter_by(status=status)
    if user_type:
        query = query.join(User, Report.user_id == User.id).filter(User.user_type == user_type)
    
    if sort_by == 'oldest':
        query = query.order_by(Report.created_at.asc())
    elif sort_by == 'priority_high':
        query = query.order_by(db.case(
            (Report.priority == 'High', 1),
            (Report.priority == 'Medium', 2),
            (Report.priority == 'Low', 3)
        ))
    elif sort_by == 'priority_low':
        query = query.order_by(db.case(
            (Report.priority == 'Low', 1),
            (Report.priority == 'Medium', 2),
            (Report.priority == 'High', 3)
        ))
    else:
        query = query.order_by(Report.created_at.desc())
    
    reports = query.paginate(page=page, per_page=20)
    
    return render_template('admin/reports.html', reports=reports, form=form)

@app.route('/admin/report/<int:report_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_view_report(report_id):
    report = Report.query.get_or_404(report_id)
    form = AdminReportUpdateForm(obj=report)
    
    if form.validate_on_submit():
        old_status = report.status
        new_status = form.status.data
        
        # Prevent editing if report is already resolved
        if report.status == 'Resolved':
            flash('Cannot edit a resolved report.', 'danger')
            return render_template('admin/view_report.html', report=report, form=form)
        
        # Prevent status downgrade (can't go backwards)
        status_order = {'Pending': 1, 'In Progress': 2, 'Resolved': 3}
        if status_order.get(new_status, 0) < status_order.get(old_status, 0):
            flash('Cannot move report backwards. Status can only move forward: Pending → In Progress → Resolved', 'danger')
            return render_template('admin/view_report.html', report=report, form=form)
        
        # Require proof when resolving
        if new_status == 'Resolved' and old_status != 'Resolved' and not form.proof.data:
            flash('Proof/Evidence is required when marking a report as Resolved.', 'danger')
            return render_template('admin/view_report.html', report=report, form=form)
        
        report.status = new_status
        report.priority = form.priority.data
        report.admin_notes = form.admin_notes.data
        report.assigned_admin_id = current_user.id
        
        # Handle proof upload
        if form.proof.data:
            from werkzeug.utils import secure_filename
            import os
            file = form.proof.data
            filename = secure_filename(file.filename)
            timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
            filename = f"proof_{timestamp}_{filename}"
            upload_path = os.path.join('static/uploads', filename)
            file.save(upload_path)
            report.proof_path = filename
        
        if new_status == 'Resolved' and old_status != 'Resolved':
            report.resolved_at = datetime.utcnow()
        
        if old_status != new_status:
            status_history = StatusHistory(
                report_id=report.id,
                old_status=old_status,
                new_status=new_status,
                notes=form.admin_notes.data,
                changed_by_id=current_user.id
            )
            db.session.add(status_history)
            
            reporter = User.query.get(report.user_id)
            send_status_update(reporter, report, old_status, new_status)
            
            if new_status == 'Resolved':
                send_feedback_request(reporter, report)
        
        db.session.commit()
        flash('Report updated successfully!', 'success')
        return redirect(url_for('admin_view_report', report_id=report.id))
    
    status_history = StatusHistory.query.filter_by(report_id=report_id).order_by(StatusHistory.created_at.desc()).all()
    
    return render_template('admin/view_report.html', report=report, form=form, status_history=status_history)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    page = request.args.get('page', 1, type=int)
    category = request.args.get('category', 'all')
    
    query = User.query
    
    if category == 'students':
        query = query.filter_by(user_type='Student', is_admin=False)
    elif category == 'faculty':
        query = query.filter_by(user_type='Faculty', is_admin=False)
    elif category == 'admin':
        query = query.filter_by(is_admin=True)
    
    users = query.order_by(User.created_at.desc()).paginate(page=page, per_page=20)
    
    # Get notification counts for each user
    user_notifications = {}
    for user in users.items:
        notif_count = Notification.query.filter_by(user_student_id=user.student_id, is_read=False).count()
        user_notifications[user.id] = notif_count
    
    return render_template('admin/users.html', users=users, category=category, user_notifications=user_notifications)

@app.route('/admin/user/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@admin_required
def toggle_user_status(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot deactivate your own account.', 'danger')
        return redirect(url_for('admin_users'))
    
    user.is_active = not user.is_active
    db.session.commit()
    
    status = 'activated' if user.is_active else 'deactivated'
    flash(f'User {user.full_name} has been {status}.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/user/<int:user_id>/toggle-admin', methods=['POST'])
@login_required
@admin_required
def toggle_admin_status(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash('You cannot change your own admin status.', 'danger')
        return redirect(url_for('admin_users'))
    
    user.is_admin = not user.is_admin
    db.session.commit()
    
    status = 'granted admin privileges' if user.is_admin else 'removed from admin'
    flash(f'User {user.full_name} has been {status}.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/api/reports/stats')
@login_required
def api_report_stats():
    try:
        if current_user.is_admin:
            pending = Report.query.filter_by(status='Pending').count()
            in_progress = Report.query.filter_by(status='In Progress').count()
            resolved = Report.query.filter_by(status='Resolved').count()
            
            categories = db.session.query(
                Report.category, db.func.count(Report.id), db.func.max(Report.updated_at)
            ).group_by(Report.category).all()
            
            priorities = db.session.query(
                Report.priority, db.func.count(Report.id), db.func.max(Report.updated_at)
            ).group_by(Report.priority).all()
            
            total_feedbacks = Feedback.query.count()
            avg_rating = 0
            satisfaction_percentage = 0
            if total_feedbacks > 0:
                avg_rating = db.session.query(db.func.avg(Feedback.rating)).scalar() or 0
                avg_rating = round(float(avg_rating), 2)
                satisfaction_percentage = round((avg_rating / 5.0) * 100, 1)
            
            # Format categories with last update
            categories_data = {}
            categories_last_update = {}
            for cat, count, last_update in categories:
                categories_data[cat] = count
                categories_last_update[cat] = last_update.strftime('%b %d, %Y %I:%M %p') if last_update else 'N/A'
            
            # Format priorities with last update
            priorities_data = {}
            priorities_last_update = {}
            for priority, count, last_update in priorities:
                priorities_data[priority] = count
                priorities_last_update[priority] = last_update.strftime('%b %d, %Y %I:%M %p') if last_update else 'N/A'
            
            priorities = priorities_data
        else:
            pending = Report.query.filter_by(user_id=current_user.id, status='Pending').count()
            in_progress = Report.query.filter_by(user_id=current_user.id, status='In Progress').count()
            resolved = Report.query.filter_by(user_id=current_user.id, status='Resolved').count()
            categories_data = []
            categories_last_update = {}
            priorities = []
            priorities_last_update = {}
            total_feedbacks = 0
            avg_rating = 0
            satisfaction_percentage = 0
        
        return jsonify({
            'status': {
                'pending': pending,
                'in_progress': in_progress,
                'resolved': resolved
            },
            'categories': categories_data,
            'categories_last_update': categories_last_update,
            'priorities': priorities if current_user.is_admin else {},
            'priorities_last_update': priorities_last_update if current_user.is_admin else {},
            'satisfaction': {
                'total_feedbacks': total_feedbacks,
                'avg_rating': avg_rating,
                'percentage': satisfaction_percentage
            }
        })
    except Exception as e:
        print(f"Error getting report stats: {str(e)}")
        return jsonify({
            'status': {'pending': 0, 'in_progress': 0, 'resolved': 0},
            'categories': {}, 'categories_last_update': {}, 'priorities': {},
            'satisfaction': {'total_feedbacks': 0, 'avg_rating': 0, 'percentage': 0}
        }), 500

@app.route('/api/reports/recent')
@login_required
def api_recent_reports():
    try:
        if current_user.is_admin:
            reports = Report.query.order_by(Report.created_at.desc()).limit(10).all()
        else:
            reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.created_at.desc()).limit(5).all()
        
        return jsonify([{
            'id': r.id,
            'ticket_id': r.ticket_id,
            'title': r.title,
            'location': r.location,
            'category': r.category,
            'priority': r.priority,
            'status': r.status,
            'created_at': r.created_at.strftime('%Y-%m-%d %H:%M')
        } for r in reports])
    except Exception as e:
        print(f"Error getting recent reports: {str(e)}")
        return jsonify([]), 500

@app.route('/profile')
@login_required
def profile():
    try:
        report_count = Report.query.filter_by(user_id=current_user.id).count()
        resolved_count = Report.query.filter_by(user_id=current_user.id, status='Resolved').count()
        return render_template('profile.html', report_count=report_count, resolved_count=resolved_count)
    except Exception as e:
        print(f"Error loading profile: {str(e)}")
        flash('Error loading profile. Please try again.', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/help')
@login_required
def help():
    return render_template('help.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.errorhandler(404)
def not_found_error(error):
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('errors/500.html'), 500

@app.context_processor
def utility_processor():
    return {
        'now': datetime.utcnow()
    }

@app.route('/api/user/report-updates')
@login_required
def get_user_report_updates():
    try:
        if current_user.is_admin:
            return jsonify({'updates': []})
        
        reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.updated_at.desc()).limit(10).all()
        
        updates = []
        for report in reports:
            updates.append({
                'ticket_id': report.ticket_id,
                'title': report.title[:50],
                'status': report.status,
                'updated': report.updated_at.isoformat()
            })
        
        return jsonify({'updates': updates})
    except Exception as e:
        print(f"Error getting user report updates: {str(e)}")
        return jsonify({'updates': []}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
