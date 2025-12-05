from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
import uuid

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.String(20), unique=True, nullable=False)
    user_type = db.Column(db.String(20), default='Student')  # Student or Faculty
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    reports = db.relationship('Report', backref='reporter', lazy='dynamic', foreign_keys='Report.user_id')
    feedbacks = db.relationship('Feedback', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_reset_token(self, secret_key):
        serializer = URLSafeTimedSerializer(secret_key)
        return serializer.dumps(self.email, salt='password-reset-salt')
    
    @staticmethod
    def verify_reset_token(token, secret_key, max_age=3600):
        serializer = URLSafeTimedSerializer(secret_key)
        try:
            email = serializer.loads(token, salt='password-reset-salt', max_age=max_age)
        except:
            return None
        return User.query.filter_by(email=email).first()
    
    def __repr__(self):
        return f'<User {self.username}>'


class Report(db.Model):
    __tablename__ = 'reports'
    
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.String(20), unique=True, nullable=False)
    title = db.Column(db.String(200), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=False)
    priority = db.Column(db.String(20), nullable=False, default='Medium')
    status = db.Column(db.String(20), nullable=False, default='Pending')
    photo_path = db.Column(db.String(500), nullable=True)
    proof_path = db.Column(db.String(500), nullable=True)
    admin_notes = db.Column(db.Text, nullable=True)
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    assigned_admin_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)
    
    status_history = db.relationship('StatusHistory', backref='report', lazy='dynamic', order_by='StatusHistory.created_at.desc()')
    feedback = db.relationship('Feedback', backref='report', uselist=False)
    assigned_admin = db.relationship('User', foreign_keys=[assigned_admin_id])
    
    def __init__(self, **kwargs):
        super(Report, self).__init__(**kwargs)
        if not self.ticket_id:
            self.ticket_id = self.generate_ticket_id()
    
    @staticmethod
    def generate_ticket_id():
        timestamp = datetime.utcnow().strftime('%Y%m%d')
        unique_part = uuid.uuid4().hex[:6].upper()
        return f"ALT-{timestamp}-{unique_part}"
    
    def __repr__(self):
        return f'<Report {self.ticket_id}>'


class StatusHistory(db.Model):
    __tablename__ = 'status_history'
    
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('reports.id'), nullable=False)
    old_status = db.Column(db.String(20), nullable=True)
    new_status = db.Column(db.String(20), nullable=False)
    notes = db.Column(db.Text, nullable=True)
    changed_by_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    changed_by = db.relationship('User')
    
    def __repr__(self):
        return f'<StatusHistory {self.report_id}: {self.old_status} -> {self.new_status}>'


class Feedback(db.Model):
    __tablename__ = 'feedbacks'
    
    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey('reports.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comments = db.Column(db.Text, nullable=True)
    resolution_confirmed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Feedback Report:{self.report_id} Rating:{self.report_id}>'


class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)  # 'report_deleted', 'password_reset'
    user_student_id = db.Column(db.String(20), nullable=False)
    user_name = db.Column(db.String(120), nullable=False)
    report_ticket_id = db.Column(db.String(20), nullable=True)  # NULL for non-report notifications
    report_title = db.Column(db.String(200), nullable=True)
    deletion_reason = db.Column(db.Text, nullable=True)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Notification {self.type} {self.report_ticket_id}>'
