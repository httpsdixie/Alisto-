from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from passlib.context import CryptContext
from itsdangerous import URLSafeTimedSerializer
import uuid

from database import Base

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    student_id = Column(String(20), unique=True, nullable=False)
    user_type = Column(String(20), default='Student')
    username = Column(String(80), unique=True, nullable=False)
    full_name = Column(String(120), nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(256), nullable=False)
    is_admin = Column(Boolean, default=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    reports = relationship('Report', backref='reporter', lazy='dynamic', foreign_keys='Report.user_id')
    feedbacks = relationship('Feedback', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        # Bcrypt has a 72-byte limit, truncate if necessary
        if isinstance(password, str):
            password = password.encode('utf-8')[:72].decode('utf-8', errors='ignore')
        self.password_hash = pwd_context.hash(password)
    
    def check_password(self, password):
        # Truncate password to match what was stored
        if isinstance(password, str):
            password = password.encode('utf-8')[:72].decode('utf-8', errors='ignore')
        return pwd_context.verify(password, self.password_hash)
    
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
        return email


class Report(Base):
    __tablename__ = 'reports'
    
    id = Column(Integer, primary_key=True)
    ticket_id = Column(String(50), unique=True, nullable=False)
    title = Column(String(200), nullable=False)
    location = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    category = Column(String(50), nullable=False)
    priority = Column(String(20), nullable=False, default='Medium')
    status = Column(String(20), nullable=False, default='Pending')
    photo_path = Column(String(500), nullable=True)
    proof_path = Column(String(500), nullable=True)
    admin_notes = Column(Text, nullable=True)
    
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    assigned_admin_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    
    status_history = relationship('StatusHistory', backref='report', lazy='dynamic', order_by='StatusHistory.created_at.desc()')
    feedback = relationship('Feedback', backref='report', uselist=False)
    assigned_admin = relationship('User', foreign_keys=[assigned_admin_id])
    
    def __init__(self, **kwargs):
        super(Report, self).__init__(**kwargs)
        if not self.ticket_id:
            self.ticket_id = self.generate_ticket_id()
    
    @staticmethod
    def generate_ticket_id():
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
        unique_part = uuid.uuid4().hex[:8].upper()
        return f"ALT-{timestamp}-{unique_part}"


class StatusHistory(Base):
    __tablename__ = 'status_history'
    
    id = Column(Integer, primary_key=True)
    report_id = Column(Integer, ForeignKey('reports.id'), nullable=False)
    old_status = Column(String(20), nullable=True)
    new_status = Column(String(20), nullable=False)
    notes = Column(Text, nullable=True)
    changed_by_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    changed_by = relationship('User')


class Feedback(Base):
    __tablename__ = 'feedbacks'
    
    id = Column(Integer, primary_key=True)
    report_id = Column(Integer, ForeignKey('reports.id'), nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    rating = Column(Integer, nullable=False)
    comments = Column(Text, nullable=True)
    resolution_confirmed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class Notification(Base):
    __tablename__ = 'notifications'
    
    id = Column(Integer, primary_key=True)
    type = Column(String(50), nullable=False)
    user_student_id = Column(String(20), nullable=False)
    user_name = Column(String(120), nullable=False)
    report_ticket_id = Column(String(50), nullable=True)
    report_title = Column(String(200), nullable=True)
    deletion_reason = Column(Text, nullable=True)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
