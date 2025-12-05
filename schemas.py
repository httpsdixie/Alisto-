from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional, List
from datetime import datetime
import re

def validate_password_strength(password: str) -> List[str]:
    errors = []
    if len(password) < 12:
        errors.append("at least 12 characters")
    if not re.search(r'[A-Z]', password):
        errors.append("one uppercase letter (A-Z)")
    if not re.search(r'[a-z]', password):
        errors.append("one lowercase letter (a-z)")
    if not re.search(r'[0-9]', password):
        errors.append("one number (0-9)")
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?]', password):
        errors.append("one special character (!@#$%^&*)")
    return errors

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    user_id: Optional[int] = None

class LoginRequest(BaseModel):
    student_id: str
    password: str
    remember_me: bool = False

class RegistrationRequest(BaseModel):
    user_type: str
    student_id: str
    username: str
    full_name: str
    email: EmailStr
    password: str
    confirm_password: str
    
    @field_validator('student_id')
    @classmethod
    def validate_student_id(cls, v):
        pattern = r'^\d{4}-\d{5}$'
        if not re.match(pattern, v):
            raise ValueError('ID must be in format YYYY-NNNNN (e.g., 2024-12345)')
        return v
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        errors = validate_password_strength(v)
        if errors:
            raise ValueError(f"Password must contain: {', '.join(errors)}")
        return v
    
    @field_validator('confirm_password')
    @classmethod
    def passwords_match(cls, v, info):
        if 'password' in info.data and v != info.data['password']:
            raise ValueError('Passwords must match')
        return v

class UserResponse(BaseModel):
    id: int
    student_id: str
    user_type: str
    username: str
    full_name: str
    email: str
    is_admin: bool
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    password: str
    confirm_password: str
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        errors = validate_password_strength(v)
        if errors:
            raise ValueError(f"Password must contain: {', '.join(errors)}")
        return v
    
    @field_validator('confirm_password')
    @classmethod
    def passwords_match(cls, v, info):
        if 'password' in info.data and v != info.data['password']:
            raise ValueError('Passwords must match')
        return v

class ReportCreate(BaseModel):
    title: str
    location: str
    description: str
    category: str
    priority: str = 'Medium'

class ReportUpdate(BaseModel):
    status: str
    priority: str
    admin_notes: Optional[str] = None

class ReportResponse(BaseModel):
    id: int
    ticket_id: str
    title: str
    location: str
    description: str
    category: str
    priority: str
    status: str
    photo_path: Optional[str] = None
    proof_path: Optional[str] = None
    admin_notes: Optional[str] = None
    user_id: int
    assigned_admin_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    
    class Config:
        from_attributes = True

class FeedbackCreate(BaseModel):
    rating: int
    comments: Optional[str] = None
    resolution_confirmed: bool = True
    
    @field_validator('rating')
    @classmethod
    def validate_rating(cls, v):
        if v < 1 or v > 5:
            raise ValueError('Rating must be between 1 and 5')
        return v

class FeedbackResponse(BaseModel):
    id: int
    report_id: int
    user_id: int
    rating: int
    comments: Optional[str] = None
    resolution_confirmed: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

class StatusHistoryResponse(BaseModel):
    id: int
    report_id: int
    old_status: Optional[str] = None
    new_status: str
    notes: Optional[str] = None
    changed_by_id: int
    created_at: datetime
    
    class Config:
        from_attributes = True

class NotificationResponse(BaseModel):
    id: int
    type: str
    user_student_id: str
    user_name: str
    report_ticket_id: Optional[str] = None
    report_title: Optional[str] = None
    deletion_reason: Optional[str] = None
    is_read: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

class UpdateProfileRequest(BaseModel):
    full_name: str
    email: EmailStr

class DeleteAccountRequest(BaseModel):
    password: str
    confirm_delete: bool

class TrackReportRequest(BaseModel):
    ticket_id: str

class HomeStats(BaseModel):
    total: int
    pending: int
    in_progress: int
    resolved: int
    rating: float
    stars: str
    recently_resolved: List[dict]
    category_updates: List[dict]
    priority_data: List[dict]

class ReportStats(BaseModel):
    by_category: dict
    by_priority: dict
    by_status: dict
