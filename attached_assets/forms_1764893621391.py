from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, TextAreaField, SelectField, BooleanField, IntegerField, HiddenField
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError, Optional, NumberRange
import re

def validate_password_strength(password):
    """Validate password meets security requirements"""
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

class LoginForm(FlaskForm):
    student_id = StringField('ID', validators=[DataRequired(), Length(min=5, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember me')

class RegistrationForm(FlaskForm):
    user_type = SelectField('I am a:', choices=[('Student', 'Student'), ('Faculty', 'Faculty')], validators=[DataRequired()])
    student_id = StringField('ID', validators=[DataRequired(), Length(min=3, max=20)])
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    full_name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=120)])
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=12)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    
    def validate_student_id(self, field):
        pattern = r'^\d{4}-\d{5}$'
        if not re.match(pattern, field.data):
            raise ValidationError('ID must be in format YYYY-NNNNN (e.g., 2024-12345)')
    
    def validate_username(self, field):
        from models import User
        existing_user = User.query.filter_by(username=field.data).first()
        if existing_user:
            raise ValidationError('Username already taken. Please choose a different username.')
    
    def validate_password(self, field):
        errors = validate_password_strength(field.data)
        if errors:
            raise ValidationError(f"Password must contain: {', '.join(errors)}")

class ReportForm(FlaskForm):
    title = StringField('Report Title', validators=[DataRequired(), Length(min=5, max=200)])
    location = StringField('Location', validators=[DataRequired(), Length(min=2, max=200)])
    description = TextAreaField('Description', validators=[DataRequired(), Length(min=10)])
    category = SelectField('Category', choices=[
        ('Infrastructure', 'Infrastructure'),
        ('Safety Hazard', 'Safety Hazard'),
        ('Electrical', 'Electrical'),
        ('Plumbing', 'Plumbing'),
        ('Sanitation', 'Sanitation'),
        ('Security', 'Security'),
        ('Other', 'Other')
    ], validators=[DataRequired()])
    priority = SelectField('Priority Level', choices=[
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High')
    ], validators=[DataRequired()])
    photo = FileField('Photo Evidence', validators=[
        FileAllowed(['jpg', 'jpeg', 'png', 'gif'], 'Only image files are allowed!')
    ])

class AdminReportUpdateForm(FlaskForm):
    status = SelectField('Status', choices=[
        ('Pending', 'Pending'),
        ('In Progress', 'In Progress'),
        ('Resolved', 'Resolved')
    ], validators=[DataRequired()])
    priority = SelectField('Priority Level', choices=[
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High')
    ], validators=[DataRequired()])
    admin_notes = TextAreaField('Admin Notes', validators=[Optional()])
    proof = FileField('Resolution Proof', validators=[
        FileAllowed(['jpg', 'jpeg', 'png', 'gif', 'pdf'], 'Only image and PDF files are allowed!')
    ])

class FeedbackForm(FlaskForm):
    rating = IntegerField('Rating', validators=[DataRequired(), NumberRange(min=1, max=5)])
    comments = TextAreaField('Comments', validators=[Optional(), Length(max=500)])
    resolution_confirmed = BooleanField('I confirm that this issue has been resolved', validators=[DataRequired()])

class TrackReportForm(FlaskForm):
    ticket_id = StringField('Ticket ID', validators=[DataRequired(), Length(min=5, max=30)])

class SearchForm(FlaskForm):
    keyword = StringField('Search', validators=[Optional()])
    category = SelectField('Category', choices=[
        ('', 'All Categories'),
        ('Infrastructure', 'Infrastructure'),
        ('Safety Hazard', 'Safety Hazard'),
        ('Electrical', 'Electrical'),
        ('Plumbing', 'Plumbing'),
        ('Sanitation', 'Sanitation'),
        ('Security', 'Security'),
        ('Other', 'Other')
    ], validators=[Optional()])
    priority = SelectField('Priority', choices=[
        ('', 'All Priorities'),
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High')
    ], validators=[Optional()])
    status = SelectField('Status', choices=[
        ('', 'All Statuses'),
        ('Pending', 'Pending'),
        ('In Progress', 'In Progress'),
        ('Resolved', 'Resolved')
    ], validators=[Optional()])
    sort_by = SelectField('Sort By', choices=[
        ('newest', 'Most Recent'),
        ('oldest', 'Oldest First'),
        ('priority_high', 'Priority (High to Low)'),
        ('priority_low', 'Priority (Low to High)')
    ], validators=[Optional()])


class ForgotPasswordForm(FlaskForm):
    email = StringField('Email Address', validators=[DataRequired(), Email()])


class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired(), Length(min=12)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    
    def validate_password(self, field):
        errors = validate_password_strength(field.data)
        if errors:
            raise ValidationError(f"Password must contain: {', '.join(errors)}")

class UpdateProfileForm(FlaskForm):
    full_name = StringField('Full Name', validators=[DataRequired(), Length(min=2, max=120)])
    email = StringField('Email Address', validators=[DataRequired(), Email()])
    
    def validate_email(self, field):
        from models import User
        user = User.query.filter_by(email=field.data).first()
        if user and user.id != __import__('flask_login').current_user.id:
            raise ValidationError('Email already registered.')

class DeleteAccountForm(FlaskForm):
    password = PasswordField('Confirm Password', validators=[DataRequired()])
    confirm_delete = BooleanField('I understand all my account data will be permanently deleted', validators=[DataRequired()])
