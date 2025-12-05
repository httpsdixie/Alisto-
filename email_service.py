import smtplib
import os
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import settings

logger = logging.getLogger(__name__)

def init_resend():
    """Kept for compatibility - not needed for Gmail SMTP"""
    pass

def send_email(to_email: str, subject: str, html_content: str) -> bool:
    """Send email using Gmail SMTP"""
    try:
        gmail_user = os.environ.get('GMAIL_USER')
        gmail_app_password = os.environ.get('GMAIL_APP_PASSWORD')
        
        if not gmail_user or not gmail_app_password:
            logger.warning(f"Email skipped: Gmail credentials not configured")
            logger.warning(f"Please set GMAIL_USER and GMAIL_APP_PASSWORD in .env file")
            return False
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"Alisto! Campus Safety <{gmail_user}>"
        msg['To'] = to_email
        
        # Attach HTML content
        html_part = MIMEText(html_content, 'html')
        msg.attach(html_part)
        
        # Send via Gmail SMTP
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(gmail_user, gmail_app_password)
            server.send_message(msg)
        
        logger.info(f"Email sent to {to_email} - {subject}")
        return True
        
    except Exception as e:
        logger.error(f"Email failed to {to_email}: {str(e)}")
        return False

def send_report_confirmation(user, report) -> bool:
    subject = f"Report Submitted - {report.ticket_id}"
    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #8B0000, #FFD700); padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">Alisto!</h1>
            <p style="color: white; margin: 5px 0;">EVSU-OC Campus Safety Reporting System</p>
        </div>
        <div style="padding: 20px; background: #f9f9f9;">
            <h2 style="color: #8B0000;">Report Submitted Successfully</h2>
            <p>Dear {user.full_name},</p>
            <p>Your safety report has been submitted successfully.</p>
            <div style="background: white; padding: 15px; border-radius: 5px; margin: 15px 0; border-left: 4px solid #8B0000;">
                <p><strong>Ticket ID:</strong> {report.ticket_id}</p>
                <p><strong>Title:</strong> {report.title}</p>
                <p><strong>Location:</strong> {report.location}</p>
                <p><strong>Category:</strong> {report.category}</p>
                <p><strong>Priority:</strong> {report.priority}</p>
                <p><strong>Status:</strong> {report.status}</p>
            </div>
            <p>Track your report using Ticket ID: <strong>{report.ticket_id}</strong></p>
            <p>Thank you for helping make our campus safer!</p>
        </div>
        <div style="background: #8B0000; padding: 10px; text-align: center;">
            <p style="color: white; margin: 0; font-size: 12px;">EVSU-OC Campus Safety Team</p>
        </div>
    </div>
    """
    return send_email(user.email, subject, html_content)

def send_status_update(user, report, old_status: str, new_status: str) -> bool:
    subject = f"Report Status Update - {report.ticket_id}"
    status_color = 'green' if new_status == 'Resolved' else '#FFD700' if new_status == 'In Progress' else '#8B0000'
    message = ''
    if new_status == 'Resolved':
        message = '<p>Your issue has been resolved! Please log in to confirm and provide feedback.</p>'
    elif new_status == 'In Progress':
        message = '<p>Our maintenance team is now working on your reported issue.</p>'
    
    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #8B0000, #FFD700); padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">Alisto!</h1>
            <p style="color: white; margin: 5px 0;">EVSU-OC Campus Safety Reporting System</p>
        </div>
        <div style="padding: 20px; background: #f9f9f9;">
            <h2 style="color: #8B0000;">Report Status Updated</h2>
            <p>Dear {user.full_name},</p>
            <p>Your report status has been updated.</p>
            <div style="background: white; padding: 15px; border-radius: 5px; margin: 15px 0; border-left: 4px solid #8B0000;">
                <p><strong>Ticket ID:</strong> {report.ticket_id}</p>
                <p><strong>Title:</strong> {report.title}</p>
                <p><strong>Previous Status:</strong> {old_status}</p>
                <p><strong>New Status:</strong> <span style="color: {status_color}; font-weight: bold;">{new_status}</span></p>
            </div>
            {message}
            <p>Thank you for your patience!</p>
        </div>
        <div style="background: #8B0000; padding: 10px; text-align: center;">
            <p style="color: white; margin: 0; font-size: 12px;">EVSU-OC Campus Safety Team</p>
        </div>
    </div>
    """
    return send_email(user.email, subject, html_content)

def send_feedback_request(user, report) -> bool:
    subject = f"Feedback Request - {report.ticket_id}"
    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #8B0000, #FFD700); padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">Alisto!</h1>
            <p style="color: white; margin: 5px 0;">EVSU-OC Campus Safety Reporting System</p>
        </div>
        <div style="padding: 20px; background: #f9f9f9;">
            <h2 style="color: #8B0000;">Your Report Has Been Resolved!</h2>
            <p>Dear {user.full_name},</p>
            <p>Great news! Your report has been marked as resolved.</p>
            <div style="background: white; padding: 15px; border-radius: 5px; margin: 15px 0; border-left: 4px solid #8B0000;">
                <p><strong>Ticket ID:</strong> {report.ticket_id}</p>
                <p><strong>Title:</strong> {report.title}</p>
                <p><strong>Location:</strong> {report.location}</p>
            </div>
            <p>We'd love to hear your feedback! Please log in to:</p>
            <ul>
                <li>Confirm the resolution</li>
                <li>Rate your experience</li>
                <li>Leave any comments</li>
            </ul>
            <p>Your feedback helps us improve our campus safety services!</p>
        </div>
        <div style="background: #8B0000; padding: 10px; text-align: center;">
            <p style="color: white; margin: 0; font-size: 12px;">EVSU-OC Campus Safety Team</p>
        </div>
    </div>
    """
    return send_email(user.email, subject, html_content)

def send_password_reset(user, reset_url: str) -> bool:
    subject = "Password Reset Request - Alisto!"
    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #8B0000, #FFD700); padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">Alisto!</h1>
            <p style="color: white; margin: 5px 0;">EVSU-OC Campus Safety Reporting System</p>
        </div>
        <div style="padding: 20px; background: #f9f9f9;">
            <h2 style="color: #8B0000;">Password Reset Request</h2>
            <p>Dear {user.full_name},</p>
            <p>We received a request to reset your password for your Alisto! account.</p>
            <div style="text-align: center; margin: 25px 0;">
                <a href="{reset_url}" style="background: #8B0000; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block;">Reset My Password</a>
            </div>
            <p style="color: #666; font-size: 14px;">This link will expire in <strong>1 hour</strong>.</p>
            <p style="color: #666; font-size: 14px;">If you didn't request a password reset, ignore this email. Your password will remain unchanged.</p>
            <div style="background: #fff3cd; padding: 10px; border-radius: 5px; margin: 15px 0; border-left: 4px solid #FFD700;">
                <p style="margin: 0; font-size: 13px;"><strong>Security Tip:</strong> Never share your password with anyone.</p>
            </div>
        </div>
        <div style="background: #8B0000; padding: 10px; text-align: center;">
            <p style="color: white; margin: 0; font-size: 12px;">EVSU-OC Campus Safety Team</p>
        </div>
    </div>
    """
    return send_email(user.email, subject, html_content)

def send_admin_new_report_notification(admin, reporter, report) -> bool:
    """Send email to admin when a new report is submitted"""
    subject = f"New Report Submitted - {report.ticket_id}"
    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #8B0000, #FFD700); padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">Alisto!</h1>
            <p style="color: white; margin: 5px 0;">EVSU-OC Campus Safety Reporting System</p>
        </div>
        <div style="padding: 20px; background: #f9f9f9;">
            <h2 style="color: #8B0000;">New Report Submitted</h2>
            <p>Dear Admin,</p>
            <p>A new safety report has been submitted and requires your attention.</p>
            <div style="background: white; padding: 15px; border-radius: 5px; margin: 15px 0; border-left: 4px solid #8B0000;">
                <p><strong>Ticket ID:</strong> {report.ticket_id}</p>
                <p><strong>Title:</strong> {report.title}</p>
                <p><strong>Location:</strong> {report.location}</p>
                <p><strong>Category:</strong> {report.category}</p>
                <p><strong>Priority:</strong> <span style="color: {'#dc3545' if report.priority == 'High' else '#ffc107' if report.priority == 'Medium' else '#28a745'};">{report.priority}</span></p>
                <p><strong>Status:</strong> {report.status}</p>
                <p><strong>Reported by:</strong> {reporter.full_name} ({reporter.student_id})</p>
            </div>
            <div style="background: #fff3cd; padding: 10px; border-radius: 5px; margin: 15px 0; border-left: 4px solid #FFD700;">
                <p style="margin: 0;"><strong>Description:</strong></p>
                <p style="margin: 5px 0 0 0;">{report.description}</p>
            </div>
            <p>Please review and take appropriate action.</p>
        </div>
        <div style="background: #8B0000; padding: 10px; text-align: center;">
            <p style="color: white; margin: 0; font-size: 12px;">EVSU-OC Campus Safety Team</p>
        </div>
    </div>
    """
    return send_email(admin.email, subject, html_content)

def send_report_deleted_notification(admin_email: str, user, report, deletion_reason: str) -> bool:
    subject = f"Report Deleted by User - {report.ticket_id}"
    html_content = f"""
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <div style="background: linear-gradient(135deg, #8B0000, #FFD700); padding: 20px; text-align: center;">
            <h1 style="color: white; margin: 0;">Alisto!</h1>
            <p style="color: white; margin: 5px 0;">EVSU-OC Campus Safety Reporting System</p>
        </div>
        <div style="padding: 20px; background: #f9f9f9;">
            <h2 style="color: #8B0000;">Report Deleted Notification</h2>
            <p>Dear Admin,</p>
            <p>A report has been deleted by the user who submitted it.</p>
            <div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin: 15px 0; border-left: 4px solid #FFD700;">
                <p><strong>Report Details:</strong></p>
                <p><strong>Ticket ID:</strong> {report.ticket_id}</p>
                <p><strong>Title:</strong> {report.title}</p>
                <p><strong>Reporter:</strong> {user.full_name} ({user.student_id})</p>
                <p><strong>Location:</strong> {report.location}</p>
                <p><strong>Category:</strong> {report.category}</p>
                <p><strong>Priority:</strong> {report.priority}</p>
                <p><strong>Status:</strong> {report.status}</p>
            </div>
            <div style="background: #ffe6e6; padding: 15px; border-radius: 5px; margin: 15px 0; border-left: 4px solid #8B0000;">
                <p><strong>Deletion Reason (provided by user):</strong></p>
                <p style="font-style: italic;">"{deletion_reason}"</p>
            </div>
            <p style="color: #666; font-size: 14px;">This report has been completely removed from the system.</p>
        </div>
        <div style="background: #8B0000; padding: 10px; text-align: center;">
            <p style="color: white; margin: 0; font-size: 12px;">EVSU-OC Campus Safety Team</p>
        </div>
    </div>
    """
    return send_email(admin_email, subject, html_content)
