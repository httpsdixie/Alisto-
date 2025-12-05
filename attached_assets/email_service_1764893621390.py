import resend
from flask import current_app
import os
import logging

logger = logging.getLogger(__name__)

def init_resend(app):
    api_key = app.config.get('RESEND_API_KEY') or os.environ.get('RESEND_API_KEY')
    if api_key:
        resend.api_key = api_key

def send_email(to_email, subject, html_content):
    """Send email via Resend"""
    try:
        api_key = current_app.config.get('RESEND_API_KEY') or os.environ.get('RESEND_API_KEY')
        
        if not api_key:
            logger.warning(f"Email skipped: RESEND_API_KEY not configured")
            return False
            
        params = {
            "from": "Alisto <onboarding@resend.dev>",
            "to": [to_email],
            "subject": subject,
            "html": html_content
        }
        
        email = resend.Emails.send(params)
        logger.info(f"Email sent to {to_email} - {subject}")
        return True
        
    except Exception as e:
        logger.error(f"Email failed to {to_email}: {str(e)}")
        return False

def send_report_confirmation(user, report):
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

def send_status_update(user, report, old_status, new_status):
    subject = f"Report Status Update - {report.ticket_id}"
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
                <p><strong>New Status:</strong> <span style="color: {'green' if new_status == 'Resolved' else '#FFD700' if new_status == 'In Progress' else '#8B0000'}; font-weight: bold;">{new_status}</span></p>
            </div>
            {'<p>Your issue has been resolved! Please log in to confirm and provide feedback.</p>' if new_status == 'Resolved' else '<p>Our maintenance team is now working on your reported issue.</p>' if new_status == 'In Progress' else ''}
            <p>Thank you for your patience!</p>
        </div>
        <div style="background: #8B0000; padding: 10px; text-align: center;">
            <p style="color: white; margin: 0; font-size: 12px;">EVSU-OC Campus Safety Team</p>
        </div>
    </div>
    """
    return send_email(user.email, subject, html_content)

def send_feedback_request(user, report):
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

def send_password_reset(user, reset_url):
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

def send_report_deleted_notification(admin_email, user, report, deletion_reason):
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
