import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    SECRET_KEY: str = os.environ.get('SESSION_SECRET') or os.urandom(24).hex()
    
    DATABASE_URL: str = os.environ.get('DATABASE_URL', '')
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL environment variable is required")
    
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7
    
    MAX_CONTENT_LENGTH: int = 5 * 1024 * 1024
    UPLOAD_FOLDER: str = 'static/uploads'
    ALLOWED_EXTENSIONS: set = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
    
    RESEND_API_KEY: str = os.environ.get('RESEND_API_KEY', '')
    
    ADMIN_STUDENT_IDS: list = [sid.strip() for sid in os.environ.get('ADMIN_STUDENT_IDS', '').split(',') if sid.strip()]
    
    # Cloudinary settings
    CLOUDINARY_CLOUD_NAME: str = os.environ.get('CLOUDINARY_CLOUD_NAME', '')
    CLOUDINARY_API_KEY: str = os.environ.get('CLOUDINARY_API_KEY', '')
    CLOUDINARY_API_SECRET: str = os.environ.get('CLOUDINARY_API_SECRET', '')
    USE_CLOUDINARY: bool = bool(CLOUDINARY_CLOUD_NAME and CLOUDINARY_API_KEY and CLOUDINARY_API_SECRET)

settings = Settings()
