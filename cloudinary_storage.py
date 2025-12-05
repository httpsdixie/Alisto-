"""
Cloudinary storage implementation for file uploads
"""
from typing import Optional
import cloudinary
import cloudinary.uploader
from fastapi import UploadFile
from config import settings

# Initialize Cloudinary if credentials are available
if settings.USE_CLOUDINARY:
    cloudinary.config(
        cloud_name=settings.CLOUDINARY_CLOUD_NAME,
        api_key=settings.CLOUDINARY_API_KEY,
        api_secret=settings.CLOUDINARY_API_SECRET,
        secure=True
    )

async def save_to_cloudinary(file: UploadFile, contents: bytes = None, folder: str = "alisto_uploads") -> Optional[str]:
    """
    Upload file to Cloudinary and return the public URL
    """
    if not settings.USE_CLOUDINARY:
        print("Cloudinary not configured. Set CLOUDINARY_* environment variables.")
        return None
    
    try:
        if contents is None:
            contents = await file.read()
        
        # Upload to Cloudinary with auto format detection
        result = cloudinary.uploader.upload(
            contents,
            folder=folder,
            resource_type="image",
            format="auto",  # Auto-detect WebP or JPEG
            quality="auto:eco"  # Eco quality for faster processing
        )
        
        # Return the secure URL
        return result.get('secure_url')
        
    except Exception as e:
        print(f"Error uploading to Cloudinary: {str(e)}")
        return None
