"""
Script to clear Neon PostgreSQL database
"""
from database import engine, Base
from models import User, Report, StatusHistory, Feedback, Notification

print("⚠️  WARNING: This will delete ALL data from the Neon database!")
print("Database:", engine.url)
confirm = input("Type 'YES' to confirm: ")

if confirm == "YES":
    print("\n🗑️  Dropping all tables...")
    Base.metadata.drop_all(bind=engine)
    
    print("✨ Creating fresh tables...")
    Base.metadata.create_all(bind=engine)
    
    print("✅ Neon database cleared and recreated!")
    print("All users, reports, and data have been deleted.")
else:
    print("❌ Cancelled. No changes made.")
