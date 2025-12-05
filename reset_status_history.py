"""
Script to completely reset status history
This will delete all status history and recreate proper entries based on current report status
"""
from database import get_db
from models import StatusHistory, Report
from datetime import datetime

def reset_status_history():
    """Reset all status history"""
    db = next(get_db())
    
    try:
        print("Starting status history reset...")
        
        # Delete all existing status history
        count = db.query(StatusHistory).count()
        print(f"Deleting {count} existing status history entries...")
        db.query(StatusHistory).delete()
        db.commit()
        print("✅ All status history deleted")
        
        # Get all reports
        reports = db.query(Report).all()
        print(f"\nRecreating status history for {len(reports)} reports...")
        
        for report in reports:
            print(f"\nReport ID: {report.id} (Ticket: {report.ticket_id})")
            print(f"  Current Status: {report.status}")
            print(f"  Created: {report.created_at}")
            
            # Create initial "Pending" entry
            initial = StatusHistory(
                report_id=report.id,
                old_status=None,
                new_status='Pending',
                notes='Report submitted',
                changed_by_id=report.user_id,
                created_at=report.created_at
            )
            db.add(initial)
            print("  ✅ Created: Pending (Report submitted)")
            
            # If status is "In Progress" or "Resolved", create intermediate entries
            if report.status in ['In Progress', 'Resolved']:
                # Create "In Progress" entry
                in_progress = StatusHistory(
                    report_id=report.id,
                    old_status='Pending',
                    new_status='In Progress',
                    notes='Status updated by admin',
                    changed_by_id=report.assigned_admin_id if report.assigned_admin_id else report.user_id,
                    created_at=report.created_at  # Use report creation time as base
                )
                db.add(in_progress)
                print("  ✅ Created: Pending → In Progress")
            
            # If status is "Resolved", create final entry
            if report.status == 'Resolved':
                resolved = StatusHistory(
                    report_id=report.id,
                    old_status='In Progress',
                    new_status='Resolved',
                    notes='Issue resolved' + (f'\n{report.admin_notes}' if report.admin_notes else ''),
                    changed_by_id=report.assigned_admin_id if report.assigned_admin_id else report.user_id,
                    created_at=report.resolved_at if report.resolved_at else report.created_at
                )
                db.add(resolved)
                print("  ✅ Created: In Progress → Resolved")
        
        # Commit all changes
        db.commit()
        print("\n" + "=" * 60)
        print("✅ STATUS HISTORY RESET COMPLETED!")
        print("=" * 60)
        print(f"\nRecreated status history for {len(reports)} reports")
        print("All reports now have proper status flow:")
        print("  - Pending reports: 1 entry (Pending)")
        print("  - In Progress reports: 2 entries (Pending → In Progress)")
        print("  - Resolved reports: 3 entries (Pending → In Progress → Resolved)")
        
    except Exception as e:
        print(f"\n❌ Error during reset: {str(e)}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    print("=" * 60)
    print("STATUS HISTORY RESET SCRIPT")
    print("=" * 60)
    print("\n⚠️  WARNING: This will DELETE all existing status history!")
    print("\nThis script will:")
    print("1. Delete ALL status history entries")
    print("2. Recreate proper status history based on current report status")
    print("3. Ensure proper status flow: Pending → In Progress → Resolved")
    print("\n" + "=" * 60)
    
    response = input("\nAre you sure you want to proceed? (yes/no): ")
    if response.lower() in ['yes', 'y']:
        confirm = input("Type 'RESET' to confirm: ")
        if confirm == 'RESET':
            reset_status_history()
        else:
            print("Confirmation failed. Reset cancelled.")
    else:
        print("Reset cancelled.")
