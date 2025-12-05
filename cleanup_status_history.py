"""
Script to clean up status history data
This will remove duplicate or incorrect status history entries
"""
from database import get_db, engine
from models import StatusHistory, Report, User
from sqlalchemy.orm import Session

def cleanup_status_history():
    """Clean up status history table"""
    db = next(get_db())
    
    try:
        print("Starting status history cleanup...")
        
        # Get all reports
        reports = db.query(Report).all()
        print(f"Found {len(reports)} reports")
        
        for report in reports:
            print(f"\nProcessing Report ID: {report.id} (Ticket: {report.ticket_id})")
            
            # Get all status history for this report
            histories = db.query(StatusHistory).filter_by(report_id=report.id).order_by(StatusHistory.created_at.asc()).all()
            print(f"  Found {len(histories)} status history entries")
            
            # Display current entries
            for h in histories:
                print(f"    - {h.old_status} → {h.new_status} at {h.created_at} by {h.changed_by.full_name}")
            
            # Check for issues
            if len(histories) == 0:
                print("  ⚠️  No status history! Creating initial entry...")
                # Create initial status history
                initial_history = StatusHistory(
                    report_id=report.id,
                    old_status=None,
                    new_status='Pending',
                    notes='Report submitted',
                    changed_by_id=report.user_id,
                    created_at=report.created_at
                )
                db.add(initial_history)
                print("  ✅ Created initial status history")
            
            # Check for duplicate "Pending - Report submitted" entries
            pending_entries = [h for h in histories if h.old_status is None and h.new_status == 'Pending']
            if len(pending_entries) > 1:
                print(f"  ⚠️  Found {len(pending_entries)} duplicate 'Pending' entries. Keeping only the first one...")
                # Keep the oldest one, delete the rest
                for h in pending_entries[1:]:
                    db.delete(h)
                    print(f"    Deleted duplicate entry from {h.created_at}")
                print("  ✅ Removed duplicate entries")
            
            # Check for invalid status transitions (Pending → Resolved without In Progress)
            if len(histories) >= 2:
                for i in range(len(histories) - 1):
                    current = histories[i]
                    next_entry = histories[i + 1]
                    
                    if current.new_status == 'Pending' and next_entry.new_status == 'Resolved':
                        print(f"  ⚠️  Invalid transition: Pending → Resolved (skipped In Progress)")
                        print(f"    This happened at {next_entry.created_at}")
                        # Note: We won't auto-fix this as it's historical data
                        # Admin should manually update if needed
        
        # Commit all changes
        db.commit()
        print("\n✅ Status history cleanup completed!")
        print("\nSummary:")
        print(f"  - Processed {len(reports)} reports")
        print(f"  - Fixed missing initial entries")
        print(f"  - Removed duplicate entries")
        
    except Exception as e:
        print(f"\n❌ Error during cleanup: {str(e)}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    print("=" * 60)
    print("STATUS HISTORY CLEANUP SCRIPT")
    print("=" * 60)
    print("\nThis script will:")
    print("1. Check all reports for status history issues")
    print("2. Create missing initial 'Pending' entries")
    print("3. Remove duplicate entries")
    print("4. Report invalid status transitions")
    print("\n" + "=" * 60)
    
    response = input("\nDo you want to proceed? (yes/no): ")
    if response.lower() in ['yes', 'y']:
        cleanup_status_history()
    else:
        print("Cleanup cancelled.")
