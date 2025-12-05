# Product Requirement Document (PRD)

**Project Name:** Alisto! – EVSU-OC Campus Safety Reporting System  
**Version:** 1.0 (Updated)  
**Prepared by:**  
- Coste, Carlos Miguel  
- Labiste, Jonathan Jr.  
- Lacbayo, Mildred  
- Manawatao, Trisha Mae  
- Perida, Dixie Shanne L.  

**Date:** December 6, 2025

---

## 1. Introduction

### 1.1 Purpose
The **Alisto! Campus Safety Reporting System** is a modern web-based platform developed for Eastern Visayas State University – Ormoc Campus (EVSU–OC). Its primary purpose is to enhance campus safety, operational transparency, and responsiveness by providing a centralized, digital mechanism for reporting, managing, and tracking safety- or maintenance-related concerns.

This system embodies the principles of modern web applications—dynamic content rendering, secure authentication, RESTful API design, cloud-based storage, database-driven interfaces, input validation, and modular application architecture—ensuring an efficient, scalable, and mobile-first safety reporting solution aligned with current technological standards.

### 1.2 Scope
The scope of the system includes the following:

- **Fully responsive web interface** optimized for mobile devices with card-based layouts and native camera integration
- **Cloud-based file storage** using Cloudinary for scalable image management
- **Real-time dashboard updates** displaying statistics, recent reports, and status changes
- **Mobile-first design** with adaptive views (cards on mobile, tables on desktop)
- **Administrative dashboard** providing comprehensive tools for report handling, user management, and analytics
- **Secure relational database** (PostgreSQL via Neon) with structured tables for users, reports, feedback, status histories, and notifications
- **Automated email notifications** for status updates and feedback requests
- **Native device camera integration** for direct photo capture on mobile devices
- **Support for 100+ concurrent users** with optimized performance and cloud infrastructure

---

## 2. Objectives

The system aims to:

1. Establish a central platform for structured campus safety and maintenance reporting
2. Streamline administrative workflows for report evaluation, prioritization, and resolution
3. Strengthen accountability through transparent status tracking and user feedback mechanisms
4. Enhance campus operational responsiveness through email notifications
5. Ensure authenticity of submissions by restricting access to verified campus members only
6. Provide mobile-optimized experience for on-the-go reporting
7. Eliminate local storage dependencies through cloud-based file management

---

## 3. Target Users

The system supports two primary user roles:

### 3.1 Students and Faculty
- Submit safety or maintenance reports with detailed information and optional photographic evidence
- Monitor the status and progression of their submitted reports through mobile-friendly interfaces
- Provide post-resolution feedback to validate administrative actions
- Receive email notifications for status updates

### 3.2 Maintenance Personnel (Admin)
- Review, update, and manage all reports submitted within the campus
- Assign priorities, append notes, and track resolution timelines
- Upload resolution proof (photos or PDFs)
- View analytics and statistics for operational decision-making
- Manage user accounts and system notifications

---

## 4. Functional Requirements

### 4.1 User Registration & Authentication

**Registration:**
- Users register using verified institutional credentials:
  - Student ID (format: YYYY-NNNNN, e.g., 2024-10001)
  - Full name
  - Email address
  - Secure password
  - User type (Student/Faculty)
- Student ID format validation prevents unauthorized access
- Passwords are hashed using bcrypt (via passlib)
- Email validation ensures proper format

**Authentication:**
- Login using Student ID and password
- Session management via JWT tokens (python-jose)
- Role-based access control (RBAC) for admin functions
- Password reset via email with secure token generation
- Anonymous or unverified reporting is strictly prohibited

### 4.2 Report Submission

**Form Fields:**
- **Title:** 5-200 characters, required
- **Location:** Specific campus location, required
- **Description:** Detailed explanation (minimum 10 characters), required
- **Category:** Infrastructure, Safety Hazard, Electrical, Plumbing, Sanitation, Security, Other
- **Priority:** Low, Medium, High (default: Medium)
- **Photo Evidence:** Optional, max 5MB, formats: JPG, PNG, GIF

**Mobile Camera Integration:**
- Native camera access via HTML5 `capture="environment"` attribute
- Direct photo capture from mobile devices
- Automatic image compression (max 1200x1200px, JPEG format, 85% quality)
- Upload to Cloudinary cloud storage

**Submission Process:**
1. User fills form with validation feedback
2. Confirmation modal warns: "Once submitted, you cannot edit"
3. Loading overlay shows progress:
   - Without photo: "~1 second"
   - With photo: "5-15 seconds (uploading to cloud)"
4. Report saved to database with auto-generated ticket ID (format: EVSU-YYYY-NNN)
5. Status automatically set to "Pending"
6. User redirected to "My Reports" with success message

**Validation & Limits:**
- Maximum 5 reports per user per 24 hours (rate limiting)
- Duplicate detection (same title + location within 24 hours)
- Front-end and back-end validation
- File type and size validation

### 4.3 Dashboard Features

**Student/Faculty Dashboard:**
- **Statistics Cards:** Count of Pending, In Progress, and Resolved reports
- **Recent Reports:** Last 5 submitted reports with quick view
- **Mobile Optimization:** 
  - Full-width "Submit New Report" button on mobile
  - Card-based layout for reports (no horizontal scrolling)
  - Compact statistics display
- **Desktop View:** Table layout with all report details

**Administrative Dashboard:**
- **Overview Statistics:**
  - Total users count
  - Pending, In Progress, Resolved report counts
  - User satisfaction metrics (average rating, feedback percentage)
- **Visual Analytics:**
  - Reports by category (doughnut chart)
  - Reports by priority (bar chart)
  - Chart.js integration for data visualization
- **Recent Reports:** Quick access to latest submissions
- **Mobile-Responsive:** 2-column grid on mobile, 4-column on desktop

### 4.4 Report Management

**My Reports Page (Users):**
- **Search & Filter:**
  - Full-width search bar on mobile
  - Dropdown filters: Category, Status, Priority, Sort order
  - Emoji icons for better mobile UX (📁 Category, 📊 Status, ⚠️ Priority)
  - Auto-submit on filter change
- **View Modes:**
  - Mobile: Card view with all essential info
  - Desktop: Table view with sortable columns
- **Pagination:** Navigate through multiple pages of reports
- **Actions:** View details, delete (if Pending status only)

**All Reports Page (Admin):**
- Same search/filter capabilities as user view
- Additional search by ticket ID
- Manage button for each report
- Mobile-optimized card layout

**Report Details Page:**
- Full report information display
- Photo evidence viewer (Cloudinary URLs)
- Status history timeline with timestamps
- Admin notes section
- Resolution proof display (images or PDF links)
- Feedback section (if resolved)
- Delete option (users, Pending status only)

### 4.5 Admin Report Management

**Update Report:**
- Change status: Pending → In Progress → Resolved
- Modify priority level
- Add admin notes
- Upload resolution proof (photo or PDF)
- Automatic email notification to reporter on status change

**Status Change Actions:**
- **To "In Progress":** Email notification sent
- **To "Resolved":** 
  - Email notification sent
  - Feedback request email sent
  - Resolved timestamp recorded
  - Admin ID recorded

### 4.6 Notifications

**Email Notifications (Gmail SMTP):**
- ~~Report submission confirmation~~ (Removed - users see report in dashboard)
- Status update notifications (with old and new status)
- Feedback request when report is resolved
- Password reset emails

**Admin Notifications (In-app):**
- New report submissions
- Notification badge on bell icon
- Last 20 notifications displayed
- Auto-cleanup of old notifications

### 4.7 Feedback Loop

**Post-Resolution Feedback:**
- Triggered when report status = "Resolved"
- User can provide:
  - **Rating:** 1-5 stars (required)
  - **Comments:** Optional text feedback
  - **Resolution Confirmation:** Yes/No checkbox
- Feedback stored for admin quality assessment
- Displayed on report details page
- Contributes to satisfaction metrics on admin dashboard

### 4.8 Search & Filter

**Available Filters:**
- Keyword search (title, description, location, ticket ID)
- Category filter (all categories + "All")
- Status filter (Pending, In Progress, Resolved, All)
- Priority filter (Low, Medium, High, All)
- Sort options: Newest, Oldest, Priority High, Priority Low

**Implementation:**
- Auto-submit on filter change (no search button needed)
- Maintains filter state across pagination
- Mobile-optimized dropdown selectors

### 4.9 Validation & Error Handling

**Input Validation:**
- Front-end: HTML5 validation + JavaScript
- Back-end: Pydantic schemas + custom validators
- Student ID pattern checking (YYYY-NNNNN format)
- Email format validation
- File upload validation (type, size)
- XSS prevention via HTML escaping

**Error Handling:**
- Graceful error messages via flash cookies
- Form validation feedback
- Network error handling
- File upload error messages
- Database error recovery

---

## 5. Non-Functional Requirements

### 5.1 Performance
- Report submission: <1 second without photo, 5-15 seconds with photo
- Dashboard load time: <2 seconds
- Image compression before upload reduces transfer time
- Cloudinary CDN for fast image delivery
- Database query optimization with indexes
- Support for 100+ concurrent users

### 5.2 Usability
- **Mobile-First Design:** Optimized for smartphones and tablets
- **Responsive Layout:** Bootstrap 5 grid system
- **Intuitive Navigation:** Clear menu structure and breadcrumbs
- **Accessible Typography:** Readable fonts and contrast ratios
- **Loading Indicators:** Progress feedback for all async operations
- **Error Messages:** Clear, actionable user feedback
- **Native Camera:** Direct camera access on mobile devices

### 5.3 Security
- **Password Security:** bcrypt hashing (via passlib)
- **Session Management:** JWT tokens with expiration
- **CSRF Protection:** Security headers and token validation
- **XSS Prevention:** HTML escaping and Content Security Policy
- **SQL Injection Prevention:** SQLAlchemy ORM with parameterized queries
- **Rate Limiting:** Max 5 reports per 24 hours per user
- **File Upload Security:** Type and size validation
- **HTTPS Enforcement:** Strict-Transport-Security header

### 5.4 Reliability
- **Database:** PostgreSQL on Neon with automatic backups
- **Cloud Storage:** Cloudinary with 99.9% uptime SLA
- **Error Logging:** Comprehensive error tracking
- **Graceful Degradation:** Fallback mechanisms for failures
- **Data Integrity:** Foreign key constraints and transactions

### 5.5 Maintainability
- **Modular Architecture:** Separation of concerns (models, routes, services)
- **Clean Code:** Consistent naming conventions and formatting
- **Documentation:** Inline comments and README files
- **Version Control:** Git with meaningful commit messages
- **Environment Configuration:** .env file for sensitive data

### 5.6 Scalability
- **Cloud Infrastructure:** Render deployment with auto-scaling
- **Cloud Storage:** Cloudinary eliminates local storage bottlenecks
- **Database:** PostgreSQL optimized for growth
- **Stateless Design:** Horizontal scaling capability
- **CDN Integration:** Fast global content delivery

---

## 6. System Architecture

### 6.1 High-Level Overview

```
[User Interface - HTML/CSS/JS/Bootstrap 5]
           ↓
[FastAPI Application Layer]
           ↓
[Authentication & Authorization - JWT]
           ↓
[Business Logic Layer]
    ├── Report Management
    ├── User Management
    ├── Notification System
    └── File Upload Handler
           ↓
[Data Layer]
    ├── PostgreSQL Database (Neon)
    └── Cloudinary Storage
           ↓
[External Services]
    ├── Gmail SMTP (Email)
    └── Cloudinary API (Images)
```

### 6.2 Module Descriptions

**User Module:**
- Registration with validation
- Login with JWT token generation
- Password reset functionality
- Role-based access control
- Profile management

**Reporting Module:**
- Report CRUD operations
- File upload to Cloudinary
- Image compression
- Duplicate detection
- Rate limiting

**Administrative Module:**
- Report management interface
- Status updates
- Priority assignment
- Analytics dashboard
- User management

**Feedback Module:**
- Post-resolution feedback collection
- Rating system
- Resolution confirmation
- Feedback display

**Notification Module:**
- Email notifications (Gmail SMTP)
- In-app notifications for admins
- Notification history
- Auto-cleanup

**File Management Module:**
- Cloudinary integration
- Image compression (JPEG, max 1200x1200, 85% quality)
- File validation
- URL generation

---

## 7. Technology Stack

### 7.1 Frontend
- **HTML5:** Semantic markup
- **CSS3:** Custom styling
- **JavaScript (ES6+):** Client-side interactivity
- **Bootstrap 5:** Responsive framework
- **Bootstrap Icons:** Icon library
- **Chart.js:** Data visualization
- **Fetch API:** Asynchronous requests

### 7.2 Backend
- **Python 3.13+**
- **FastAPI:** Modern web framework
- **Uvicorn:** ASGI server
- **SQLAlchemy:** ORM for database operations
- **Pydantic:** Data validation
- **Passlib[bcrypt]:** Password hashing
- **Python-Jose[cryptography]:** JWT tokens
- **Python-Multipart:** File upload handling
- **Pillow:** Image processing
- **Jinja2:** Template engine
- **Cloudinary:** Cloud storage SDK

### 7.3 Database
- **PostgreSQL:** Relational database
- **Neon:** Serverless PostgreSQL hosting
- **SQLAlchemy ORM:** Database abstraction

### 7.4 External Services
- **Cloudinary:** Image and file storage
- **Gmail SMTP:** Email delivery
- **Neon:** Database hosting
- **Render:** Application hosting

### 7.5 Development Tools
- **Version Control:** Git + GitHub
- **IDE:** Visual Studio Code / Kiro IDE
- **Package Manager:** pip
- **Environment Management:** python-dotenv
- **Deployment:** Render (with render.yaml)

---

## 8. Workflow

### 8.1 User Registration and Login
1. User accesses registration page
2. Fills form with Student ID, name, email, password, user type
3. System validates Student ID format and email
4. Password hashed with bcrypt
5. User record created in database
6. Redirect to login page
7. User logs in with Student ID and password
8. JWT token generated and stored in session
9. Redirect to dashboard

### 8.2 Report Submission
1. User clicks "Submit New Report"
2. Fills form with title, location, description, category, priority
3. Optionally captures photo using native camera or uploads file
4. Clicks submit → confirmation modal appears
5. User confirms submission
6. Loading overlay shows progress message
7. If photo attached:
   - Image compressed to JPEG (max 1200x1200, 85% quality)
   - Uploaded to Cloudinary (5-15 seconds)
   - Cloudinary URL returned
8. Report saved to database with auto-generated ticket ID
9. Status history record created
10. Admin notification created
11. User redirected to "My Reports" with success message

### 8.3 Admin Review & Management
1. Admin logs in and views dashboard
2. Sees statistics and recent reports
3. Clicks "View All" to see all reports
4. Filters/searches for specific reports
5. Clicks "Manage" on a report
6. Views full report details and photo evidence
7. Updates status (Pending → In Progress → Resolved)
8. Changes priority if needed
9. Adds admin notes
10. Uploads resolution proof (if resolved)
11. Saves changes
12. System sends email notification to reporter
13. If resolved, sends feedback request email

### 8.4 Notifications
1. **Status Update:**
   - Admin changes report status
   - System generates email with old and new status
   - Email sent to reporter via Gmail SMTP
2. **Feedback Request:**
   - Report marked as "Resolved"
   - System generates feedback request email
   - Email sent to reporter with link to report

### 8.5 Feedback Collection
1. User receives feedback request email
2. Clicks link to view resolved report
3. Feedback form appears on report page
4. User provides rating (1-5 stars)
5. Optionally adds comments
6. Confirms if issue is actually resolved
7. Submits feedback
8. Feedback saved to database
9. Contributes to admin satisfaction metrics

### 8.6 Analytics & Reporting
1. Admin accesses dashboard
2. Views statistics cards (users, pending, in progress, resolved)
3. Views satisfaction metrics (average rating, feedback percentage)
4. Views charts:
   - Reports by category (doughnut chart)
   - Reports by priority (bar chart)
5. Charts update dynamically based on current data

---

## 9. Deliverables

1. **Fully functional web application** with mobile-first responsive design
2. **User dashboard** with statistics and report management
3. **Administrative dashboard** with analytics and comprehensive management tools
4. **PostgreSQL database** with structured schema and relationships
5. **Cloudinary integration** for scalable file storage
6. **Email notification system** via Gmail SMTP
7. **Native camera integration** for mobile devices
8. **Automated feedback collection** system
9. **Comprehensive documentation:**
   - User manual
   - Admin guide
   - Technical documentation
   - API documentation
10. **Deployment configuration** for Render hosting

---

## 10. Development Roadmap

### Phase 1: Foundation (Completed)
- ✅ User authentication and registration
- ✅ Database schema design and implementation
- ✅ Basic report submission form
- ✅ PostgreSQL integration via Neon

### Phase 2: Core Features (Completed)
- ✅ User and admin dashboards
- ✅ Report CRUD operations
- ✅ Status management
- ✅ Email notifications (Gmail SMTP)

### Phase 3: Advanced Features (Completed)
- ✅ Cloudinary integration for file storage
- ✅ Image compression and optimization
- ✅ Analytics and charts (Chart.js)
- ✅ Feedback system
- ✅ Admin notifications

### Phase 4: Mobile Optimization (Completed)
- ✅ Native camera integration
- ✅ Mobile-first responsive design
- ✅ Card-based layouts for mobile
- ✅ Adaptive table/card views
- ✅ Loading indicators with progress messages

### Phase 5: Polish & Deployment (Completed)
- ✅ Comprehensive testing
- ✅ Security hardening
- ✅ Performance optimization
- ✅ Documentation
- ✅ Render deployment configuration

---

## 11. Risks & Constraints

### 11.1 Technical Risks
- **Cloud Service Dependency:** Reliance on Cloudinary and Neon availability
- **Network Dependency:** Photo uploads require stable internet connection
- **Mobile Browser Compatibility:** Camera API support varies by browser
- **Email Delivery:** Gmail SMTP may have rate limits or deliverability issues

### 11.2 User Adoption Risks
- User reluctance to submit feedback
- Incomplete report submissions
- Duplicate or spam reports

### 11.3 Operational Constraints
- Limited admin resources for report management
- Data sensitivity and privacy implications
- Storage costs for high-volume photo uploads

### 11.4 Mitigation Strategies
- **Fallback Mechanisms:** File upload option if camera fails
- **Rate Limiting:** Prevent spam and abuse
- **User Education:** Clear instructions and help documentation
- **Monitoring:** Track system performance and errors
- **Regular Audits:** Security and data privacy reviews
- **Cost Management:** Cloudinary free tier monitoring

---

## 12. Success Criteria

The system will be considered successful if:

1. ✅ **Reliability:** Users can consistently submit and track reports without errors
2. ✅ **Efficiency:** Administrators can manage and resolve issues within reasonable timeframes
3. ✅ **Performance:** System handles 100+ concurrent users without degradation
4. ✅ **Mobile Experience:** Mobile users can easily submit reports with photos
5. ✅ **Security:** All reports originate from verified users with secure authentication
6. ✅ **Notifications:** Email notifications are delivered reliably and promptly
7. ✅ **User Satisfaction:** Average feedback rating ≥ 4.0 stars
8. ✅ **Adoption:** At least 70% of campus community registers within first semester
9. ✅ **Response Time:** Average report resolution time ≤ 7 days
10. ✅ **Data Integrity:** Zero data loss incidents
11. ✅ **Uptime:** System availability ≥ 99% during operational hours

---

## 13. Future Enhancements

### 13.1 Planned Features
- **QR Code Location Encoding:** Scan QR codes at campus locations for auto-fill
- **Real-time Updates:** WebSocket integration for live dashboard updates
- **Push Notifications:** Browser push notifications for status updates
- **Multi-language Support:** Tagalog and English language options
- **Advanced Analytics:** Trend analysis and predictive maintenance
- **Mobile App:** Native iOS and Android applications
- **Chatbot Integration:** AI-powered help and FAQ system

### 13.2 Scalability Plans
- Expansion to other EVSU campuses
- Integration with campus-wide maintenance management system
- API for third-party integrations
- Advanced reporting and export features

---

## Appendix A: Database Schema

### Tables
1. **users:** User accounts and authentication
2. **reports:** Safety and maintenance reports
3. **status_history:** Report status change timeline
4. **feedback:** User feedback on resolved reports
5. **notifications:** Admin notification system

### Key Relationships
- User → Reports (one-to-many)
- Report → Status History (one-to-many)
- Report → Feedback (one-to-one)
- Report → Admin (many-to-one, assigned_admin)

---

## Appendix B: API Endpoints

### Authentication
- `GET /` - Home page
- `GET /register` - Registration form
- `POST /register` - Create account
- `GET /login` - Login form
- `POST /login` - Authenticate user
- `GET /logout` - End session
- `GET /forgot-password` - Password reset request
- `POST /forgot-password` - Send reset email
- `GET /reset-password/{token}` - Reset password form
- `POST /reset-password/{token}` - Update password

### User Dashboard
- `GET /dashboard` - User/Admin dashboard
- `GET /profile` - User profile
- `POST /profile` - Update profile

### Reports
- `GET /report/new` - New report form
- `POST /report/new` - Submit report
- `GET /my-reports` - User's reports list
- `GET /report/{id}` - View report details
- `POST /report/{id}/delete` - Delete report
- `POST /report/{id}/feedback` - Submit feedback

### Admin
- `GET /admin/reports` - All reports list
- `GET /admin/report/{id}` - Manage report
- `POST /admin/report/{id}/update` - Update report
- `GET /admin/users` - User management
- `GET /admin/guide` - Admin guide

### API
- `GET /api/user/report-updates` - Check for updates

---

## Appendix C: Environment Variables

Required environment variables for deployment:

```
DATABASE_URL=postgresql://...
SESSION_SECRET=<random-secret-key>
GMAIL_USER=<email-address>
GMAIL_APP_PASSWORD=<app-password>
ADMIN_STUDENT_IDS=<comma-separated-ids>
DEBUG=False
CLOUDINARY_CLOUD_NAME=<cloud-name>
CLOUDINARY_API_KEY=<api-key>
CLOUDINARY_API_SECRET=<api-secret>
```

---

**Document Version:** 1.0 (Updated)  
**Last Updated:** December 6, 2025  
**Status:** Production Ready
