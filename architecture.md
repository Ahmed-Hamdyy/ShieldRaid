# VulnScan Project Architecture

## Overview
VulnScan is a web-based vulnerability scanning application built with Flask and Supabase. The application provides security scanning capabilities, user management, and reporting features.

## Project Structure
```
vulnscan/
├── app.py                 # Main application file with Flask routes and core logic
├── requirements.txt       # Python dependencies
├── .env                  # Environment variables configuration
├── schema.sql            # Database schema definitions
├── scan_tools/           # Vulnerability scanning modules
├── templates/            # HTML templates
├── static/               # Static files (CSS, JavaScript, images)
├── logs/                 # Application logs
├── migrations/           # Database migrations
├── uploads/             # User uploaded files
└── tests/                # Test files

```

## Core Components

### 1. Backend Framework
- **Flask Application** (`app.py`)
  - Route handlers
  - Authentication middleware
  - WebSocket integration
  - Request processing
  - Response handling

### 2. Database Layer
- **Supabase Integration**
  - User management
  - Scan results storage
  - Settings management
  - Report storage
  - Real-time updates

### 3. Authentication System
- User registration
- Email verification
- Password management
- Session handling
- Role-based access control (RBAC)
  - Regular users
  - Administrators
  - Blue teamers
  - Analyzers

### 4. Scanning Engine
- **Scanner Manager**
  - Concurrent scan handling
  - Progress tracking
  - Result aggregation
  - Module coordination

### 5. Reporting System
- Multiple format support (PDF, HTML, JSON)
- Customizable templates
- Severity-based categorization
- Statistical analysis
- Export capabilities

## Key Features

### 1. User Management
- User registration and authentication
- Profile management
- Role-based permissions
- Settings customization

### 2. Vulnerability Scanning
- Multiple scanning modules
- Concurrent scan execution
- Real-time progress tracking
- Result analysis and storage

### 3. Dashboard and Analytics
- Scan statistics
- Vulnerability trends
- User activity monitoring
- Performance metrics

### 4. Reporting
- Automated report generation
- Multiple export formats
- Customizable templates
- Historical data access

### 5. Admin Panel
- User management
- System monitoring
- Configuration control
- Activity logging

## Technical Stack

### Frontend
- HTML5
- CSS3
- JavaScript
- WebSocket for real-time updates
- Chart.js for data visualization

### Backend
- Python 3.x
- Flask web framework
- Flask-SocketIO
- Supabase Python client

### Database
- Supabase (PostgreSQL)
- Real-time subscriptions
- Row Level Security (RLS)

### Security
- JWT authentication
- CSRF protection
- Rate limiting
- Input validation
- XSS prevention

## API Endpoints

### Authentication
- `/register` - User registration
- `/login` - User login
- `/logout` - User logout
- `/auth/verify` - Email verification
- `/auth/confirm` - Token confirmation

### Scanning
- `/scan` - Initiate new scan
- `/scan_results` - Get scan results
- `/scan_progress` - Get scan progress

### User Management
- `/profile` - User profile management
- `/settings/*` - User settings management
- `/api/regenerate-key` - API key management

### Reports
- `/reports` - Report management
- `/api/reports/generate/<scan_id>` - Generate report
- `/api/reports/download/<report_id>` - Download report

### Admin
- `/admin` - Admin dashboard
- `/admin/users/<user_id>` - User management
- `/admin/edit_user` - Edit user details

## Data Flow

1. **User Authentication**
   - User credentials → Authentication → Session management
   - Role assignment → Permission validation

2. **Scanning Process**
   - URL input → Scanner manager → Scanning modules
   - Progress tracking → Real-time updates
   - Result collection → Database storage

3. **Reporting**
   - Scan data → Report generation
   - Template processing → File creation
   - Storage → Download management

4. **Analytics**
   - Data collection → Processing
   - Visualization → Dashboard display

## Security Measures

1. **Authentication**
   - Secure password hashing
   - Email verification
   - Session management
   - Rate limiting

2. **Authorization**
   - Role-based access control
   - Resource permission checks
   - API key validation

3. **Data Protection**
   - Input sanitization
   - Output encoding
   - CSRF protection
   - XSS prevention

4. **System Security**
   - Error handling
   - Logging
   - Monitoring
   - Backup management

## Deployment

### Requirements
- Python 3.x
- PostgreSQL database
- Environment variables configuration
- SSL certificate

### Configuration
- Database connection
- Email service setup
- API keys
- Security settings

### Monitoring
- Error logging
- Performance tracking
- Security auditing
- User activity monitoring

## Future Enhancements

1. **Scanning Capabilities**
   - Additional vulnerability checks
   - Custom scanning rules
   - Integration with external tools

2. **Reporting**
   - Enhanced templates
   - Additional export formats
   - Automated scheduling

3. **Analytics**
   - Advanced metrics
   - Custom dashboards
   - Predictive analysis

4. **Integration**
   - Third-party security tools
   - CI/CD pipeline integration
   - API expansion 