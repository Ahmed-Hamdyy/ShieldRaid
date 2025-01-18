# VulnScan Pro - Project Guide

## Project Overview
VulnScan Pro is a comprehensive web application vulnerability scanner built with Flask and modern web technologies.

## Core Technologies
- **Backend**: Flask 2.0.1
- **Database**: Supabase
- **Real-time**: Flask-SocketIO
- **Frontend**: HTML5, CSS3, JavaScript
- **Authentication**: Custom with Supabase
- **UI Framework**: Bootstrap 5.3

## Project Structure

### Core Files
- `app.py` - Main application file
- `.env` - Environment variables
- `requirements.txt` - Python dependencies
- `database_setup.sql` - Database schema

### Templates Directory (`/templates`)
- `base.html` - Base template with modern UI and theme support
- `landing.html` - Landing page with full-width design
- `documentation.html` - Documentation and guides
- `dashboard.html` - User dashboard
- `index.html` - Main scanning interface
- Authentication Pages:
  - `login.html`
  - `register.html`
  - `verify_email.html`
  - `confirm_email.html`
- Test Pages:
  - `vulnerable_test.html`
  - `sql_test.html`
  - `xss_test.html`
  - `csrf_test.html`
  - `redirect_test.html`

### Static Assets (`/static`)
- CSS:
  - `style.css` - Main stylesheet with theme variables
- JavaScript:
  - UI interactions
  - Real-time updates
  - Theme switching
- Images:
  - Logos and icons

### Scan Tools (`/scan_tools`)
Core scanning functionality modules:
- `scanner_manager.py` - Central scan coordinator
- `utils.py` - Common utilities

Vulnerability Checkers:
1. Authentication & Session:
   - `check_broken_authentication.py`
   - `check_session_fixation.py`

2. Injection & XSS:
   - `check_sql_injection.py`
   - `check_xss.py`
   - `check_xxe.py`

3. Access Control:
   - `check_idor.py`
   - `check_csrf.py`
   - `check_mass_assignment.py`

4. Security Configuration:
   - `check_security_headers.py`
   - `check_content_security_policy.py`
   - `check_ssl_tls.py`
   - `check_security_misconfiguration.py`

5. Data Protection:
   - `check_sensitive_data_exposure.py`
   - `check_unencrypted_sensitive_cookies.py`

6. File Operations:
   - `check_directory_traversal.py`
   - `check_path_traversal.py`
   - `check_insecure_file_upload.py`

7. Other Security Checks:
   - `check_clickjacking.py`
   - `check_insecure_deserialization.py`
   - `check_remote_code_execution.py`
   - `check_vulnerable_components.py`
   - `check_weak_password_policies.py`
   - `check_no_rate_limiting.py`

## UI Theme System
- Dark/Light theme support
- CSS Variables for consistent styling
- Modern glass-morphism effects
- Responsive design
- Animated transitions

### Color Palette
```css
--primary-color: #00ff9d
--secondary-color: #0066ff
--accent-color: #ff00ff
--background-dark: #0a0b0e
--text-primary: #ffffff
--text-secondary: #b3b3b3
```

## Key Features
1. **User Management**
   - Registration with email verification
   - Secure authentication
   - Session management

2. **Vulnerability Scanning**
   - Multiple scan modules
   - Real-time progress updates
   - Detailed vulnerability reports

3. **Dashboard**
   - Scan history
   - Statistics and metrics
   - Visual data representation

4. **Documentation**
   - User guides
   - API documentation
   - Security recommendations

## Database Schema
Key tables:
- users
- scans
- vulnerabilities
- scan_results
- user_settings

## API Endpoints
1. **Authentication**
   - `/register` - User registration
   - `/login` - User login
   - `/logout` - User logout

2. **Scanning**
   - `/vulnscan` - Main scanning interface
   - `/scan/start` - Start new scan
   - `/scan/status` - Get scan status
   - `/scan/results` - Get scan results

3. **Dashboard**
   - `/dashboard` - User dashboard
   - `/dashboard/stats` - Get statistics
   - `/dashboard/history` - Scan history

## Development Guidelines
1. **Code Style**
   - PEP 8 for Python
   - Modern ES6+ for JavaScript
   - BEM methodology for CSS
   - Type hints for Python 3.9+
   - ESLint for JavaScript linting

2. **Security Practices**
   - Input validation
   - Output encoding
   - CSRF protection
   - Rate limiting
   - Secure headers
   - Content Security Policy (CSP)
   - HTTPS enforcement
   - Cookie security (SameSite, Secure, HttpOnly)
   - Regular dependency updates
   - Security headers monitoring

3. **Performance**
   - Async operations
   - Efficient database queries
   - Resource caching
   - Optimized assets
   - Lazy loading for images
   - Code splitting
   - Service Worker for offline capabilities
   - Progressive Web App (PWA) features

4. **Testing**
   - Unit tests with pytest
   - Integration tests
   - End-to-end testing with Playwright
   - Security testing with OWASP ZAP
   - Performance testing with Lighthouse
   - Continuous Integration/Deployment (CI/CD)

## Update Log
- Initial setup: Base template and landing page
- Added: Modern UI components and theme system
- Added: Full-width responsive design
- Added: Glass-morphism effects and animations
- Added: Real-time scanning capabilities
- Added: Dashboard and documentation pages
- Added: Enhanced security practices and testing guidelines
- Added: PWA features and performance optimizations

*Last Updated: November 14, 2023* 