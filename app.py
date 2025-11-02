from flask import Flask, render_template, request, redirect, url_for, flash, session
from firebase_config import initialize_firebase, db
import os
from dotenv import load_dotenv
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import requests
from firebase_admin import firestore
import json
import time
import random
import string
from datetime import datetime, timedelta
from authlib.integrations.flask_client import OAuth
import hashlib
import logging
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach

# Note: netifaces is not available on this system, using basic IP detection
NETIFACES_AVAILABLE = False

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default-secret-key')

# Make hasattr available in Jinja2 templates
app.jinja_env.globals.update(hasattr=hasattr)

# Configure logging with security focus
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)

# Add security event logging
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.WARNING)
security_handler = logging.FileHandler('security.log')
security_handler.setFormatter(logging.Formatter('%(asctime)s - SECURITY - %(levelname)s - %(message)s'))
security_logger.addHandler(security_handler)
logger = logging.getLogger(__name__)

# CSRF protection enabled for security
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)

# Initialize rate limiter with stricter limits for security
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per day", "20 per hour"],
    storage_uri="memory://"
)

# OAuth Configuration
oauth = OAuth(app)

# Google OAuth Configuration
# Use environment variable for redirect URI, default to localhost
google_redirect_uri = os.getenv('GOOGLE_REDIRECT_URI', 'http://localhost:5000/authorize/google')

google = oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET'),
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    access_token_url='https://oauth2.googleapis.com/token',
    access_token_params=None,
    refresh_token_url=None,
    redirect_uri=google_redirect_uri,
    jwks_uri='https://www.googleapis.com/oauth2/v3/certs',
    client_kwargs={
        'scope': 'openid email profile',
        # Add mobile-friendly parameters
        'prompt': 'consent',
        'access_type': 'offline',
        'include_granted_scopes': 'true'
    }
)

# Facebook OAuth Configuration
# Use environment variable for redirect URI, default to localhost
facebook_redirect_uri = os.getenv('FACEBOOK_REDIRECT_URI', 'http://localhost:5000/authorize/facebook')

facebook = oauth.register(
    name='facebook',
    client_id=os.getenv('FACEBOOK_APP_ID'),
    client_secret=os.getenv('FACEBOOK_APP_SECRET'),
    access_token_url='https://graph.facebook.com/oauth/access_token',
    access_token_params=None,
    authorize_url='https://www.facebook.com/dialog/oauth',
    authorize_params=None,
    redirect_uri=facebook_redirect_uri,
    api_base_url='https://graph.facebook.com/',
    client_kwargs={'scope': 'email'},
)

# File-based user storage for Datastore Mode
USERS_FILE = 'users.json'

def load_users_from_file():
    """Load users from JSON file for Datastore Mode"""
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"Error loading users from file: {e}")
    return []

def save_users_to_file(users):
    """Save users to JSON file for Datastore Mode"""
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
    except Exception as e:
        logger.error(f"Error saving users to file: {e}")

def get_cart_count(user_id):
    """Get the total number of items in the user's cart"""
    if not db:
        return 0
    try:
        cart_ref = db.collection('carts').document(user_id)
        cart_doc = cart_ref.get()
        if cart_doc.exists:
            cart_data = cart_doc.to_dict()
            items = cart_data.get('items', [])
            return sum(item.get('quantity', 0) for item in items)
    except Exception as e:
        logger.error(f"Error getting cart count for user {user_id}: {e}")
    return 0

def generate_reset_token():
    """Generate a secure password reset token"""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=32))

def send_password_reset_email(email, token):
    """Send password reset email via Gmail SMTP"""
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        # Email configuration
        smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        smtp_port = int(os.getenv('SMTP_PORT', 587))
        smtp_username = os.getenv('SMTP_USERNAME')
        smtp_password = os.getenv('SMTP_PASSWORD')
        from_email = os.getenv('FROM_EMAIL', smtp_username)
        from_name = os.getenv('FROM_NAME', 'Barman Store')

        if not smtp_username or not smtp_password:
            logger.warning("SMTP credentials not configured. Falling back to console output.")
            # Fallback to console output for demo
            reset_url = f"http://localhost:5000/reset_password/{token}"
            logger.info("=" * 50)
            logger.info(f"PASSWORD RESET LINK FOR: {email}")
            logger.info("=" * 50)
            logger.info(f"Direct Link: {reset_url}")
            logger.info("=" * 50)
            return True

        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = "Reset Your Barman Store Password"
        msg['From'] = f"{from_name} <{from_email}>"
        msg['To'] = email

        # HTML email content
        reset_url = f"http://localhost:5000/reset_password/{token}"
        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #007bff;">Reset Your Barman Store Password</h2>
                <p>You requested a password reset for your Barman Store account.</p>
                <p>Please click the button below to reset your password:</p>
                <p style="text-align: center; margin: 30px 0;">
                    <a href="{reset_url}" style="background-color: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">Reset Password</a>
                </p>
                <p><strong>Important:</strong> This link will expire in 1 hour for security reasons.</p>
                <p>If the button doesn't work, copy and paste this link into your browser:</p>
                <p style="word-break: break-all; background-color: #f8f9fa; padding: 10px; border-radius: 3px;">{reset_url}</p>
                <p>If you didn't request a password reset, please ignore this email.</p>
                <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                <p style="color: #666; font-size: 12px;">
                    Best regards,<br>
                    Barman Store Team
                </p>
            </div>
        </body>
        </html>
        """

        # Plain text fallback
        text = f"""
        Reset Your Barman Store Password

        You requested a password reset for your Barman Store account.

        Click the link below to reset your password:
        {reset_url}

        This link will expire in 1 hour.

        If you didn't request a password reset, please ignore this email.

        Best regards,
        Barman Store Team
        """

        # Attach parts
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
        msg.attach(part1)
        msg.attach(part2)

        # Send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Secure the connection
        server.login(smtp_username, smtp_password)
        server.sendmail(from_email, email, msg.as_string())
        server.quit()

        logger.info(f"Password reset email sent successfully to: {email}")
        return True

    except Exception as e:
        logger.error(f"Failed to send password reset email via SMTP: {str(e)}")
        logger.info("Falling back to console output...")

        # Fallback to console output
        reset_url = f"http://localhost:5000/reset_password/{token}"
        logger.info("=" * 50)
        logger.info(f"PASSWORD RESET LINK FOR: {email}")
        logger.info("=" * 50)
        logger.info(f"Direct Link: {reset_url}")
        logger.info("=" * 50)

        return False

def send_support_ticket_confirmation(user_email, ticket_id, subject):
    """Send support ticket confirmation email to user"""
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        # Email configuration
        smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        smtp_port = int(os.getenv('SMTP_PORT', 587))
        smtp_username = os.getenv('SMTP_USERNAME')
        smtp_password = os.getenv('SMTP_PASSWORD')
        from_email = os.getenv('FROM_EMAIL', smtp_username)
        from_name = os.getenv('FROM_NAME', 'Barman Store')

        if not smtp_username or not smtp_password:
            logger.warning("SMTP credentials not configured. Support confirmation email not sent.")
            return False

        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"Support Ticket Created - {ticket_id[:8].upper()}"
        msg['From'] = f"{from_name} <{from_email}>"
        msg['To'] = user_email

        # HTML email content
        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #28a745;">Support Ticket Created Successfully</h2>
                <p>Hello,</p>
                <p>Thank you for contacting Barman Store support. Your support ticket has been created successfully.</p>

                <div style="background-color: #f8f9fa; border-left: 4px solid #28a745; padding: 20px; margin: 20px 0;">
                    <h3>Ticket Details:</h3>
                    <p><strong>Ticket ID:</strong> {ticket_id[:8].upper()}</p>
                    <p><strong>Subject:</strong> {subject}</p>
                    <p><strong>Status:</strong> Open</p>
                    <p><strong>Created:</strong> {datetime.utcnow().strftime('%d/%m/%Y %H:%M UTC')}</p>
                </div>

                <p>Our support team will review your ticket and respond as soon as possible. You can check the status of your ticket by logging into your account and visiting the Support section.</p>

                <p>If you have any additional information to add to this ticket, please reply to this email or update it through your account.</p>

                <h3>Contact Information:</h3>
                <p><strong>Email:</strong> {{ os.environ.get('SUPPORT_EMAIL', 'support@barmanstore.com') }}</p>
                <p><strong>Phone:</strong> {{ os.environ.get('SUPPORT_PHONE', '+91-9876543210') }}</p>
                <p><strong>Business Hours:</strong> Monday to Saturday: 9:00 AM - 9:00 PM IST</p>

                <p>Best regards,<br>Barman Store Support Team</p>
            </div>
        </body>
        </html>
        """

        # Plain text fallback
        text = f"""
        Support Ticket Created Successfully

        Hello,

        Thank you for contacting Barman Store support. Your support ticket has been created successfully.

        Ticket Details:
        Ticket ID: {ticket_id[:8].upper()}
        Subject: {subject}
        Status: Open
        Created: {datetime.utcnow().strftime('%d/%m/%Y %H:%M UTC')}

        Our support team will review your ticket and respond as soon as possible.

        Contact Information:
        Email: support@barmanstore.com
        Phone: +91-XXXXXXXXXX
        Business Hours: Monday to Saturday: 9:00 AM - 9:00 PM IST

        Best regards,
        Barman Store Support Team
        """

        # Attach parts
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
        msg.attach(part1)
        msg.attach(part2)

        # Send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(from_email, user_email, msg.as_string())
        server.quit()

        logger.info(f"Support ticket confirmation email sent to: {user_email}")
        return True

    except Exception as e:
        logger.error(f"Failed to send support ticket confirmation email: {str(e)}")
        return False

def send_admin_support_notification(ticket_id, subject, category, priority, user_email):
    """Send notification email to admin about new support ticket"""
    try:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        # Email configuration
        smtp_server = os.getenv('SMTP_SERVER', 'smtp.gmail.com')
        smtp_port = int(os.getenv('SMTP_PORT', 587))
        smtp_username = os.getenv('SMTP_USERNAME')
        smtp_password = os.getenv('SMTP_PASSWORD')
        from_email = os.getenv('FROM_EMAIL', smtp_username)
        from_name = os.getenv('FROM_NAME', 'Barman Store')

        if not smtp_username or not smtp_password:
            logger.warning("SMTP credentials not configured. Admin notification email not sent.")
            return False

        # Send to admin email (you can configure this)
        admin_email = os.getenv('ADMIN_EMAIL', smtp_username)  # Default to same as from_email

        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = f"New Support Ticket - {ticket_id[:8].upper()}"
        msg['From'] = f"{from_name} <{from_email}>"
        msg['To'] = admin_email

        # HTML email content
        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #dc3545;">New Support Ticket Received</h2>
                <p>A new support ticket has been submitted and requires your attention.</p>

                <div style="background-color: #f8f9fa; border-left: 4px solid #dc3545; padding: 20px; margin: 20px 0;">
                    <h3>Ticket Details:</h3>
                    <p><strong>Ticket ID:</strong> {ticket_id[:8].upper()}</p>
                    <p><strong>Subject:</strong> {subject}</p>
                    <p><strong>Category:</strong> {category.title()}</p>
                    <p><strong>Priority:</strong> <span style="color: {'#dc3545' if priority == 'high' else '#ffc107' if priority == 'medium' else '#28a745'};">{priority.title()}</span></p>
                    <p><strong>User Email:</strong> {user_email}</p>
                    <p><strong>Created:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</p>
                </div>

                <p>Please log into the admin panel to view and respond to this support ticket.</p>

                <p style="text-align: center; margin: 30px 0;">
                    <a href="http://localhost:5000/admin/support/{ticket_id}" style="background-color: #dc3545; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;">View Ticket in Admin Panel</a>
                </p>

                <p>Best regards,<br>Barman Store System</p>
            </div>
        </body>
        </html>
        """

        # Plain text fallback
        text = f"""
        New Support Ticket Received

        A new support ticket has been submitted and requires your attention.

        Ticket Details:
        Ticket ID: {ticket_id[:8].upper()}
        Subject: {subject}
        Category: {category.title()}
        Priority: {priority.title()}
        User Email: {user_email}
        Created: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}

        Please log into the admin panel to view and respond to this support ticket.

        Best regards,
        Barman Store System
        """

        # Attach parts
        part1 = MIMEText(text, 'plain')
        part2 = MIMEText(html, 'html')
        msg.attach(part1)
        msg.attach(part2)

        # Send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(from_email, admin_email, msg.as_string())
        server.quit()

        logger.info(f"Admin support notification email sent to: {admin_email}")
        return True

    except Exception as e:
        logger.error(f"Failed to send admin support notification email: {str(e)}")
        return False

# Initialize Flask-Login with enhanced security
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'
login_manager.session_protection = 'strong'  # Enable session protection

# Additional security settings
app.config['SESSION_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection for cookies
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Session timeout

# Context processor to inject cart count and environment variables into all templates
@app.context_processor
def inject_cart_count():
    data = {'cart_count': 0}
    if current_user.is_authenticated:
        data['cart_count'] = get_cart_count(current_user.id)

    # Add environment variables for templates
    data['SUPPORT_EMAIL'] = os.environ.get('SUPPORT_EMAIL', 'support@barmanstore.com')
    data['SUPPORT_PHONE'] = os.environ.get('SUPPORT_PHONE', '+91-9876543210')
    data['ADMIN_EMAIL'] = os.environ.get('ADMIN_EMAIL', 'admin@barmanstore.com')
    data['BUSINESS_HOURS'] = os.environ.get('BUSINESS_HOURS', 'Monday to Saturday: 9:00 AM - 9:00 PM IST, Sunday: 10:00 AM - 6:00 PM IST')

    return data

# Initialize Firebase on app startup
initialize_firebase()


class User(UserMixin):
    def __init__(self, uid, email, role='customer', oauth_provider=None, oauth_id=None):
        self.id = uid
        self.email = email
        self.role = role
        self.oauth_provider = oauth_provider
        self.oauth_id = oauth_id

    def is_admin(self):
        return self.role == 'admin'

@login_manager.user_loader
def load_user(user_id):
    """
    Load user from Firestore or file-based storage.
    Returns User object or None if user not found.
    """
    # Load user from Firestore if available
    if db:
        try:
            user_doc = db.collection('users').document(user_id).get()
            if user_doc.exists:
                user_data = user_doc.to_dict()
                role = user_data.get('role', 'customer')
                email = user_data.get('email', '')
                oauth_provider = user_data.get('oauth_provider')
                oauth_id = user_data.get('oauth_id')
                return User(user_id, email, role, oauth_provider, oauth_id)
        except Exception as e:
            logger.error(f"Error loading user {user_id} from Firestore: {e}")

    # No fallback admin users - all users must be created through registration
    return User(user_id, None, 'customer')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/account', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def account():
    """
    Handle user login and registration.
    Rate limited to prevent brute force attacks.
    """
    if request.method == 'POST':
        if 'login' in request.form:
            # Handle login with input validation and sanitization
            email = bleach.clean(request.form.get('email', '').strip().lower())
            password = request.form.get('password', '')

            # Validate email format
            import re
            if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
                flash("Please enter a valid email address.", 'error')
                return render_template('account.html')

            # No hardcoded admin login - all users must be created through registration

            # For now, login directly from Firestore without Firebase Auth
            # This bypasses the API key issue
            if db:
                try:
                    # Find user by email in Firestore
                    users_ref = db.collection('users')
                    query = users_ref.where('email', '==', email).limit(1)
                    users = list(query.stream())

                    if users:
                        user_doc = users[0]
                        user_data = user_doc.to_dict()

                        # Check password with secure hashing
                        stored_password_hash = user_data.get('password_hash', '')
                        if stored_password_hash and check_password_hash(stored_password_hash, password):
                            user = User(user_doc.id, email, user_data.get('role', 'customer'))
                            login_user(user)
                            logger.info(f"User {email} logged in successfully")
                            flash("Login successful!", 'success')
                            return redirect(url_for('home'))
                        else:
                            logger.warning(f"Failed login attempt for email: {email}")
                            flash("Invalid email or password.", 'error')
                    else:
                        logger.warning(f"Login attempt for non-existent email: {email}")
                        flash("Invalid email or password.", 'error')
                except Exception as e:
                    logger.error(f"Login failed for {email}: {str(e)}")
                    flash("Login failed. Please try again.", 'error')
            else:
                flash("Database not available. Please configure Firebase credentials.", 'error')
        elif 'register' in request.form:
            # Handle registration with comprehensive validation and sanitization
            first_name = bleach.clean(request.form.get('first_name', '').strip())
            last_name = bleach.clean(request.form.get('last_name', '').strip())
            email = bleach.clean(request.form.get('email', '').strip().lower())
            phone = bleach.clean(request.form.get('phone', '').strip())
            address = bleach.clean(request.form.get('address', '').strip())
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')

            # Validate required fields
            if not all([first_name, last_name, email, phone, password]):
                flash("All fields are required.", 'error')
                return render_template('account.html')

            # Validate passwords match
            if password != confirm_password:
                flash("Passwords do not match.", 'error')
                return render_template('account.html')

            # Validate email format
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                flash("Please enter a valid email address.", 'error')
                return render_template('account.html')

            # Validate phone number format (basic validation for international numbers)
            phone_pattern = r'^\+?[1-9]\d{1,14}$'
            # Remove spaces, dashes, parentheses for validation
            clean_phone = re.sub(r'[\s\-\(\)]', '', phone)
            if not re.match(phone_pattern, clean_phone):
                flash("Please enter a valid phone number (e.g., +1234567890 or 1234567890).", 'error')
                return render_template('account.html')

            # Validate password strength (minimum 8 characters, mix of characters)
            if len(password) < 8:
                flash("Password must be at least 8 characters long.", 'error')
                return render_template('account.html')
            if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)', password):
                flash("Password must contain at least one uppercase letter, one lowercase letter, and one number.", 'error')
                return render_template('account.html')

            # Validate name lengths
            if len(first_name) < 2 or len(last_name) < 2:
                flash("First and last names must be at least 2 characters long.", 'error')
                return render_template('account.html')

            # For now, create user directly in Firestore without Firebase Auth
            # This bypasses the API key issue
            if db:
                try:
                    # Test Firestore connection first
                    test_ref = db.collection('test_connection').document('test')
                    test_ref.set({'test': True}, merge=True)
                    test_ref.delete()

                    # Check for duplicate email
                    email_query = db.collection('users').where('email', '==', email).limit(1)
                    existing_email = list(email_query.stream())
                    if existing_email:
                        flash("An account with this email already exists.", 'error')
                        return render_template('account.html')

                    # Check for duplicate phone
                    phone_query = db.collection('users').where('phone', '==', phone).limit(1)
                    existing_phone = list(phone_query.stream())
                    if existing_phone:
                        flash("An account with this phone number already exists.", 'error')
                        return render_template('account.html')

                    # Generate a simple user ID
                    import uuid
                    user_id = str(uuid.uuid4())

                    # Hash password for security
                    password_hash = generate_password_hash(password)

                    user_data = {
                        'first_name': first_name,
                        'last_name': last_name,
                        'email': email,
                        'phone': clean_phone,  # Store cleaned phone number
                        'address': address,
                        'role': 'customer',  # All new users start as customers
                        'created_at': firestore.SERVER_TIMESTAMP,
                        'password_hash': password_hash,  # Secure password storage
                        'account_status': 'active'  # Track account status
                    }

                    db.collection('users').document(user_id).set(user_data)

                    # Create user object and login
                    user = User(user_id, email, 'customer')
                    login_user(user)

                    logger.info(f"New user registered: {email}")
                    flash("Account created successfully! You can now start shopping.", 'success')

                    return redirect(url_for('home'))

                except Exception as e:
                    logger.error(f"Registration failed for {email}: {str(e)}")
                    flash("Registration failed. Please try again.", 'error')
            else:
                flash("Database not available. Please configure Firebase credentials.", 'error')
    return render_template('account.html')

# Keep the old routes for backward compatibility, but redirect to account
@app.route('/login')
def login():
    return redirect(url_for('account'))

@app.route('/register')
def register():
    return redirect(url_for('account'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

# OAuth Routes
@app.route('/login/google')
def login_google():
    # Use the configured redirect URI instead of url_for to ensure LAN access works
    redirect_uri = google_redirect_uri
    logger.info(f"Google OAuth redirect URI: {redirect_uri}")
    return google.authorize_redirect(redirect_uri)

@app.route('/login/facebook')
def login_facebook():
    # Use the configured redirect URI instead of url_for to ensure LAN access works
    redirect_uri = facebook_redirect_uri
    logger.info(f"Facebook OAuth redirect URI: {redirect_uri}")
    return facebook.authorize_redirect(redirect_uri)

@app.route('/authorize/google')
def authorize_google():
    try:
        # Log the callback for debugging mobile access
        logger.info(f"Google OAuth callback received from: {request.remote_addr}")
        logger.info(f"User-Agent: {request.headers.get('User-Agent', 'Unknown')}")

        token = google.authorize_access_token()
        resp = google.get('https://www.googleapis.com/oauth2/v2/userinfo')
        user_info = resp.json()

        # Check if user exists in Firestore
        if db:
            try:
                # Find user by OAuth ID
                users_ref = db.collection('users')
                query = users_ref.where('oauth_provider', '==', 'google').where('oauth_id', '==', user_info['id']).limit(1)
                users = list(query.stream())

                if users:
                    # User exists, log them in
                    user_doc = users[0]
                    user_data = user_doc.to_dict()
                    user = User(user_doc.id, user_data['email'], user_data.get('role', 'customer'), 'google', user_info['id'])
                    login_user(user)
                    logger.info(f"Google OAuth login successful for user: {user_info['email']} from {request.remote_addr}")
                    flash("Login successful!", 'success')
                    return redirect(url_for('home'))
                else:
                    # Create new user
                    import uuid
                    user_id = str(uuid.uuid4())

                    user_data = {
                        'first_name': user_info.get('given_name', ''),
                        'last_name': user_info.get('family_name', ''),
                        'email': user_info['email'],
                        'phone': '',
                        'address': '',
                        'role': 'customer',
                        'oauth_provider': 'google',
                        'oauth_id': user_info['id'],
                        'created_at': firestore.SERVER_TIMESTAMP,
                    }

                    db.collection('users').document(user_id).set(user_data)

                    user = User(user_id, user_info['email'], 'customer', 'google', user_info['id'])
                    login_user(user)
                    logger.info(f"Google OAuth account created for user: {user_info['email']} from {request.remote_addr}")
                    flash("Account created successfully! You can now start shopping.", 'success')
                    return redirect(url_for('home'))

            except Exception as e:
                logger.error(f"Google OAuth login failed: {str(e)}")
                flash(f"OAuth login failed: {str(e)}", 'error')
                return redirect(url_for('account'))
        else:
            flash("Database not available.", 'error')
            return redirect(url_for('account'))

    except Exception as e:
        logger.error(f"Google OAuth authorization failed: {str(e)}")
        flash(f"Google OAuth failed: {str(e)}", 'error')
        return redirect(url_for('account'))

@app.route('/authorize/facebook')
def authorize_facebook():
    try:
        token = facebook.authorize_access_token()
        resp = facebook.get('me?fields=id,name,email,first_name,last_name')
        user_info = resp.json()

        # Check if user exists in Firestore
        if db:
            try:
                # Find user by OAuth ID
                users_ref = db.collection('users')
                query = users_ref.where('oauth_provider', '==', 'facebook').where('oauth_id', '==', user_info['id']).limit(1)
                users = list(query.stream())

                if users:
                    # User exists, log them in
                    user_doc = users[0]
                    user_data = user_doc.to_dict()
                    user = User(user_doc.id, user_data['email'], user_data.get('role', 'customer'), 'facebook', user_info['id'])
                    login_user(user)
                    flash("Login successful!", 'success')
                    return redirect(url_for('home'))
                else:
                    # Create new user
                    import uuid
                    user_id = str(uuid.uuid4())

                    user_data = {
                        'first_name': user_info.get('first_name', ''),
                        'last_name': user_info.get('last_name', ''),
                        'email': user_info.get('email', ''),
                        'phone': '',
                        'address': '',
                        'role': 'customer',
                        'oauth_provider': 'facebook',
                        'oauth_id': user_info['id'],
                        'created_at': firestore.SERVER_TIMESTAMP,
                    }

                    db.collection('users').document(user_id).set(user_data)

                    user = User(user_id, user_info.get('email', ''), 'customer', 'facebook', user_info['id'])
                    login_user(user)
                    flash("Account created successfully! You can now start shopping.", 'success')
                    return redirect(url_for('home'))

            except Exception as e:
                flash(f"OAuth login failed: {str(e)}", 'error')
                return redirect(url_for('account'))
        else:
            flash("Database not available.", 'error')
            return redirect(url_for('account'))

    except Exception as e:
        flash(f"Facebook OAuth failed: {str(e)}", 'error')
        return redirect(url_for('account'))

@app.route('/products')
@login_required
def products():
    """
    Display all products for admin management.
    Requires admin privileges.
    """
    if not current_user.is_admin():
        logger.warning(f"Unauthorized access attempt to products page by user: {current_user.email}")
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    # Fetch all products
    products = []
    if db:
        try:
            products_ref = db.collection('products')
            products_docs = products_ref.stream()
            for product_doc in products_docs:
                product_data = product_doc.to_dict()
                product_data['id'] = product_doc.id
                products.append(product_data)
        except Exception as e:
            logger.error(f"Error fetching products: {e}")
            flash("Database temporarily unavailable. Some features may not work.", 'warning')

    return render_template('products.html', products=products)

@app.route('/admin')
@login_required
def admin():
    """
    Admin dashboard displaying all users and system management options.
    Requires admin privileges.
    """
    if not current_user.is_admin():
        logger.warning(f"Unauthorized access attempt to admin panel by user: {current_user.email}")
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    # Fetch all users
    users = []
    db_available = False

    if db:
        try:
            users_ref = db.collection('users')
            users_docs = users_ref.stream()
            for user_doc in users_docs:
                user_data = user_doc.to_dict()
                user_data['id'] = user_doc.id
                users.append(user_data)
            db_available = True
        except Exception as e:
            logger.error(f"Error fetching users from Firestore: {e}")
            if "Datastore Mode" in str(e):
                # Use file-based storage for Datastore Mode
                users = load_users_from_file()
                flash("Using file-based storage for Datastore Mode. User data will persist locally.", 'info')
            else:
                flash("Database temporarily unavailable. Some features may not work.", 'warning')

    # No longer add hardcoded admin users - they should be created through registration

    # For demo purposes, add some sample users if database is unavailable and no file users
    if not db_available and len(users) <= 1:  # Only admin or empty
        sample_users = [
            {
                'id': 'user1',
                'first_name': 'John',
                'last_name': 'Doe',
                'email': 'john.doe@example.com',
                'phone': '+1-555-0123',
                'role': 'customer',
                'created_at': None
            },
            {
                'id': 'user2',
                'first_name': 'Jane',
                'last_name': 'Smith',
                'email': 'jane.smith@example.com',
                'phone': '+1-555-0456',
                'role': 'customer',
                'created_at': None
            },
            {
                'id': 'user3',
                'first_name': 'Bob',
                'last_name': 'Johnson',
                'email': 'bob.johnson@example.com',
                'phone': '+1-555-0789',
                'role': 'admin',
                'created_at': None
            }
        ]
        users.extend(sample_users)
        # Save sample users to file for persistence
        save_users_to_file(users)

    return render_template('admin.html', users=users)

@app.route('/admin/edit_user/<user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        role = request.form['role']

        # All users can now be updated normally

        # Check if using file-based storage (Datastore Mode)
        if not db or (hasattr(db, '__str__') and "Datastore Mode" in str(db)) or (db and "Datastore Mode" in str(type(db))):
            # Update user in file-based storage
            users = load_users_from_file()
            for user in users:
                if user.get('id') == user_id:
                    user.update({
                        'first_name': first_name,
                        'last_name': last_name,
                        'email': email,
                        'phone': phone,
                        'address': address,
                        'role': role
                    })
                    save_users_to_file(users)
                    flash("User updated successfully.", 'success')
                    return redirect(url_for('admin'))
            flash("User not found.", 'error')
            return redirect(url_for('admin'))
        else:
            # Update user in Firestore
            try:
                user_data = {
                    'first_name': first_name,
                    'last_name': last_name,
                    'email': email,
                    'phone': phone,
                    'address': address,
                    'role': role,
                    'updated_at': firestore.SERVER_TIMESTAMP
                }
                db.collection('users').document(user_id).update(user_data)
                flash("User updated successfully.", 'success')
                return redirect(url_for('admin'))
            except Exception as e:
                flash(f"Error updating user: {str(e)}", 'error')

    # GET request: fetch user data
    # Handle admin users specially
    if user_id in ['admin', 'admin2']:
        admin_emails = {'admin': 'naren.barman@gmail.com', 'admin2': 'admin@admin.com'}
        admin_names = {'admin': 'System', 'admin2': 'Admin'}
        user_data = {
            'id': user_id,
            'first_name': admin_names[user_id],
            'last_name': 'Administrator',
            'email': admin_emails[user_id],
            'phone': 'N/A',
            'address': 'N/A',
            'role': 'admin'
        }
        return render_template('edit_user.html', user=user_data)

    # Check if using file-based storage (Datastore Mode)
    if not db or (hasattr(db, '__str__') and "Datastore Mode" in str(db)) or (db and "Datastore Mode" in str(type(db))):
        users = load_users_from_file()
        for user in users:
            if user.get('id') == user_id:
                return render_template('edit_user.html', user=user)
        flash("User not found.", 'error')
        return redirect(url_for('admin'))
    else:
        # Fetch from Firestore
        try:
            user_doc = db.collection('users').document(user_id).get()
            if user_doc.exists:
                user_data = user_doc.to_dict()
                user_data['id'] = user_id
                return render_template('edit_user.html', user=user_data)
        except Exception as e:
            flash(f"Error fetching user: {str(e)}", 'error')

    flash("User not found.", 'error')
    return redirect(url_for('admin'))

@app.route('/admin/delete_user/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    if user_id == current_user.id:
        flash("Cannot delete your own account.", 'error')
        return redirect(url_for('admin'))

    # Check if using file-based storage (Datastore Mode)
    if not db or (hasattr(db, '__str__') and "Datastore Mode" in str(db)) or (db and "Datastore Mode" in str(type(db))):
        # Delete user from file-based storage
        users = load_users_from_file()
        users = [user for user in users if user.get('id') != user_id]
        save_users_to_file(users)
        flash("User deleted successfully.", 'success')
    else:
        # Delete user from Firestore
        try:
            db.collection('users').document(user_id).delete()
            flash("User deleted successfully.", 'success')
        except Exception as e:
            flash(f"Error deleting user: {str(e)}", 'error')

    return redirect(url_for('admin'))

@app.route('/catalog')
@login_required
def catalog():
    # Fetch products from Firestore
    if db is None:
        flash("Database not available. Please configure Firebase credentials.", 'error')
        return redirect(url_for('home'))

    # Check Firestore connectivity
    try:
        # Test Firestore connection with a simple operation
        test_ref = db.collection('test_connection').document('test')
        test_ref.set({'test': True}, merge=True)
        test_ref.delete()
    except Exception as e:
        flash(f"Database connection issue: {str(e)}. Please check Firestore permissions in Firebase Console.", 'error')
        return redirect(url_for('home'))
    try:
        products_ref = db.collection('products')
        products = products_ref.stream()
        product_list = []
        for product in products:
            product_data = product.to_dict()
            product_data['id'] = product.id
            product_list.append(product_data)

        # Get user's cart items to highlight products already in cart
        cart_items = {}
        if db:
            try:
                cart_ref = db.collection('carts').document(current_user.id)
                cart_doc = cart_ref.get()
                if cart_doc.exists:
                    cart_data = cart_doc.to_dict()
                    items = cart_data.get('items', [])
                    for item in items:
                        cart_items[item['product_id']] = item['quantity']
            except Exception as e:
                logger.error(f'Error loading cart for catalog: {str(e)}')

        return render_template('catalog.html', products=product_list, cart_items=cart_items)
    except Exception as e:
        flash("Error fetching products.", 'error')
        return redirect(url_for('home'))

@app.route('/add_to_cart/<product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    quantity = int(request.form.get('quantity', 1))
    if quantity < 1:
        quantity = 1
    if db:
        try:
            cart_ref = db.collection('carts').document(current_user.id)
            cart_doc = cart_ref.get()
            if cart_doc.exists:
                cart_data = cart_doc.to_dict()
                items = cart_data.get('items', [])
            else:
                items = []
            # Check if product already in cart, if yes, increase quantity
            found = False
            for item in items:
                if item['product_id'] == product_id:
                    item['quantity'] += quantity
                    found = True
                    break
            if not found:
                # Add new item
                items.append({'product_id': product_id, 'quantity': quantity})
            cart_ref.set({'items': items, 'updated_at': firestore.SERVER_TIMESTAMP})
            flash('Product added to cart!', 'success')
        except Exception as e:
            flash(f'Error adding to cart: {str(e)}', 'error')
    else:
        flash('Database not available.', 'error')
    return redirect(url_for('catalog'))

@app.route('/cart')
@login_required
def cart():
    cart_items = []
    total = 0
    if db:
        try:
            cart_ref = db.collection('carts').document(current_user.id)
            cart_doc = cart_ref.get()
            if cart_doc.exists:
                cart_data = cart_doc.to_dict()
                items = cart_data.get('items', [])
                for item in items:
                    product_ref = db.collection('products').document(item['product_id'])
                    product_doc = product_ref.get()
                    if product_doc.exists:
                        product_data = product_doc.to_dict()
                        product_data['id'] = item['product_id']
                        product_data['quantity'] = item['quantity']
                        product_data['subtotal'] = product_data['price'] * item['quantity']
                        total += product_data['subtotal']
                        cart_items.append(product_data)
        except Exception as e:
            flash(f'Error loading cart: {str(e)}', 'error')
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    if not db:
        flash('Database not available.', 'error')
        return redirect(url_for('cart'))

    try:
        # Get cart items
        cart_ref = db.collection('carts').document(current_user.id)
        cart_doc = cart_ref.get()

        if not cart_doc.exists:
            flash('Your cart is empty.', 'error')
            return redirect(url_for('cart'))

        cart_data = cart_doc.to_dict()
        items = cart_data.get('items', [])

        if not items:
            flash('Your cart is empty.', 'error')
            return redirect(url_for('cart'))

        # Build order items with product details
        order_items = []
        total_amount = 0

        for item in items:
            product_ref = db.collection('products').document(item['product_id'])
            product_doc = product_ref.get()

            if product_doc.exists:
                product_data = product_doc.to_dict()
                item_total = product_data['price'] * item['quantity']
                total_amount += item_total

                order_items.append({
                    'product_id': item['product_id'],
                    'name': product_data.get('name', 'Unknown Product'),
                    'description': product_data.get('description', ''),
                    'price': product_data['price'],
                    'quantity': item['quantity'],
                    'subtotal': item_total,
                    'image_url': product_data.get('image_url', '')
                })

        # Get user information
        user_ref = db.collection('users').document(current_user.id)
        user_doc = user_ref.get()
        user_data = user_doc.to_dict() if user_doc.exists else {}

        # Create order data
        import uuid
        order_id = str(uuid.uuid4())

        order_data = {
            'order_id': order_id,
            'user_id': current_user.id,
            'user_email': current_user.email,
            'user_name': f"{user_data.get('first_name', '')} {user_data.get('last_name', '')}".strip(),
            'user_phone': user_data.get('phone', ''),
            'user_address': user_data.get('address', ''),
            'items': order_items,
            'total_amount': total_amount,
            'status': 'pending',  # pending, processed, waiting_for_payment, bill_generated, delivered, closed
            'order_date': firestore.SERVER_TIMESTAMP,
            'updated_at': firestore.SERVER_TIMESTAMP
        }

        # Save order to database
        db.collection('orders').document(order_id).set(order_data)

        # Clear the cart
        cart_ref.set({'items': [], 'updated_at': firestore.SERVER_TIMESTAMP})

        flash(f'Order placed successfully! Your order ID is {order_id[:8].upper()}. Thank you for shopping with us.', 'success')

    except Exception as e:
        flash(f'Error processing checkout: {str(e)}', 'error')
        return redirect(url_for('cart'))

    return redirect(url_for('catalog'))

@app.route('/update_cart_quantity/<product_id>', methods=['POST'])
@login_required
def update_cart_quantity(product_id):
    quantity = int(request.form.get('quantity', 1))
    if quantity < 1:
        quantity = 1
    if db:
        try:
            cart_ref = db.collection('carts').document(current_user.id)
            cart_doc = cart_ref.get()
            if cart_doc.exists:
                cart_data = cart_doc.to_dict()
                items = cart_data.get('items', [])
                for item in items:
                    if item['product_id'] == product_id:
                        item['quantity'] = quantity
                        break
                cart_ref.set({'items': items, 'updated_at': firestore.SERVER_TIMESTAMP})
                flash('Cart updated!', 'success')
        except Exception as e:
            flash(f'Error updating cart: {str(e)}', 'error')
    return redirect(url_for('cart'))

@app.route('/remove_from_cart/<product_id>', methods=['POST'])
@login_required
def remove_from_cart(product_id):
    if db:
        try:
            cart_ref = db.collection('carts').document(current_user.id)
            cart_doc = cart_ref.get()
            if cart_doc.exists:
                cart_data = cart_doc.to_dict()
                items = cart_data.get('items', [])
                items = [item for item in items if item['product_id'] != product_id]
                cart_ref.set({'items': items, 'updated_at': firestore.SERVER_TIMESTAMP})
                flash('Product removed from cart!', 'success')
        except Exception as e:
            flash(f'Error removing from cart: {str(e)}', 'error')
    return redirect(url_for('cart'))

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        category = request.form['category']
        brand = request.form.get('brand', '')
        weight = request.form.get('weight', '')
        hsn = request.form.get('hsn', '')
        price = float(request.form['price'])
        stock_quantity = int(request.form.get('stock_quantity', 0))
        sku = request.form.get('sku', '')
        image_url = request.form.get('image_url', '')
        tags = request.form.get('tags', '')

        # Add product to Firestore
        if db:
            try:
                product_data = {
                    'name': name,
                    'description': description,
                    'category': category,
                    'brand': brand,
                    'weight': weight,
                    'hsn': hsn,
                    'price': price,
                    'stock_quantity': stock_quantity,
                    'sku': sku,
                    'image_url': image_url,
                    'tags': tags,
                    'created_at': firestore.SERVER_TIMESTAMP,
                    'updated_at': firestore.SERVER_TIMESTAMP
                }
                db.collection('products').add(product_data)
                flash('Product added successfully!', 'success')
                return redirect(url_for('products'))
            except Exception as e:
                flash(f'Error adding product: {str(e)}', 'error')
        else:
            flash('Database not available.', 'error')
    return render_template('add_product.html')

@app.route('/edit_product/<product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        category = request.form['category']
        brand = request.form.get('brand', '')
        weight = request.form.get('weight', '')
        hsn = request.form.get('hsn', '')
        dimensions = request.form.get('dimensions', '')
        price = float(request.form['price'])
        stock_quantity = int(request.form.get('stock_quantity', 0))
        sku = request.form.get('sku', '')
        image_url = request.form.get('image_url', '')
        tags = request.form.get('tags', '')

        # Update product in Firestore
        if db:
            try:
                product_ref = db.collection('products').document(product_id)
                product_ref.update({
                    'name': name,
                    'description': description,
                    'category': category,
                    'brand': brand,
                    'weight': weight,
                    'hsn': hsn,
                    'dimensions': dimensions,
                    'price': price,
                    'stock_quantity': stock_quantity,
                    'sku': sku,
                    'image_url': image_url,
                    'tags': tags,
                    'updated_at': firestore.SERVER_TIMESTAMP
                })
                flash('Product updated successfully!', 'success')
                return redirect(url_for('products'))
            except Exception as e:
                flash(f'Error updating product: {str(e)}', 'error')
        else:
            flash('Database not available.', 'error')
        return redirect(url_for('products'))

    # GET request: fetch product data
    if db:
        try:
            product_ref = db.collection('products').document(product_id)
            product = product_ref.get()
            if product.exists:
                product_data = product.to_dict()
                product_data['id'] = product.id
                return render_template('edit_product.html', product=product_data)
        except Exception as e:
            flash(f'Error fetching product: {str(e)}', 'error')
    else:
        flash('Database not available.', 'error')

    flash('Product not found.', 'error')
    return redirect(url_for('products'))

@app.route('/delete_product/<product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    if db:
        try:
            product_ref = db.collection('products').document(product_id)
            product_ref.delete()
            flash('Product deleted successfully!', 'success')
        except Exception as e:
            flash(f'Error deleting product: {str(e)}', 'error')
    else:
        flash('Database not available.', 'error')

    return redirect(url_for('products'))

@app.route('/purchase_register', methods=['GET', 'POST'])
@login_required
def purchase_register():
    """
    Display purchase register with filtering and reporting capabilities.
    Requires admin privileges.
    """
    if not current_user.is_admin():
        logger.warning(f"Unauthorized access attempt to purchase register by user: {current_user.email}")
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    # Get filter parameters
    supplier_filter = request.args.get('supplier', '').strip()
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    sort_by = request.args.get('sort_by', 'created_at')
    sort_order = request.args.get('sort_order', 'desc')

    # Fetch all purchase bills
    purchase_bills = []
    total_amount = 0
    total_gst = 0
    total_grand_total = 0
    total_balance = 0

    if db:
        try:
            purchases_ref = db.collection('purchase_bills')

            # Apply filters
            if supplier_filter:
                purchases_ref = purchases_ref.where('supplier_name', '>=', supplier_filter).where('supplier_name', '<=', supplier_filter + '\uf8ff')

            purchases_docs = purchases_ref.stream()

            for purchase_doc in purchases_docs:
                purchase_data = purchase_doc.to_dict()
                purchase_data['id'] = purchase_doc.id

                # Apply date filters
                if date_from or date_to:
                    purchase_date = purchase_data.get('purchase_date', '')
                    if purchase_date:
                        try:
                            # Convert date string to comparable format
                            if isinstance(purchase_date, str):
                                from datetime import datetime
                                purchase_datetime = datetime.strptime(purchase_date, '%Y-%m-%d')
                            else:
                                purchase_datetime = purchase_date

                            if date_from:
                                from_date = datetime.strptime(date_from, '%Y-%m-%d')
                                if purchase_datetime.date() < from_date.date():
                                    continue

                            if date_to:
                                to_date = datetime.strptime(date_to, '%Y-%m-%d')
                                if purchase_datetime.date() > to_date.date():
                                    continue
                        except (ValueError, AttributeError):
                            pass  # Skip date filtering if date format is invalid

                purchase_bills.append(purchase_data)

                # Calculate totals
                total_amount += purchase_data.get('total_amount', 0)
                total_gst += purchase_data.get('total_gst', 0)
                total_grand_total += purchase_data.get('grand_total', 0)
                total_balance += purchase_data.get('balance', 0)

        except Exception as e:
            logger.error(f"Error fetching purchase bills: {e}")
            flash("Database temporarily unavailable. Some features may not work.", 'warning')

    # Sort the results
    if sort_by == 'supplier_name':
        purchase_bills.sort(key=lambda x: x.get('supplier_name', '').lower(), reverse=(sort_order == 'desc'))
    elif sort_by == 'purchase_date':
        purchase_bills.sort(key=lambda x: x.get('purchase_date', ''), reverse=(sort_order == 'desc'))
    elif sort_by == 'grand_total':
        purchase_bills.sort(key=lambda x: x.get('grand_total', 0), reverse=(sort_order == 'desc'))
    else:  # created_at (default)
        purchase_bills.sort(key=lambda x: x.get('created_at'), reverse=(sort_order == 'desc'))

    # Get unique suppliers for filter dropdown
    suppliers = set()
    for bill in purchase_bills:
        if bill.get('supplier_name'):
            suppliers.add(bill['supplier_name'])
    suppliers = sorted(list(suppliers))

    return render_template('purchase_register.html',
                         purchase_bills=purchase_bills,
                         suppliers=suppliers,
                         total_amount=total_amount,
                         total_gst=total_gst,
                         total_grand_total=total_grand_total,
                         total_balance=total_balance,
                         filters={
                             'supplier': supplier_filter,
                             'date_from': date_from,
                             'date_to': date_to,
                             'sort_by': sort_by,
                             'sort_order': sort_order
                         })

@app.route('/add_purchase', methods=['GET', 'POST'])
@login_required
def add_purchase():
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    # Fetch available products for dropdown
    products = []
    if db:
        try:
            products_ref = db.collection('products')
            products_docs = products_ref.stream()
            for product_doc in products_docs:
                product_data = product_doc.to_dict()
                product_data['id'] = product_doc.id
                products.append(product_data)
        except Exception as e:
            logger.error(f"Error fetching products: {e}")

    # Fetch available suppliers for dropdown
    suppliers = []
    if db:
        try:
            # Get unique suppliers from existing purchase bills
            suppliers_ref = db.collection('purchase_bills')
            suppliers_docs = suppliers_ref.stream()
            supplier_names = set()
            for supplier_doc in suppliers_docs:
                supplier_data = supplier_doc.to_dict()
                supplier_name = supplier_data.get('supplier_name', '').strip()
                if supplier_name:
                    supplier_names.add(supplier_name)
            suppliers = sorted(list(supplier_names))
        except Exception as e:
            logger.error(f"Error fetching suppliers: {e}")

    if request.method == 'POST':
        supplier_name = request.form.get('supplier_name', '').strip()
        bill_number = request.form.get('bill_number', '')
        purchase_date = request.form['purchase_date']
        payment_made = float(request.form.get('payment_made', 0))
        notes = request.form.get('notes', '')

        # Process multiple products with fully editable fields
        products_data = []
        total_amount = 0
        total_gst = 0

        # Get all product entries - now using combined product name/SKU field
        product_name_skus = request.form.getlist('product_name_sku[]')
        quantities = request.form.getlist('quantity[]')
        units = request.form.getlist('unit[]')
        rates = request.form.getlist('rate[]')
        mrps = request.form.getlist('mrp[]')
        discount_percents = request.form.getlist('discount_percent[]')
        gst_rates = request.form.getlist('gst_rate[]')

        for i in range(len(product_name_skus)):
            if product_name_skus[i] and quantities[i] and rates[i] and mrps[i]:
                # Sanitize input data
                product_name_sku = bleach.clean(product_name_skus[i].strip())

                # Parse product name and SKU from combined field
                # Format: "Product Name (SKU)" or just "Product Name"
                if '(' in product_name_sku and product_name_sku.endswith(')'):
                    # Has SKU
                    parts = product_name_sku.rsplit(' (', 1)
                    product_name = parts[0].strip()
                    product_sku = parts[1].rstrip(')').strip()
                else:
                    # No SKU
                    product_name = product_name_sku
                    product_sku = ""

                quantity = int(quantities[i])
                unit = bleach.clean(units[i].strip()) if units[i] else ""
                rate = float(rates[i])
                mrp = float(mrps[i])
                discount_percent = float(discount_percents[i]) if discount_percents[i] else 0
                gst_rate = float(gst_rates[i]) if gst_rates[i] else 0

                # Validate input ranges
                if quantity <= 0 or rate < 0 or mrp < 0 or discount_percent < 0 or gst_rate < 0:
                    flash("Invalid product data. Please check quantities and prices.", 'error')
                    return render_template('add_purchase.html', products=products, suppliers=suppliers)

                subtotal = quantity * rate
                discount_amount = subtotal * (discount_percent / 100)
                taxable_amount = subtotal - discount_amount
                gst_amount = taxable_amount * (gst_rate / 100)
                total_with_gst = taxable_amount + gst_amount

                product_data = {
                    'product_id': f"custom_{i+1}",  # Generate custom ID for non-catalog products
                    'product_name': product_name,
                    'product_sku': product_sku,
                    'unit': unit,
                    'mrp': mrp,
                    'quantity': quantity,
                    'rate': rate,
                    'discount_percent': discount_percent,
                    'discount_amount': discount_amount,
                    'taxable_amount': taxable_amount,
                    'gst_rate': gst_rate,
                    'gst_amount': gst_amount,
                    'total_with_gst': total_with_gst
                }
                products_data.append(product_data)
                total_amount += taxable_amount
                total_gst += gst_amount

                # Note: MRP update logic removed since we're now using fully editable product entries
                # Products can be entered manually without being tied to the catalog

        grand_total = total_amount + total_gst
        balance = grand_total - payment_made

        # Add purchase bill to Firestore
        if db:
            try:
                purchase_data = {
                    'supplier_name': supplier_name,
                    'bill_number': bill_number,
                    'purchase_date': purchase_date,
                    'products': products_data,
                    'total_amount': total_amount,
                    'total_gst': total_gst,
                    'grand_total': grand_total,
                    'payment_made': payment_made,
                    'balance': balance,
                    'notes': notes,
                    'created_at': firestore.SERVER_TIMESTAMP,
                    'created_by': current_user.email
                }
                # Auto-add new products to inventory
                new_products_added = []
                for product_data_item in products_data:
                    product_name = product_data_item['product_name']
                    product_sku = product_data_item['product_sku']

                    # Check if product already exists in catalog
                    existing_product = None
                    try:
                        # Check by name first
                        products_ref = db.collection('products')
                        name_query = products_ref.where('name', '==', product_name).limit(1)
                        existing_docs = list(name_query.stream())

                        if existing_docs:
                            existing_product = existing_docs[0]
                        elif product_sku:
                            # Check by SKU if name doesn't match
                            sku_query = products_ref.where('sku', '==', product_sku).limit(1)
                            existing_docs = list(sku_query.stream())
                            if existing_docs:
                                existing_product = existing_docs[0]

                        # If product doesn't exist, create it
                        if not existing_product:
                            # Try to find HSN code from existing products with similar names
                            suggested_hsn = ''
                            try:
                                # Search for products with similar names to suggest HSN
                                similar_products_ref = db.collection('products')
                                similar_products = similar_products_ref.stream()

                                for similar_product in similar_products:
                                    similar_data = similar_product.to_dict()
                                    similar_name = similar_data.get('name', '').lower()
                                    current_name = product_name.lower()

                                    # Check for partial name matches (at least 3 words in common or 70% similarity)
                                    current_words = set(current_name.split())
                                    similar_words = set(similar_name.split())

                                    if len(current_words.intersection(similar_words)) >= 2 or \
                                       (len(current_words) > 0 and len(current_words.intersection(similar_words)) / len(current_words) > 0.7):
                                        if similar_data.get('hsn'):
                                            suggested_hsn = similar_data['hsn']
                                            logger.info(f"Suggested HSN {suggested_hsn} for new product '{product_name}' based on similar product '{similar_data['name']}'")
                                            break
                            except Exception as e:
                                logger.error(f"Error finding similar products for HSN suggestion: {str(e)}")

                            new_product_data = {
                                'name': product_name,
                                'sku': product_sku,
                                'description': f'Added from purchase bill - {supplier_name}',
                                'category': 'General',  # Default category
                                'brand': '',
                                'weight': '',
                                'hsn': suggested_hsn,  # Auto-suggested HSN code
                                'price': product_data_item['rate'],  # Use purchase rate as selling price
                                'stock_quantity': product_data_item['quantity'],  # Add purchased quantity to stock
                                'image_url': '',
                                'tags': '',
                                'created_at': firestore.SERVER_TIMESTAMP,
                                'updated_at': firestore.SERVER_TIMESTAMP
                            }

                            # Add unit information if available
                            if product_data_item.get('unit'):
                                new_product_data['unit'] = product_data_item['unit']

                            db.collection('products').add(new_product_data)
                            new_products_added.append(product_name)
                            logger.info(f"Auto-added new product to inventory: {product_name}")
                        else:
                            # Update existing product stock
                            existing_data = existing_product.to_dict()
                            current_stock = existing_data.get('stock_quantity', 0)
                            new_stock = current_stock + product_data_item['quantity']

                            db.collection('products').document(existing_product.id).update({
                                'stock_quantity': new_stock,
                                'updated_at': firestore.SERVER_TIMESTAMP
                            })
                            logger.info(f"Updated stock for existing product: {product_name} (new stock: {new_stock})")

                    except Exception as e:
                        logger.error(f"Error auto-adding product {product_name}: {str(e)}")
                        # Continue with purchase bill creation even if product addition fails

                db.collection('purchase_bills').add(purchase_data)

                flash('Purchase bill added successfully!', 'success')
                return redirect(url_for('purchase_register'))
            except Exception as e:
                flash(f'Error adding purchase bill: {str(e)}', 'error')
        else:
            flash('Database not available.', 'error')
    return render_template('add_purchase.html', products=products, suppliers=suppliers)

@app.route('/delete_purchase/<purchase_id>', methods=['POST'])
@login_required
def delete_purchase(purchase_id):
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    if db:
        try:
            purchase_ref = db.collection('purchase_bills').document(purchase_id)
            purchase_ref.delete()
            flash('Purchase bill deleted successfully!', 'success')
        except Exception as e:
            flash(f'Error deleting purchase bill: {str(e)}', 'error')
    else:
        flash('Database not available.', 'error')

    return redirect(url_for('purchase_register'))

@app.route('/add_payment/<purchase_id>', methods=['GET', 'POST'])
@login_required
def add_payment(purchase_id):
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    # Fetch purchase bill details
    purchase_bill = None
    if db:
        try:
            purchase_ref = db.collection('purchase_bills').document(purchase_id)
            purchase_doc = purchase_ref.get()
            if purchase_doc.exists:
                purchase_bill = purchase_doc.to_dict()
                purchase_bill['id'] = purchase_id
        except Exception as e:
            logger.error(f"Error fetching purchase bill: {str(e)}")
            flash("Error loading purchase bill.", 'error')
            return redirect(url_for('purchase_register'))

    if not purchase_bill:
        flash("Purchase bill not found.", 'error')
        return redirect(url_for('purchase_register'))

    if request.method == 'POST':
        payment_amount = float(request.form.get('payment_amount', 0))
        payment_date = request.form.get('payment_date')
        payment_method = request.form.get('payment_method', 'cash')
        notes = request.form.get('notes', '')

        # Validate payment amount
        if payment_amount <= 0:
            flash("Payment amount must be greater than zero.", 'error')
            return render_template('add_payment.html', purchase_bill=purchase_bill)

        if payment_amount > purchase_bill.get('balance', 0):
            flash("Payment amount cannot exceed outstanding balance.", 'error')
            return render_template('add_payment.html', purchase_bill=purchase_bill)

        if db:
            try:
                # Add payment record
                payment_data = {
                    'purchase_bill_id': purchase_id,
                    'payment_amount': payment_amount,
                    'payment_date': payment_date,
                    'payment_method': payment_method,
                    'notes': notes,
                    'created_at': firestore.SERVER_TIMESTAMP,
                    'created_by': current_user.email
                }
                db.collection('purchase_payments').add(payment_data)

                # Update purchase bill balance
                new_balance = purchase_bill['balance'] - payment_amount
                new_payment_made = purchase_bill['payment_made'] + payment_amount

                purchase_ref.update({
                    'balance': new_balance,
                    'payment_made': new_payment_made,
                    'updated_at': firestore.SERVER_TIMESTAMP
                })

                flash(f'Payment of ₹{payment_amount:.2f} added successfully!', 'success')
                return redirect(url_for('view_purchase_payments', purchase_id=purchase_id))

            except Exception as e:
                logger.error(f"Error adding payment: {str(e)}")
                flash(f'Error adding payment: {str(e)}', 'error')
        else:
            flash('Database not available.', 'error')

    return render_template('add_payment.html', purchase_bill=purchase_bill)

@app.route('/view_purchase_payments/<purchase_id>')
@login_required
def view_purchase_payments(purchase_id):
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    # Fetch purchase bill details
    purchase_bill = None
    payments = []

    if db:
        try:
            # Fetch purchase bill
            purchase_ref = db.collection('purchase_bills').document(purchase_id)
            purchase_doc = purchase_ref.get()
            if purchase_doc.exists:
                purchase_bill = purchase_doc.to_dict()
                purchase_bill['id'] = purchase_id

                # Fetch payments for this bill
                payments_ref = db.collection('purchase_payments').where('purchase_bill_id', '==', purchase_id)
                payments_docs = payments_ref.stream()

                for payment_doc in payments_docs:
                    payment_data = payment_doc.to_dict()
                    payment_data['id'] = payment_doc.id
                    payments.append(payment_data)
        except Exception as e:
            logger.error(f"Error fetching purchase bill and payments: {str(e)}")
            flash("Error loading data.", 'error')
            return redirect(url_for('purchase_register'))

    if not purchase_bill:
        flash("Purchase bill not found.", 'error')
        return redirect(url_for('purchase_register'))

    return render_template('view_purchase_payments.html', purchase_bill=purchase_bill, payments=payments)

@app.route('/view_orders')
@login_required
def view_orders():
    orders = []

    if db:
        try:
            # Fetch orders for the current user (or all orders if admin)
            if current_user.is_admin():
                # Admin can see all orders
                orders_ref = db.collection('orders')
                orders_docs = orders_ref.stream()
            else:
                # Regular users can only see their own orders
                orders_ref = db.collection('orders').where('user_id', '==', current_user.id)
                orders_docs = orders_ref.stream()

            for order_doc in orders_docs:
                order_data = order_doc.to_dict()
                order_data['id'] = order_doc.id

                # Format order date
                if order_data.get('order_date'):
                    if hasattr(order_data['order_date'], 'strftime'):
                        order_data['date'] = order_data['order_date'].strftime('%Y-%m-%d %H:%M')
                    else:
                        order_data['date'] = str(order_data['order_date'])
                else:
                    order_data['date'] = 'N/A'

                orders.append(order_data)

            # Sort orders by date (newest first) since we can't use order_by in query
            orders.sort(key=lambda x: x.get('order_date') or '', reverse=True)

        except Exception as e:
            logger.error(f"Error fetching orders: {str(e)}")
            flash("Error loading orders. Please try again.", 'error')

    return render_template('view_orders.html', orders=orders)




@app.route('/api/units')
@login_required
def get_units():
    """API endpoint to get all unique units used in purchase bills"""
    units = set()
    if db:
        try:
            purchases_ref = db.collection('purchase_bills')
            purchases_docs = purchases_ref.stream()

            for purchase_doc in purchases_docs:
                purchase_data = purchase_doc.to_dict()
                products = purchase_data.get('products', [])
                for product in products:
                    unit = product.get('unit', '').strip()
                    if unit:
                        units.add(unit)
        except Exception as e:
            logger.error(f"Error fetching units: {e}")

    return {'units': list(units)}

@app.route('/api/search_hsn/<hsn_code>')
@login_required
def search_hsn(hsn_code):
    """API endpoint to search for products by HSN code"""
    if db:
        try:
            products_ref = db.collection('products').where('hsn', '==', hsn_code).limit(1)
            products = list(products_ref.stream())

            if products:
                product_data = products[0].to_dict()
                product_data['id'] = products[0].id
                return {'product': product_data}
        except Exception as e:
            logger.error(f"Error searching HSN: {e}")

    return {'product': None}

@app.route('/api/search_product')
@login_required
def search_product():
    """API endpoint to search for HSN codes by product details"""
    name = request.args.get('name', '').strip()
    brand = request.args.get('brand', '').strip()
    category = request.args.get('category', '').strip()

    if not name:
        return {'hsn': None}

    if db:
        try:
            # Search for products with similar names
            products_ref = db.collection('products')
            products = products_ref.stream()

            for product in products:
                product_data = product.to_dict()
                product_name = product_data.get('name', '').lower()
                product_brand = product_data.get('brand', '').lower()
                product_category = product_data.get('category', '').lower()

                # Check similarity
                name_match = name.lower() in product_name or product_name in name.lower()
                brand_match = not brand or brand.lower() in product_brand
                category_match = not category or category.lower() == product_category

                if name_match and brand_match and category_match and product_data.get('hsn'):
                    return {'hsn': product_data['hsn']}

        except Exception as e:
            logger.error(f"Error searching product: {e}")

    return {'hsn': None}

@app.route('/api/hsn_codes')
@login_required
def get_hsn_codes():
    """API endpoint to get all unique HSN codes"""
    hsn_codes = set()
    if db:
        try:
            products_ref = db.collection('products')
            products = products_ref.stream()

            for product in products:
                product_data = product.to_dict()
                hsn = product_data.get('hsn', '').strip()
                if hsn:
                    hsn_codes.add(hsn)
        except Exception as e:
            logger.error(f"Error fetching HSN codes: {e}")

    return {'hsn_codes': sorted(list(hsn_codes))}


@app.route('/api/customer/<customer_id>/transactions')
@login_required
def get_customer_transactions(customer_id):
    """API endpoint to get transactions for a customer"""
    if not current_user.is_admin():
        return {'success': False, 'error': 'Admin access required'}, 403

    transactions = []
    if db:
        try:
            orders_ref = db.collection('orders').where('user_id', '==', customer_id)
            orders_docs = orders_ref.stream()

            for order_doc in orders_docs:
                order_data = order_doc.to_dict()
                order_data['id'] = order_doc.id

                transactions.append({
                    'date': order_data.get('order_date'),
                    'description': f"Order {order_data['id'][:8].upper()}",
                    'amount': order_data.get('total_amount', 0),
                    'status': order_data.get('status', 'pending')
                })

            # Sort transactions by date
            transactions.sort(key=lambda x: x.get('date') or '', reverse=False)

        except Exception as e:
            logger.error(f"Error fetching customer transactions: {e}")

    return {'success': True, 'data': transactions}



@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/help')
def help():
    return render_template('help.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def forgot_password():
    """
    Handle password reset requests with rate limiting.
    Limited to 3 requests per hour to prevent abuse.
    """
    if request.method == 'POST':
        email = bleach.clean(request.form.get('email', '').strip().lower())

        if db:
            try:
                # Check if user exists
                users_ref = db.collection('users').where('email', '==', email).limit(1)
                users = list(users_ref.stream())

                if users:
                    user_doc = users[0]
                    reset_token = generate_reset_token()

                    # Store reset token with expiry (1 hour from now)
                    expiry_time = datetime.utcnow() + timedelta(hours=1)

                    db.collection('users').document(user_doc.id).update({
                        'password_reset_token': reset_token,
                        'password_reset_expiry': expiry_time,
                        'updated_at': firestore.SERVER_TIMESTAMP
                    })

                    send_password_reset_email(email, reset_token)
                    flash("Password reset link sent to your email. Please check your inbox.", 'success')
                else:
                    # Don't reveal if email exists or not for security
                    flash("If an account with this email exists, a password reset link has been sent.", 'info')

                return redirect(url_for('account'))
            except Exception as e:
                flash(f"Error sending reset email: {str(e)}", 'error')
        else:
            flash("Database not available.", 'error')

    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def reset_password(token):
    """
    Handle password reset with token validation.
    Rate limited to prevent brute force attacks.
    """
    if request.method == 'POST':
        new_password = bleach.clean(request.form.get('password', ''))
        confirm_password = bleach.clean(request.form.get('confirm_password', ''))

        # Validate passwords match
        if new_password != confirm_password:
            flash("Passwords do not match.", 'error')
            return render_template('reset_password.html', token=token)

        # Validate password strength (enhanced)
        if len(new_password) < 8:
            flash("Password must be at least 8 characters long.", 'error')
            return render_template('reset_password.html', token=token)
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)', new_password):
            flash("Password must contain at least one uppercase letter, one lowercase letter, and one number.", 'error')
            return render_template('reset_password.html', token=token)

        if db:
            try:
                # Find user with this reset token
                users_ref = db.collection('users').where('password_reset_token', '==', token).limit(1)
                users = list(users_ref.stream())

                if users:
                    user_doc = users[0]
                    user_data = user_doc.to_dict()

                    # Check if token is expired
                    expiry = user_data.get('password_reset_expiry')
                    if expiry:
                        # Handle both datetime objects and Firestore timestamps
                        if hasattr(expiry, 'replace'):  # datetime object with tzinfo
                            current_time = datetime.utcnow().replace(tzinfo=None)
                            expiry_time = expiry.replace(tzinfo=None) if hasattr(expiry, 'tzinfo') and expiry.tzinfo else expiry
                        else:  # Firestore timestamp
                            current_time = datetime.utcnow()
                            expiry_time = expiry

                        if current_time > expiry_time:
                            flash("Password reset link has expired.", 'error')
                            return redirect(url_for('forgot_password'))

                    # Update password with secure hashing and clear reset token
                    hashed_password = generate_password_hash(new_password)
                    db.collection('users').document(user_doc.id).update({
                        'password_hash': hashed_password,
                        'password_reset_token': None,
                        'password_reset_expiry': None,
                        'updated_at': firestore.SERVER_TIMESTAMP
                    })

                    flash("Password reset successfully! You can now log in with your new password.", 'success')
                    return redirect(url_for('account'))
                else:
                    flash("Invalid or expired reset link.", 'error')
            except Exception as e:
                flash(f"Error resetting password: {str(e)}", 'error')
        else:
            flash("Database not available.", 'error')

    return render_template('reset_password.html', token=token)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """
    Allow users to edit their profile information.
    Includes input validation and sanitization.
    """
    if request.method == 'POST':
        first_name = bleach.clean(request.form.get('first_name', '').strip())
        last_name = bleach.clean(request.form.get('last_name', '').strip())
        phone = bleach.clean(request.form.get('phone', '').strip())
        address = bleach.clean(request.form.get('address', '').strip())

        # Validate phone number format
        import re
        phone_pattern = r'^\+?[1-9]\d{1,14}$'
        clean_phone = re.sub(r'[\s\-\(\)]', '', phone)
        if not re.match(phone_pattern, clean_phone):
            flash("Please enter a valid phone number (e.g., +1234567890 or 1234567890).", 'error')
            return render_template('edit_profile.html')

        if db:
            try:
                user_ref = db.collection('users').document(current_user.id)
                user_ref.update({
                    'first_name': first_name,
                    'last_name': last_name,
                    'phone': phone,
                    'address': address,
                    'updated_at': firestore.SERVER_TIMESTAMP
                })

                flash("Profile updated successfully!", 'success')
                return redirect(url_for('account'))
            except Exception as e:
                flash(f"Error updating profile: {str(e)}", 'error')
        else:
            flash("Database not available.", 'error')

    # GET request: fetch current user data
    user_data = {}
    if db:
        try:
            user_doc = db.collection('users').document(current_user.id).get()
            if user_doc.exists:
                user_data = user_doc.to_dict()
        except Exception as e:
            flash(f"Error loading profile: {str(e)}", 'error')

    return render_template('edit_profile.html', user=user_data)

@app.route('/support', methods=['GET', 'POST'])
@login_required
def support():
    """
    Handle support ticket creation and display user's tickets.
    Includes input validation and sanitization.
    """
    if request.method == 'POST':
        subject = bleach.clean(request.form.get('subject', '').strip())
        category = bleach.clean(request.form.get('category', '').strip())
        priority = bleach.clean(request.form.get('priority', '').strip())
        description = bleach.clean(request.form.get('description', '').strip())

        # Validate required fields
        if not all([subject, category, priority, description]):
            flash("All fields are required.", 'error')
            return redirect(url_for('support'))

        # Validate field lengths
        if len(subject) < 5 or len(subject) > 100:
            flash("Subject must be between 5 and 100 characters.", 'error')
            return redirect(url_for('support'))

        if len(description) < 10 or len(description) > 1000:
            flash("Description must be between 10 and 1000 characters.", 'error')
            return redirect(url_for('support'))

        # Validate category and priority values
        valid_categories = ['general', 'technical', 'billing', 'account', 'other']
        valid_priorities = ['low', 'medium', 'high', 'urgent']

        if category not in valid_categories:
            flash("Invalid category selected.", 'error')
            return redirect(url_for('support'))

        if priority not in valid_priorities:
            flash("Invalid priority selected.", 'error')
            return redirect(url_for('support'))

        if db:
            try:
                ticket_data = {
                    'user_id': current_user.id,
                    'user_email': current_user.email,
                    'subject': subject,
                    'category': category,
                    'priority': priority,
                    'description': description,
                    'status': 'open',
                    'created_at': firestore.SERVER_TIMESTAMP,
                    'updated_at': firestore.SERVER_TIMESTAMP,
                    'responses': []
                }
                ticket_ref = db.collection('support_tickets').add(ticket_data)
                ticket_id = ticket_ref[1].id

                # Send confirmation email to user
                send_support_ticket_confirmation(current_user.email, ticket_id, subject)

                # Send notification email to admin
                send_admin_support_notification(ticket_id, subject, category, priority, current_user.email)

                flash(f'Support ticket created successfully! Ticket ID: {ticket_id[:8].upper()}. A confirmation email has been sent to your inbox.', 'success')
                return redirect(url_for('support'))
            except Exception as e:
                flash(f'Error creating support ticket: {str(e)}', 'error')
        else:
            flash('Database not available.', 'error')

    # Fetch user's existing tickets
    user_tickets = []
    if db:
        try:
            tickets_ref = db.collection('support_tickets').where('user_id', '==', current_user.id).order_by('created_at', direction=firestore.Query.DESCENDING)
            tickets = tickets_ref.stream()
            for ticket in tickets:
                ticket_data = ticket.to_dict()
                ticket_data['id'] = ticket.id
                user_tickets.append(ticket_data)
        except Exception as e:
            logger.error(f"Error fetching user tickets: {str(e)}")

    return render_template('support.html', tickets=user_tickets)

@app.route('/admin/support')
@login_required
def admin_support():
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    # Fetch all support tickets
    all_tickets = []
    if db:
        try:
            tickets_ref = db.collection('support_tickets').order_by('created_at', direction=firestore.Query.DESCENDING)
            tickets = tickets_ref.stream()
            for ticket in tickets:
                ticket_data = ticket.to_dict()
                ticket_data['id'] = ticket.id
                all_tickets.append(ticket_data)
        except Exception as e:
            logger.error(f"Error fetching support tickets: {str(e)}")
            flash("Error loading support tickets.", 'error')

    return render_template('admin_support.html', tickets=all_tickets)

@app.route('/admin/sync_with_firestore', methods=['POST'])
@login_required
def sync_with_firestore():
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('admin'))

    if not db:
        flash('Firestore database not available.', 'error')
        return redirect(url_for('admin'))

    try:
        # Sync users from file-based storage to Firestore
        file_users = load_users_from_file()
        synced_count = 0
        updated_count = 0

        for user_data in file_users:
            user_id = user_data.get('id')
            if user_id:
                # Check if user exists in Firestore
                user_ref = db.collection('users').document(user_id)
                user_doc = user_ref.get()

                if user_doc.exists:
                    # Update existing user
                    firestore_data = user_doc.to_dict()
                    # Merge file data with Firestore data, preferring file data for conflicts
                    merged_data = {**firestore_data, **user_data}
                    user_ref.update(merged_data)
                    updated_count += 1
                else:
                    # Create new user in Firestore
                    user_ref.set(user_data)
                    synced_count += 1

        flash(f'Successfully synced {synced_count} new users and updated {updated_count} existing users to Firestore.', 'success')
        logger.info(f"Data sync completed: {synced_count} synced, {updated_count} updated")

    except Exception as e:
        logger.error(f"Error syncing data with Firestore: {str(e)}")
        flash(f'Error syncing data: {str(e)}', 'error')

    return redirect(url_for('admin'))

@app.route('/admin/update_oauth_roles', methods=['POST'])
@login_required
def update_oauth_roles():
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('admin'))

    if db:
        try:
            # Update all users with oauth_provider to have role 'customer'
            users_ref = db.collection('users')
            query = users_ref.where('oauth_provider', 'in', ['google', 'facebook'])
            users = list(query.stream())

            updated_count = 0
            for user_doc in users:
                user_data = user_doc.to_dict()
                if user_data.get('role') != 'customer':
                    user_doc.reference.update({'role': 'customer'})
                    updated_count += 1

            flash(f'Successfully updated {updated_count} OAuth users to customer role.', 'success')
        except Exception as e:
            logger.error(f"Error updating OAuth roles: {str(e)}")
            flash(f'Error updating OAuth roles: {str(e)}', 'error')
    else:
        flash('Database not available.', 'error')

    return redirect(url_for('admin'))

@app.route('/admin/customers')
@login_required
def admin_customers():
    """
    Fetch all customers with their current balance for the billing tab.
    Requires admin privileges.
    """
    if not current_user.is_admin():
        logger.warning(f"Unauthorized access attempt to customers list by user: {current_user.email}")
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    customers = []
    if db:
        try:
            # Fetch all users with role 'customer'
            users_ref = db.collection('users').where('role', '==', 'customer')
            users_docs = users_ref.stream()

            for user_doc in users_docs:
                user_data = user_doc.to_dict()
                user_data['id'] = user_doc.id

                # Calculate current balance: sum of total_amount from pending orders
                balance = 0.0
                try:
                    orders_ref = db.collection('orders').where('user_id', '==', user_doc.id).where('status', 'in', ['pending', 'processed', 'waiting_for_payment'])
                    orders_docs = orders_ref.stream()
                    for order_doc in orders_docs:
                        order_data = order_doc.to_dict()
                        balance += order_data.get('total_amount', 0)
                except Exception as e:
                    logger.error(f"Error calculating balance for user {user_doc.id}: {e}")

                user_data['balance'] = balance
                customers.append(user_data)

        except Exception as e:
            logger.error(f"Error fetching customers: {e}")
            flash("Database temporarily unavailable. Some features may not work.", 'warning')

    return {'customers': customers}

@app.route('/customer/<customer_id>/history')
@login_required
def customer_history(customer_id):
    """
    Display customer transaction history with debits and credits.
    Requires admin privileges.
    """
    if not current_user.is_admin():
        logger.warning(f"Unauthorized access attempt to customer history by user: {current_user.email}")
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    # Get customer info
    customer = None
    if db:
        try:
            user_doc = db.collection('users').document(customer_id).get()
            if user_doc.exists:
                customer = user_doc.to_dict()
                customer['id'] = customer_id
        except Exception as e:
            logger.error(f"Error fetching customer {customer_id}: {e}")
            flash("Error loading customer information.", 'error')
            return redirect(url_for('admin'))

    if not customer:
        flash("Customer not found.", 'error')
        return redirect(url_for('admin'))

    # Get all transactions for this customer (orders and payments)
    transactions = []

    if db:
        try:
            # Get orders (debits - money owed by customer)
            orders_ref = db.collection('orders').where('user_id', '==', customer_id)
            orders_docs = orders_ref.stream()

            for order_doc in orders_docs:
                order_data = order_doc.to_dict()
                order_data['id'] = order_doc.id
                order_data['type'] = 'debit'  # Customer owes money
                order_data['description'] = f"Order {order_data['id'][:8].upper()}"
                order_data['date'] = order_data.get('order_date')
                order_data['bill_no'] = order_data.get('order_id', '')[:8].upper()
                order_data['total_amount'] = order_data.get('total_amount', 0)
                order_data['amount'] = order_data.get('total_amount', 0)
                order_data['source'] = 'orders'  # Mark as order transaction
                order_data['status'] = order_data.get('status', 'pending')
                transactions.append(order_data)

            # Get customer transactions (both debits and credits)
            customer_transactions_ref = db.collection('customer_transactions').where('customer_id', '==', customer_id)
            customer_transactions_docs = customer_transactions_ref.stream()

            for transaction_doc in customer_transactions_docs:
                transaction_data = transaction_doc.to_dict()
                transaction_data['id'] = transaction_doc.id
                transaction_data['type'] = transaction_data.get('type', 'debit')
                transaction_data['description'] = transaction_data.get('description', 'Transaction')
                transaction_data['date'] = transaction_data.get('date')
                transaction_data['bill_no'] = transaction_data.get('bill_no', '')
                transaction_data['total_amount'] = transaction_data.get('amount', 0) if transaction_data.get('type') == 'debit' else 0
                transaction_data['amount'] = transaction_data.get('amount', 0)
                transaction_data['source'] = 'customer_transactions'  # Mark as manual transaction
                transaction_data['status'] = ''  # No status for manual transactions
                transaction_data['payment_method'] = transaction_data.get('payment_method', 'N/A') if transaction_data.get('type') == 'credit' else ''
                transactions.append(transaction_data)

        except Exception as e:
            logger.error(f"Error fetching transactions for customer {customer_id}: {e}")
            flash("Error loading transaction history.", 'error')

    # Sort all transactions by date (newest first for conversation format)
    transactions.sort(key=lambda x: x.get('date') or '', reverse=True)

    # Calculate current balance: sum of total_amount from pending orders minus credits
    balance = 0.0
    try:
        # Add pending orders (debits)
        orders_ref = db.collection('orders').where('user_id', '==', customer_id).where('status', 'in', ['pending', 'processed', 'waiting_for_payment'])
        orders_docs = orders_ref.stream()
        for order_doc in orders_docs:
            order_data = order_doc.to_dict()
            balance += order_data.get('total_amount', 0)

        # Subtract credits (payments made)
        credits_ref = db.collection('customer_transactions').where('customer_id', '==', customer_id).where('type', '==', 'credit')
        credits_docs = credits_ref.stream()
        for credit_doc in credits_docs:
            credit_data = credit_doc.to_dict()
            balance -= credit_data.get('amount', 0)

        # Add debits (additional charges)
        debits_ref = db.collection('customer_transactions').where('customer_id', '==', customer_id).where('type', '==', 'debit')
        debits_docs = debits_ref.stream()
        for debit_doc in debits_docs:
            debit_data = debit_doc.to_dict()
            balance += debit_data.get('amount', 0)

    except Exception as e:
        logger.error(f"Error calculating balance for customer {customer_id}: {e}")

    return render_template('customer_history.html', customer=customer, transactions=transactions, balance=balance)

@csrf.exempt
@app.route('/customer/<customer_id>/transaction/<transaction_id>')
@login_required
def view_customer_transaction(customer_id, transaction_id):
    """
    View details of a specific customer transaction.
    Requires admin privileges.
    """
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    # Get customer info
    customer = None
    if db:
        try:
            user_doc = db.collection('users').document(customer_id).get()
            if user_doc.exists:
                customer = user_doc.to_dict()
                customer['id'] = customer_id
        except Exception as e:
            logger.error(f"Error fetching customer {customer_id}: {e}")
            flash("Error loading customer information.", 'error')
            return redirect(url_for('admin'))

    if not customer:
        flash("Customer not found.", 'error')
        return redirect(url_for('admin'))

    # Get transaction details
    transaction = None
    if db:
        try:
            # Check if it's a customer transaction
            transaction_doc = db.collection('customer_transactions').document(transaction_id).get()
            if transaction_doc.exists:
                transaction = transaction_doc.to_dict()
                transaction['id'] = transaction_id
                transaction['type'] = transaction.get('type', 'debit')
            else:
                # Check if it's an order
                order_doc = db.collection('orders').document(transaction_id).get()
                if order_doc.exists:
                    order_data = order_doc.to_dict()
                    transaction = {
                        'id': transaction_id,
                        'type': 'debit',
                        'amount': order_data.get('total_amount', 0),
                        'description': f"Order {transaction_id[:8].upper()}",
                        'date': order_data.get('order_date'),
                        'bill_no': order_data.get('order_id', '')[:8].upper(),
                        'created_at': order_data.get('order_date'),
                        'created_by': order_data.get('user_email', 'system')
                    }
        except Exception as e:
            logger.error(f"Error fetching transaction {transaction_id}: {e}")
            flash("Error loading transaction details.", 'error')
            return redirect(url_for('customer_history', customer_id=customer_id))

    if not transaction:
        flash("Transaction not found.", 'error')
        return redirect(url_for('customer_history', customer_id=customer_id))

    return render_template('view_transaction.html', customer=customer, transaction=transaction)

@app.route('/customer/<customer_id>/transaction/<transaction_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_customer_transaction(customer_id, transaction_id):
    """
    Edit a customer transaction.
    Requires admin privileges.
    """
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    # Get customer info
    customer = None
    if db:
        try:
            user_doc = db.collection('users').document(customer_id).get()
            if user_doc.exists:
                customer = user_doc.to_dict()
                customer['id'] = customer_id
        except Exception as e:
            logger.error(f"Error fetching customer {customer_id}: {e}")
            flash("Error loading customer information.", 'error')
            return redirect(url_for('admin'))

    if not customer:
        flash("Customer not found.", 'error')
        return redirect(url_for('admin'))

    # Get transaction details
    transaction = None
    transaction_source = None  # 'customer_transactions' or 'orders'
    if db:
        try:
            # Check if it's a customer transaction
            transaction_doc = db.collection('customer_transactions').document(transaction_id).get()
            if transaction_doc.exists:
                transaction = transaction_doc.to_dict()
                transaction['id'] = transaction_id
                transaction_source = 'customer_transactions'
            else:
                # Check if it's an order (orders cannot be edited)
                order_doc = db.collection('orders').document(transaction_id).get()
                if order_doc.exists:
                    flash("Order transactions cannot be edited.", 'error')
                    return redirect(url_for('customer_history', customer_id=customer_id))
        except Exception as e:
            logger.error(f"Error fetching transaction {transaction_id}: {e}")
            flash("Error loading transaction details.", 'error')
            return redirect(url_for('customer_history', customer_id=customer_id))

    if not transaction:
        flash("Transaction not found.", 'error')
        return redirect(url_for('customer_history', customer_id=customer_id))

    if request.method == 'POST':
        # Get form data
        amount = float(request.form.get('amount', 0))
        description = bleach.clean(request.form.get('description', '').strip())
        bill_no = bleach.clean(request.form.get('bill_no', '').strip())
        transaction_date = request.form.get('date')
        modification_reason = bleach.clean(request.form.get('modification_reason', '').strip())

        # Validate input
        if amount <= 0:
            flash("Amount must be greater than 0.", 'error')
            return render_template('edit_transaction.html', customer=customer, transaction=transaction)

        # Description is now optional

        if not transaction_date:
            flash("Date is required.", 'error')
            return render_template('edit_transaction.html', customer=customer, transaction=transaction)

        if not modification_reason:
            flash("Modification reason is required.", 'error')
            return render_template('edit_transaction.html', customer=customer, transaction=transaction)

        try:
            # Calculate balance change
            old_amount = transaction.get('amount', 0)
            old_type = transaction.get('type', 'debit')
            new_type = transaction.get('type', 'debit')  # Type doesn't change in edit

            # Create detailed modification log entry
            changes = []
            if old_amount != amount:
                changes.append(f"Amount: ₹{old_amount:.2f} → ₹{amount:.2f}")
            if transaction.get('description', '') != description:
                changes.append(f"Description: '{transaction.get('description', '')}' → '{description}'")
            if transaction.get('date') != transaction_date:
                changes.append(f"Date: {transaction.get('date', 'N/A')} → {transaction_date}")
            if transaction.get('bill_no', '') != bill_no:
                changes.append(f"Bill No: '{transaction.get('bill_no', '')}' → '{bill_no}'")

            detailed_reason = f"{modification_reason} | {', '.join(changes)}" if changes else modification_reason

            modification_log = {
                'timestamp': datetime.utcnow(),
                'modified_by': current_user.email,
                'reason': detailed_reason,
                'changes': changes,
                'previous_amount': old_amount,
                'new_amount': amount,
                'previous_description': transaction.get('description', ''),
                'new_description': description,
                'previous_date': transaction.get('date'),
                'new_date': transaction_date,
                'previous_bill_no': transaction.get('bill_no', ''),
                'new_bill_no': bill_no
            }

            # Update transaction
            update_data = {
                'amount': amount,
                'description': description,
                'bill_no': bill_no if bill_no else None,
                'date': transaction_date,
                'updated_at': datetime.utcnow(),
                'last_modified': datetime.utcnow(),
                'last_modified_by': current_user.email,
                'modification_reason': modification_reason
            }

            # Add modification history if it doesn't exist
            if 'modification_history' not in transaction:
                update_data['modification_history'] = [modification_log]
            else:
                # Append to existing history
                existing_history = transaction.get('modification_history', [])
                existing_history.append(modification_log)
                update_data['modification_history'] = existing_history

            # Remove firestore.SERVER_TIMESTAMP from update_data to avoid the error
            if 'updated_at' in update_data:
                update_data['updated_at'] = datetime.utcnow()
            if 'last_modified' in update_data:
                update_data['last_modified'] = datetime.utcnow()

            db.collection(transaction_source).document(transaction_id).update(update_data)

            # Update customer balance if amount changed
            if old_amount != amount:
                balance_change = (amount - old_amount) if new_type == 'debit' else (old_amount - amount)

                customer_data = db.collection('users').document(customer_id).get().to_dict()
                current_balance = customer_data.get('balance', 0)
                new_balance = current_balance + balance_change

                db.collection('users').document(customer_id).update({
                    'balance': new_balance,
                    'updated_at': datetime.utcnow()
                })

            flash("Transaction updated successfully!", 'success')
            return redirect(url_for('customer_history', customer_id=customer_id))

        except Exception as e:
            logger.error(f"Error updating transaction {transaction_id}: {str(e)}")
            flash(f"Error updating transaction: {str(e)}", 'error')

    return render_template('edit_transaction.html', customer=customer, transaction=transaction)

@app.route('/customer/<customer_id>/transaction/<transaction_id>/delete', methods=['POST'])
@login_required
def delete_customer_transaction(customer_id, transaction_id):
    """
    Delete a customer transaction.
    Requires admin privileges.
    """
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    if db:
        try:
            # Check if it's a customer transaction
            transaction_doc = db.collection('customer_transactions').document(transaction_id).get()
            if transaction_doc.exists:
                transaction_data = transaction_doc.to_dict()

                # Update customer balance before deleting
                amount = transaction_data.get('amount', 0)
                transaction_type = transaction_data.get('type', 'debit')

                # Reverse the balance effect
                balance_change = -amount if transaction_type == 'debit' else amount

                customer_data = db.collection('users').document(customer_id).get().to_dict()
                current_balance = customer_data.get('balance', 0)
                new_balance = current_balance + balance_change

                # Delete transaction
                db.collection('customer_transactions').document(transaction_id).delete()

                # Update customer balance
                db.collection('users').document(customer_id).update({
                    'balance': new_balance,
                    'updated_at': firestore.SERVER_TIMESTAMP
                })
        
                # Log deletion in modification history (for audit purposes)
                deletion_log = {
                    'timestamp': datetime.utcnow(),
                    'modified_by': current_user.email,
                    'reason': f"Transaction deleted - Amount: ₹{amount:.2f}, Description: '{transaction_data.get('description', '')}', Date: {transaction_data.get('date', 'N/A')}, Bill No: '{transaction_data.get('bill_no', '')}'",
                    'action': 'DELETE',
                    'previous_amount': amount,
                    'previous_description': transaction_data.get('description', ''),
                    'previous_date': transaction_data.get('date'),
                    'previous_bill_no': transaction_data.get('bill_no', '')
                }
        
                # Create a deletion audit record
                db.collection('transaction_audit_log').add({
                    'customer_id': customer_id,
                    'transaction_id': transaction_id,
                    'action': 'DELETE',
                    'details': deletion_log,
                    'performed_by': current_user.email,
                    'timestamp': datetime.utcnow()
                })
        
                flash("Transaction deleted successfully!", 'success')
            else:
                # Check if it's an order (orders cannot be deleted)
                order_doc = db.collection('orders').document(transaction_id).get()
                if order_doc.exists:
                    flash("Order transactions cannot be deleted.", 'error')
                else:
                    flash("Transaction not found.", 'error')

        except Exception as e:
            logger.error(f"Error deleting transaction {transaction_id}: {str(e)}")
            flash(f"Error deleting transaction: {str(e)}", 'error')

    return redirect(url_for('customer_history', customer_id=customer_id))

@csrf.exempt
@app.route('/customer/add_transaction', methods=['POST'])
@login_required
def add_customer_transaction():
    """
    Add a debit or credit transaction for a customer.
    Requires admin privileges.
    """
    if not current_user.is_admin():
        return {'success': False, 'message': 'Access denied. Admin privileges required.'}, 403

    try:
        data = request.get_json()

        # Validate required fields
        required_fields = ['customer_id', 'type', 'amount', 'description', 'date']
        for field in required_fields:
            if field not in data or not data[field]:
                return {'success': False, 'message': f'{field.replace("_", " ").title()} is required.'}, 400

        customer_id = data['customer_id']
        transaction_type = data['type']
        amount = float(data['amount'])
        description = bleach.clean(data['description'].strip())
        bill_no = bleach.clean(data.get('bill_no', '').strip())
        transaction_date = data['date']

        # Validate transaction type
        if transaction_type not in ['debit', 'credit']:
            return {'success': False, 'message': 'Invalid transaction type.'}, 400

        # Validate amount
        if amount <= 0:
            return {'success': False, 'message': 'Amount must be greater than 0.'}, 400

        # Validate date
        try:
            from datetime import datetime
            datetime.strptime(transaction_date, '%Y-%m-%d')
        except ValueError:
            return {'success': False, 'message': 'Invalid date format.'}, 400

        if db:
            # Verify customer exists
            customer_doc = db.collection('users').document(customer_id).get()
            if not customer_doc.exists:
                return {'success': False, 'message': 'Customer not found.'}, 404

            # Create transaction record
            transaction_data = {
                'customer_id': customer_id,
                'type': transaction_type,
                'amount': amount,
                'description': description,
                'bill_no': bill_no if bill_no else None,
                'date': transaction_date,
                'created_by': current_user.email,
                'created_at': firestore.SERVER_TIMESTAMP
            }

            # Add to customer_transactions collection
            db.collection('customer_transactions').add(transaction_data)

            # Update customer's balance
            # For debit: increase balance (customer owes more)
            # For credit: decrease balance (customer paid)
            balance_change = amount if transaction_type == 'debit' else -amount

            # Get current balance from customer data
            customer_data = customer_doc.to_dict()
            current_balance = customer_data.get('balance', 0)
            new_balance = current_balance + balance_change  # Allow negative balance for credits

            # Update customer balance
            db.collection('users').document(customer_id).update({
                'balance': new_balance,
                'updated_at': firestore.SERVER_TIMESTAMP
            })

            logger.info(f"Added {transaction_type} transaction of ₹{amount} for customer {customer_id}")
            return {'success': True, 'message': f'{transaction_type.title()} transaction added successfully!'}

        else:
            return {'success': False, 'message': 'Database not available.'}, 500

    except Exception as e:
        logger.error(f"Error adding customer transaction: {str(e)}")
        return {'success': False, 'message': 'An error occurred while adding the transaction.'}, 500

@app.route('/admin/support/<ticket_id>', methods=['GET', 'POST'])
@login_required
def admin_support_ticket(ticket_id):
    """
    Handle admin responses to support tickets.
    Requires admin privileges.
    """
    if not current_user.is_admin():
        logger.warning(f"Unauthorized access attempt to support ticket {ticket_id} by user: {current_user.email}")
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    if request.method == 'POST':
        response = bleach.clean(request.form.get('response', '').strip())
        new_status = bleach.clean(request.form.get('status', '').strip())

        # Validate response
        if not response or len(response.strip()) < 5:
            flash("Response must be at least 5 characters long.", 'error')
            return redirect(url_for('admin_support_ticket', ticket_id=ticket_id))

        # Validate status if provided
        if new_status and new_status not in ['open', 'in_progress', 'resolved', 'closed']:
            flash("Invalid status selected.", 'error')
            return redirect(url_for('admin_support_ticket', ticket_id=ticket_id))

        if db:
            try:
                ticket_ref = db.collection('support_tickets').document(ticket_id)
                ticket_doc = ticket_ref.get()

                if ticket_doc.exists:
                    ticket_data = ticket_doc.to_dict()
                    responses = ticket_data.get('responses', [])

                    # Add new response
                    responses.append({
                        'responder_id': current_user.id,
                        'responder_email': current_user.email,
                        'response': response,
                        'timestamp': firestore.SERVER_TIMESTAMP,
                        'is_admin': True
                    })

                    update_data = {
                        'responses': responses,
                        'updated_at': firestore.SERVER_TIMESTAMP
                    }

                    if new_status:
                        update_data['status'] = new_status

                    ticket_ref.update(update_data)
                    flash('Response added successfully!', 'success')
                else:
                    flash('Ticket not found.', 'error')
            except Exception as e:
                flash(f'Error adding response: {str(e)}', 'error')

        return redirect(url_for('admin_support_ticket', ticket_id=ticket_id))

    # GET request: fetch ticket details
    ticket = None
    if db:
        try:
            ticket_doc = db.collection('support_tickets').document(ticket_id).get()
            if ticket_doc.exists:
                ticket = ticket_doc.to_dict()
                ticket['id'] = ticket_id
        except Exception as e:
            flash(f'Error fetching ticket: {str(e)}', 'error')

    if not ticket:
        flash('Ticket not found.', 'error')
        return redirect(url_for('admin_support'))

    return render_template('admin_support_ticket.html', ticket=ticket)




if __name__ == '__main__':
    # Development configuration with auto-reload
    debug_mode = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'

    # SSL configuration for secure connections
    ssl_context = None
    if not debug_mode:
        # In production, use SSL certificates
        cert_file = os.environ.get('SSL_CERT_FILE')
        key_file = os.environ.get('SSL_KEY_FILE')
        if cert_file and key_file:
            ssl_context = (cert_file, key_file)
            logger.info("SSL certificates configured for secure connections")
        else:
            logger.warning("SSL certificates not configured. Running without HTTPS in production is not recommended.")

    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=debug_mode,
        threaded=True,
        use_reloader=debug_mode,  # Enable reloader in development
        ssl_context=ssl_context
    )