from flask import Blueprint, render_template, redirect, url_for, request, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from .models import create_user, get_user, add_translation_to_history, get_translation_history, get_user_by_email, reset_user_password
import boto3
import os
from dotenv import load_dotenv
from .utils import send_otp_email, verification, login_required

# Load environment variables
load_dotenv()

# Initialize the authentication blueprint
auth = Blueprint('auth', __name__)

# Initialize AWS Translate client
translate = boto3.client(
    'translate',
    region_name=os.getenv('AWS_REGION'),
    aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
    aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY')
)

# ------------------------------------
# SIGNUP AND OTP VERIFICATION
# ------------------------------------

@auth.route('/signup', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('first_name') + " " + request.form.get('last_name')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        email = request.form.get('email')

        # Validate form inputs
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('auth.register'))

        if get_user(username):
            flash('Username already exists. Please choose a different username.', 'danger')
            return redirect(url_for('auth.register'))

        # Send OTP and store temp user data in session
        if send_otp_email(email):
            session['temp_user'] = {'name': name, 'username': username, 'password': password, 'email': email}
            return redirect(url_for('auth.verify_otp'))
        else:
            flash('Error sending OTP. Please try again.', 'danger')
            return redirect(url_for('auth.register'))

    return render_template('signup.html')


@auth.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        input_otp = request.form.get('otp')

        # Verify the OTP
        if verification(input_otp):
            temp_user = session.pop('temp_user', None)
            if temp_user:
                hashed_password = generate_password_hash(temp_user['password'], method='pbkdf2:sha256')
                create_user(temp_user['name'], temp_user['username'], hashed_password, temp_user['email'])
                flash('Registration successful. Please log in.', 'success')
                return redirect(url_for('auth.login'))  # Redirect to login page
            else:
                flash('Session expired. Please register again.', 'danger')
                return redirect(url_for('auth.register'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('verify_signup_otp.html')

# ------------------------------------
# LOGIN
# ------------------------------------

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Authenticate user
        user = get_user(username)
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            session['isLogin'] = True  # Track login status
            return redirect(url_for('auth.dashboard'))
        else:
            flash('Invalid username or password. Please try again.', 'danger')

    return render_template('login.html')

# ------------------------------------
# DASHBOARD AND LOGOUT
# ------------------------------------

@auth.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    input_text = None
    target_language = None
    translated_text = None

    if request.method == 'POST':
        input_text = request.form.get('input_text')
        target_language = request.form.get('target_language')

        if not input_text or not target_language:
            flash('Both input text and target language are required.', 'danger')
            return redirect(url_for('auth.dashboard'))

        # Call AWS Translate
        try:
            response = translate.translate_text(
                Text=input_text,
                SourceLanguageCode='auto',  # Detect source language automatically
                TargetLanguageCode=target_language
            )
            translated_text = response.get('TranslatedText')
            print(translated_text)

            # Save to translation history
            add_translation_to_history(session['username'], input_text, translated_text)

        except Exception as e:
            flash(f'Error translating text: {str(e)}', 'danger')
            return redirect(url_for('auth.dashboard'))
        
    return render_template('dashboard.html', input_text=input_text, target_language=target_language, translated_text=translated_text)


@auth.route('/logout')
def logout():
    session.pop('username', None)
    session['isLogin'] = False
    flash('You have been logged out.', 'success')
    return redirect(url_for('auth.login'))

# ------------------------------------
# FORGOT PASSWORD & RESET PASSWORD
# ------------------------------------

@auth.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = get_user_by_email(email)

        if user:
            # Send OTP to user's email
            if send_otp_email(email):
                session['reset_email'] = email
                flash('OTP has been sent to your email. Please check and verify.', 'success')
                return redirect(url_for('auth.verify_reset_otp'))
            else:
                flash('Error sending OTP. Please try again.', 'danger')
        else:
            flash('Email not found. Please check your email address.', 'danger')

    return render_template('forget_password.html')


@auth.route('/verify_reset_otp', methods=['GET', 'POST'])
def verify_reset_otp():
    if request.method == 'POST':
        input_otp = request.form.get('otp')

        if verification(input_otp):
            return redirect(url_for('auth.reset_password'))
        else:
            flash('Invalid OTP. Please try again.', 'danger')

    return render_template('verify_otp.html')  # Reusing OTP verification template


@auth.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('auth.reset_password'))

        email = session.get('reset_email')
        if email:
            hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
            if reset_user_password(email, hashed_password):
                flash('Password reset successfully. Please log in.', 'success')
                return redirect(url_for('auth.login'))
            else:
                flash('Error resetting password. Please try again.', 'danger')
        else:
            flash('Session expired. Please try the reset process again.', 'danger')

    return render_template('reset_password.html')

# ------------------------------------
# TRANSLATION HISTORY
# ------------------------------------

@auth.route('/history')
@login_required
def history():
    username = session.get('username')
    if username:
        translation_history = get_translation_history(username)
        return render_template('history.html', history=translation_history)
    else:
        flash('You need to log in to view your history.', 'danger')
        return redirect(url_for('auth.login'))


@auth.route('/profile')
@login_required
def profile():
    # Ensure the user is logged in and session has 'username'
    if 'username' in session:
        # Retrieve user details
        user = get_user(session['username'])
        
        # Retrieve translation history for the user
        translation_history = get_translation_history(session['username'])
        
        # Reverse the translation history to show the most recent first
        translation_history = translation_history[::-1]
        
        # Render the profile template with user and translation data
        return render_template('profile.html', user=user, translations=translation_history)
    else:
        # If the user is not logged in, redirect to login page with a flash message
        flash('Please log in to view your profile.', 'danger')
        return redirect(url_for('auth.login'))
