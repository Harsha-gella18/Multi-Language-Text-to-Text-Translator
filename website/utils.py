



import random
import smtplib
from email.mime.text import MIMEText
from flask import session, redirect, url_for
import os
from dotenv import load_dotenv
from functools import wraps

load_dotenv()  # Load environment variables

import random
import os
import smtplib
from email.mime.text import MIMEText
from flask import session

def send_otp_email(mail, otp=None):
    otp = otp or str(random.randint(100000, 999999))  # Generate a 6-digit OTP
    print(otp)
    session['otp'] = otp  # Store the OTP in session for verification
    sender_email = os.getenv('SENDER_EMAIL')
    receiver_email = mail
    subject = 'Your One-Time Password (OTP)'
    
    # Updated message text
    body = (
        f'Hello,\n\n'
        f'Your one-time password (OTP) for the verification process is {otp}.\n\n'
        f'Please enter this code on the verification page to complete the process.\n\n'
        f'If you did not request this, please disregard this email.\n\n'
        f'Thank you!'
    )

    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = sender_email
    msg['To'] = receiver_email

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, os.getenv('EMAIL_PASSWORD'))
            server.sendmail(sender_email, receiver_email, msg.as_string())
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False


def verification(otp):
    session_otp = session.get('otp')
    return session_otp and session_otp == otp

# Add the necessary login check wrappers
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function
