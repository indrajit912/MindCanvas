# app/auth/routes.py
# Author: Indrajit Ghosh
# Created On: Mar 24, 2024
# Modified On: Apr 18, 2024
#
# Standard library imports
import logging

# Third-party imports
from flask import abort, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from cryptography.fernet import InvalidToken

# Local application imports
from app.forms.auth_forms import EmailRegistrationForm, UserLoginForm, UserRegistrationForm
from app.models.user import User
from app.utils.decorators import logout_required
from app.utils.encryption import decrypt_user_private_key, generate_derived_key_from_passwd
from app.utils.token import get_token_for_email_registration, confirm_email_registration_token
from app.utils.user_utils import update_user_last_seen, create_new_user, update_user, change_user_password
from config import EmailConfig
from scripts.email_message import EmailMessage

# Relative imports
from . import auth_bp

logger = logging.getLogger(__name__)

def redirect_to_destination(destination):
    # Redirect to the specified destination
    if destination == 'dashboard':
        return redirect(url_for('auth.dashboard'))
    elif destination == 'profile':
        return redirect(url_for('auth.profile'))
    elif destination == 'user-all-entries':
        return redirect(url_for('auth.user_journal_entries', user_id=current_user.id))
    elif destination == 'search':
        return redirect(url_for('auth.search', user_id=current_user.id))
    elif destination == 'favourites':
        return redirect(url_for('auth.favourites', user_id=current_user.id))
    
    # Check if the destination contains a dot, meaning it could be a dynamic route
    elif '.' in destination:
        parts = destination.split('.')
        
        # Ensure there are at least blueprint and route names
        if len(parts) < 2:
            # Invalid format, redirect to dashboard or handle as needed
            return redirect(url_for('auth.dashboard'))

        # Extract blueprint and route name
        bp_name = parts[0]
        route_name = parts[1]

        # Collect parameters if present
        if len(parts) > 2:
            # Build parameter dictionary
            params = {parts[i]: parts[i + 1] for i in range(2, len(parts), 2)}
        else:
            params = {}

        # Redirect using the dynamically constructed route
        try:
            return redirect(url_for(f'{bp_name}.{route_name}', **params))
        except Exception as e:
            # Log the error and fallback to dashboard if something goes wrong
            print(f"Error during redirect: {e}")
            return redirect(url_for('auth.dashboard'))
    else:
        # Handle invalid destination
        return redirect(url_for('auth.dashboard')) 

@auth_bp.before_request
def update_last_seen():
    if current_user.is_authenticated:
        user_id = current_user.id
        status_code, response_data = update_user_last_seen(user_id)

        if status_code != 200:
            logger.error(f"Updating last seen failed for '{current_user.username}'")


# Login view (route)
@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = UserLoginForm()

    # Login logic here
    if form.validate_on_submit():

        # Check if the user provided username or email
        user = User.query.filter((User.username == form.username_or_email.data) | (User.email == form.username_or_email.data)).first()

        if user:
            # Check the hash
            if user.check_password(form.passwd.data):
                # Password matched!
                login_user(user)

                session['entries_unlocked'] = False
                # Save the User's derived key to the session 
                derived_key = generate_derived_key_from_passwd(form.passwd.data)
                user_private_key = decrypt_user_private_key(
                    encrypted_private_key=current_user.encrypted_private_key,
                    derived_key=derived_key
                )
                session['current_user_private_key'] = user_private_key
                
                flash("Login successful!", 'success')
                logger.info(f"User '{user.email}' successfully logged in.")

                return redirect(url_for('auth.dashboard'))
            else:
                flash("Wrong passsword. Try again!", 'error')
        else:
            flash("That user doesn't exist! Try again...", 'error')
        
        form = UserLoginForm(formdata=None)

    return render_template('login.html', form=form)


@auth_bp.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash("You have been logged out successfully!", 'success')
    logger.info("User logged out successfully.")

    return redirect(url_for('auth.login'))


@auth_bp.route('/register_email', methods=['GET', 'POST'])
@logout_required
def register_email():
    form = EmailRegistrationForm()

    if form.validate_on_submit():
        # Check whether the email already exists in the database
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            flash("Email id taken. Try different one!", 'warning')
            return redirect(url_for('auth.register_email'))
        else:
            # Get the token
            token = get_token_for_email_registration(fullname=form.fullname.data, email=form.email.data)
            acc_registration_url = url_for('auth.register_user', token=token, _external=True)
            
            # Send acc_registration_url to the new user form.email.data.
            _email_html_text = render_template(
                'emails/email_register.html',
                acc_registration_url=acc_registration_url,
                username=form.fullname.data
            )

            msg = EmailMessage(
                sender_email_id=EmailConfig.INDRAJITS_BOT_EMAIL_ID,
                to=form.email.data,
                subject=f"{current_app.config['FLASK_APP_NAME']}: New Account Registration",
                email_html_text=_email_html_text
            )

            try:
                msg.send(
                    sender_email_password=EmailConfig.INDRAJITS_BOT_EMAIL_PASSWD,
                    server_info=EmailConfig.GMAIL_SERVER,
                    print_success_status=False
                )

                flash('Almost there! New account registration instructions sent to your email. Please check and follow the link.', 'info')
                logger.info(f"New acc registration instruction sent over email to '{form.email.data}'.")
                form = EmailRegistrationForm(formdata=None)
                return render_template('register_email.html', form=form)
            
            except Exception as e:
                # TODO: Handle email sending error better
                flash('An error occurred while attempting to send the account registration link through email. Try again!', 'danger')
                logger.error("Error occurred while attempting to send the account registration link through email.")
                return redirect(url_for('auth.register_email'))


    return render_template('register_email.html', form=form)

@auth_bp.route('/register_user/<token>', methods=['GET', 'POST'])
def register_user(token):
    user_data = confirm_email_registration_token(token)

    if not user_data:
        flash('Invalid or expired reset token. Please try again.', 'danger')
        return redirect(url_for('auth.register_email'))
    
    form = UserRegistrationForm()

    if form.validate_on_submit():
        # Prepare data for the POST request
        new_user_data = {
            'fullname': user_data['fullname'],
            'email': user_data['email'],
            'username': form.username.data,
            'password': form.passwd.data,
            'email_verified': True
        }

        # Create the user!
        status_code, message = create_new_user(**new_user_data)

        if status_code == 200:
            # Capture the user_json sent by the POST request.
            user_json = message
            logger.info(f"A new user registered with the username `{user_json['username']}`.")
            flash("You have successfully registered! You may now log in using these credentials.", 'success')

            # Derive the password reset key
            passwd_reset_key = generate_derived_key_from_passwd(new_user_data['password'])

            # Send welcome email to the user with the new password_reset_key.
            _email_html_text = render_template(
                'emails/welcome_email.html',
                passwd_reset_key=passwd_reset_key.hex(), # To reverse this use bytes.fromhex(password_reset_key_hex)
                username=new_user_data['fullname']
            )

            msg = EmailMessage(
                sender_email_id=EmailConfig.INDRAJITS_BOT_EMAIL_ID,
                to=new_user_data['email'],
                subject="Welcome to MindCanvas!",
                email_html_text=_email_html_text
            )

            try:
                msg.send(
                    sender_email_password=EmailConfig.INDRAJITS_BOT_EMAIL_PASSWD,
                    server_info=EmailConfig.GMAIL_SERVER,
                    print_success_status=False
                )

                flash('A welcome email containing a password reset key has been dispatched to your email address.', 'info')
                logger.info(f"EMAIL_SENT: Welcome email with password reset key has been emailed to '{new_user_data['fullname']}'.")

            except Exception as e:
                # TODO: Handle email sending error better
                flash('An error occurred while attempting to send the welcome email. Try again!', 'danger')
                logger.error(f"Error occurred while attempting to send welcome email along with password reset key through email.\nERROR: {e}")

            return redirect(url_for('auth.login'))
        
        elif status_code == 400:
            flash(message['message'], 'error')
        else:
            logger.error("Failed to register the user.")
            flash('Failed to register user. Please try again.', 'danger')

    return render_template('register_user.html', form=form, user_data=user_data)


@auth_bp.route('/send_verification_email', methods=['GET'])
@login_required
def send_verification_email():
    if not current_user.email_verified:
        # Generate verification token
        token = current_user.generate_email_verification_token()

        # Construct verification link
        verification_link = url_for('auth.verify_email', token=token, _external=True)

        _email_html_text = render_template(
            'emails/email_verification.html',
            verification_link=verification_link
        )

        msg = EmailMessage(
            sender_email_id=EmailConfig.INDRAJITS_BOT_EMAIL_ID,
            to=current_user.email,
            subject=f"{current_app.config['FLASK_APP_NAME']}: Email verification!",
            email_html_text=_email_html_text
        )

        try:
            msg.send(
                sender_email_password=EmailConfig.INDRAJITS_BOT_EMAIL_PASSWD,
                server_info=EmailConfig.GMAIL_SERVER,
                print_success_status=False
            )

            flash('Email verification link sent to your email address. Please check and follow the link.', 'info')
            logger.info(f"Email verification link sent over email to '{current_user.email}'.")
            
            return redirect(url_for('auth.profile'))
            
        except Exception as e:
            # TODO: Handle email sending error better
            flash('An error occurred while attempting to send the email verification link through email. Try again!', 'danger')
            logger.error(f"Error occurred while attempting to send the email verification link through email.\nERROR: {e}")
            return redirect(url_for('auth.profile'))
    
    return redirect(url_for('auth.profile'))


@auth_bp.route('/verify_email/<token>', methods=['GET'])
def verify_email(token):
    user = User.verify_email_verification_token(token)
    if user:
        # Update user!
        status_code, message = update_user(user_id=user.id, data={"email_verified": True})

        if status_code == 200:
            flash('Your email has been successfully verified!', 'success')
            logger.info(f"Email verified successfully: '{user.username}'")
        else:
            flash("Email cannot be verified due to some error. Try again later!", 'error')
            logger.error(f"Error occurred while verifying email address.\nERROR: {message}")

    else:
        flash('Invalid or expired verification link. Please try again.', 'error')

    return redirect(url_for('auth.login'))


@auth_bp.route('/change_password', methods=['POST'])
@login_required
def change_password():
    user_id = request.form.get('user_id')
    old_passwd = request.form.get('old_passwd')

    if current_user.id != int(user_id):
        abort(403)

    user = User.query.get_or_404(user_id)
    if user.check_password(old_passwd):
        new_passwd = request.form.get('new_passwd')
        confirm_passwd = request.form.get('confirm_passwd')

        if new_passwd != confirm_passwd:
            flash("Passwords didn't match. Try again!", 'error')
            return redirect(url_for('auth.profile'))
        
        # Get user's private key from the session
        user_private_key = session['current_user_private_key']

        # Change user password
        status_code, message = change_user_password(
            user_id=user.id, new_password=new_passwd, private_key=user_private_key
        )

        if status_code == 200:
            flash("Password changed successfully.", 'success')
            logger.info(f"PASSWORD_CHANGE: The user '{user.username}' changed their password.")

            # Derive the password reset key
            passwd_reset_key = generate_derived_key_from_passwd(new_passwd)

            # Send email to the user with the new password_reset_key.
            _email_html_text = render_template(
                'emails/change_passwd_email.html',
                passwd_reset_key=passwd_reset_key.hex(), # To reverse this use bytes.fromhex(password_reset_key_hex)
                username=user.fullname
            )
            
            msg = EmailMessage(
                sender_email_id=EmailConfig.INDRAJITS_BOT_EMAIL_ID,
                to=current_user.email,
                subject=f"{current_app.config['FLASK_APP_NAME']}: Password Change Notification!",
                email_html_text=_email_html_text
            )

            try:
                msg.send(
                    sender_email_password=EmailConfig.INDRAJITS_BOT_EMAIL_PASSWD,
                    server_info=EmailConfig.GMAIL_SERVER,
                    print_success_status=False
                )

                flash('An email containing a password reset key has been dispatched to your email address.', 'info')
                logger.info(f"EMAIL_SENT: A password change notification with password reset key has been emailed to '{current_user.email}'.")

            except Exception as e:
                # TODO: Handle email sending error better
                flash('An error occurred while attempting to send the password reset key through email. Try again!', 'danger')
                logger.error(f"Error occurred while attempting to send the password change notification along with password reset key through email.\nERROR: {e}")
        else:
            flash("Error occurred while changing the password.", 'error')
            logger.error(f"API_ERROR: couldn't change the user password due to err during api call.\n{message}")
    else:
        flash("Wrong old password!", 'error')

    return redirect(url_for('auth.profile'))

@auth_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():

    if request.method == 'POST':
        username_email = request.form.get('username_email')
        passwd_reset_key = request.form.get('passwd_reset_key')
        new_passwd = request.form.get('new_passwd')
        confirm_passwd = request.form.get('confirm_passwd')

        # Get the user
        user = User.query.filter((User.username == username_email) | (User.email == username_email)).first()
        
        if user:
            
            if not new_passwd == confirm_passwd:
                flash("Passwords don't match. Try again!", 'error')
                return render_template('forgot_password.html')
            
            try:
                # Get user's encrypted_private_key
                user_encrypted_private_key = user.encrypted_private_key

                # Make the derived key from the passwd_reset_key
                user_derived_key = bytes.fromhex(passwd_reset_key)

                # Decrypt user's encrypted private key
                user_private_key = decrypt_user_private_key(
                    user_encrypted_private_key,
                    user_derived_key
                )

                # Change the password
                status_code, message = change_user_password(
                    user_id=user.id,
                    new_password=new_passwd,
                    private_key=user_private_key
                )

                if status_code == 200:
                    flash("Your password has been successfully changed. You can now log in using your new password.", 'success')
                    logger.info(f"PASSWORD_CHANGE: The user '{user.username}' changed their password.")

                    # Derive the password reset key
                    passwd_reset_key = generate_derived_key_from_passwd(new_passwd)

                    # Send email to the user with the new password_reset_key.
                    _email_html_text = render_template(
                        'emails/change_passwd_email.html',
                        passwd_reset_key=passwd_reset_key.hex(),
                        username=user.fullname
                    )

                    msg = EmailMessage(
                        sender_email_id=EmailConfig.INDRAJITS_BOT_EMAIL_ID,
                        to=user.email,
                        subject=f"{current_app.config['FLASK_APP_NAME']}: Password Reset Successful!",
                        email_html_text=_email_html_text
                    )

                    try:
                        msg.send(
                            sender_email_password=EmailConfig.INDRAJITS_BOT_EMAIL_PASSWD,
                            server_info=EmailConfig.GMAIL_SERVER,
                            print_success_status=False
                        )

                        flash('An email containing a password reset key has been dispatched to your email address.', 'info')
                        logger.info(f"EMAIL_SENT: A password reset notification with password reset key has been emailed to '{user.email}'.")
                        return redirect(url_for('auth.login'))
                    
                    except Exception as e:
                        # TODO: Handle email sending error better
                        flash('An error occurred while attempting to send the password reset key through email. Try again!', 'danger')
                        logger.error(f"Error occurred while attempting to send the password change notification along with password reset key through email.\nERROR: {e}")

            except ValueError:
                flash("Invalid password reset key. Please enter a valid key.", 'error')
            except InvalidToken:
                flash("Invalid token. Please check your password reset key and try again.", "error")
            except Exception as e:
                flash(f"An error occurred: {str(e)}", 'error')
                logger.error(f"An error occurred while resetting the user's password.\n{e}")
                
        else:
            flash(f"Sorry, we couldn't find any user with the username or email '{username_email}'.", 'error')

    return render_template('forgot_password.html')


