from flask import Flask, render_template, flash, redirect, url_for, request, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
import os
from icloud_to_s3.auth import AuthenticationManager
from icloud_to_s3.backup import BackupManager
from icloud_to_s3.utils import handle_2fa_challenge

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id):
        self.id = id

class CloudCredentialsForm(FlaskForm):
    icloud_username = StringField('iCloud Username', validators=[DataRequired(), Email()])
    icloud_password = PasswordField('iCloud Password', validators=[DataRequired()])
    aws_access_key = StringField('AWS Access Key', validators=[DataRequired()])
    aws_secret_key = PasswordField('AWS Secret Key', validators=[DataRequired()])
    s3_bucket = StringField('S3 Bucket Name', validators=[DataRequired()])
    submit = SubmitField('Start Backup')

class TwoFactorForm(FlaskForm):
    code = StringField('Verification Code', validators=[DataRequired()])
    submit = SubmitField('Verify')

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('backup'))
    return render_template('index.html')

@app.route('/backup', methods=['GET', 'POST'])
@login_required
def backup():
    form = CloudCredentialsForm()
    if form.validate_on_submit():
        try:
            auth_manager = AuthenticationManager()

            # Authenticate with iCloud
            if not auth_manager.authenticate_icloud(form.icloud_username.data, form.icloud_password.data):
                flash('Failed to authenticate with iCloud', 'error')
                return render_template('backup.html', form=form)

            # Store credentials in session for 2FA and backup process
            session['icloud_username'] = form.icloud_username.data
            session['icloud_password'] = form.icloud_password.data
            session['aws_access_key'] = form.aws_access_key.data
            session['aws_secret_key'] = form.aws_secret_key.data
            session['s3_bucket'] = form.s3_bucket.data

            # Check if 2FA is required
            if auth_manager.get_icloud_api().requires_2fa:
                return redirect(url_for('two_factor_auth'))

            # If no 2FA required, proceed with AWS authentication
            if not auth_manager.authenticate_aws(form.aws_access_key.data, form.aws_secret_key.data):
                flash('Failed to authenticate with AWS', 'error')
                return render_template('backup.html', form=form)

            return redirect(url_for('start_backup'))

        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
            return render_template('backup.html', form=form)

    return render_template('backup.html', form=form)

@app.route('/2fa', methods=['GET', 'POST'])
@login_required
def two_factor_auth():
    form = TwoFactorForm()

    if form.validate_on_submit():
        try:
            auth_manager = AuthenticationManager()
            auth_manager.authenticate_icloud(session['icloud_username'], session['icloud_password'])

            if auth_manager.get_icloud_api().validate_2fa_code(form.code.data):
                # 2FA successful, proceed with AWS authentication
                if not auth_manager.authenticate_aws(session['aws_access_key'], session['aws_secret_key']):
                    flash('Failed to authenticate with AWS', 'error')
                    return redirect(url_for('backup'))

                return redirect(url_for('start_backup'))
            else:
                flash('Invalid verification code', 'error')
                return render_template('2fa.html', form=form)

        except Exception as e:
            flash(f'Error during 2FA verification: {str(e)}', 'error')
            return render_template('2fa.html', form=form)

    return render_template('2fa.html', form=form)

@app.route('/start_backup')
@login_required
def start_backup():
    try:
        auth_manager = AuthenticationManager()
        auth_manager.authenticate_icloud(session['icloud_username'], session['icloud_password'])
        auth_manager.authenticate_aws(session['aws_access_key'], session['aws_secret_key'])

        backup_manager = BackupManager(
            auth_manager.get_icloud_api(),
            auth_manager.get_s3_client()
        )

        files = backup_manager.list_icloud_files()
        if not files:
            flash('No files found in iCloud', 'warning')
            return redirect(url_for('backup'))

        # Store files in session for the actual backup process
        session['files_to_backup'] = len(files)
        backup_manager.backup_to_s3(session['s3_bucket'], files)

        flash('Backup completed successfully!', 'success')
        return redirect(url_for('backup'))

    except Exception as e:
        flash(f'Error starting backup: {str(e)}', 'error')
        return redirect(url_for('backup'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # For demo purposes, accept any login
        user = User('demo_user')
        login_user(user)
        return redirect(url_for('backup'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)