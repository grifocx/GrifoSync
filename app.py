from flask import Flask, render_template, flash, redirect, url_for, request, session
from datetime import timedelta
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from flask_migrate import Migrate
import os
import logging
from models import db, User, BackupJob, CredentialVault
from datetime import datetime
from icloud_to_s3.auth import AuthenticationManager
from icloud_to_s3.backup import BackupManager
from icloud_to_s3.utils import handle_2fa_challenge, validate_bucket_name

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Load and validate database URL
database_url = os.environ.get('DATABASE_URL')
if not database_url:
    raise ValueError("DATABASE_URL environment variable is not set")
logger.info("Database URL is configured")

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', os.urandom(24))
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

try:
    # Initialize SQLAlchemy
    db.init_app(app)
    logger.info("SQLAlchemy initialized successfully")

    # Initialize Flask-Migrate
    migrate = Migrate(app, db)
    logger.info("Flask-Migrate initialized successfully")
except Exception as e:
    logger.error(f"Error initializing database: {str(e)}")
    raise

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password',
                                   validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists. Please choose another one.')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already registered. Please use another one.')

class BackupCredentialsForm(FlaskForm):
    icloud_username = StringField('iCloud Username', validators=[DataRequired(), Email()])
    icloud_password = PasswordField('iCloud Password', validators=[DataRequired()])
    aws_access_key = StringField('AWS Access Key', validators=[DataRequired(), Length(min=20, max=20)])
    aws_secret_key = PasswordField('AWS Secret Key', validators=[DataRequired(), Length(min=40)])
    s3_bucket = StringField('S3 Bucket Name', validators=[DataRequired()])
    submit = SubmitField('Start Backup')

class TwoFactorForm(FlaskForm):
    code = StringField('Verification Code', validators=[DataRequired()])
    submit = SubmitField('Verify')

class SaveCredentialsForm(FlaskForm):
    credential_type = SelectField('Credential Type', 
                                choices=[('icloud', 'iCloud'), ('aws', 'AWS')],
                                validators=[DataRequired()])
    submit = SubmitField('Save Credentials')


@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', current_user=current_user)

@app.route('/start_backup', methods=['GET', 'POST'])
@login_required
def start_backup():
    form = BackupCredentialsForm()

    if form.validate_on_submit():
        try:
            auth_manager = AuthenticationManager()

            # Validate iCloud credentials
            if not auth_manager.authenticate_icloud(form.icloud_username.data, form.icloud_password.data):
                flash('Failed to authenticate with iCloud', 'error')
                return render_template('backup_credentials.html', form=form)

            # Store credentials temporarily for 2FA process
            session['temp_icloud_username'] = form.icloud_username.data
            session['temp_icloud_password'] = form.icloud_password.data
            session['temp_aws_access_key'] = form.aws_access_key.data
            session['temp_aws_secret_key'] = form.aws_secret_key.data
            session['temp_s3_bucket'] = form.s3_bucket.data

            # If 2FA is required, redirect to 2FA page
            if auth_manager.get_icloud_api().requires_2fa:
                return redirect(url_for('two_factor_auth'))

            # If no 2FA required, validate AWS credentials
            if not auth_manager.authenticate_aws(form.aws_access_key.data, form.aws_secret_key.data):
                flash('Failed to authenticate with AWS', 'error')
                return render_template('backup_credentials.html', form=form)

            # Proceed with backup
            return redirect(url_for('perform_backup'))

        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
            return render_template('backup_credentials.html', form=form)

    return render_template('backup_credentials.html', form=form)

@app.route('/2fa', methods=['GET', 'POST'])
@login_required
def two_factor_auth():
    form = TwoFactorForm()

    if form.validate_on_submit():
        try:
            auth_manager = AuthenticationManager()

            # Get credentials from session
            icloud_username = session.get('temp_icloud_username')
            icloud_password = session.get('temp_icloud_password')

            if not all([icloud_username, icloud_password]):
                flash('Session expired. Please enter your credentials again.', 'error')
                return redirect(url_for('start_backup'))

            # Authenticate with iCloud using temporary credentials
            auth_manager.authenticate_icloud(icloud_username, icloud_password)

            if auth_manager.get_icloud_api().validate_2fa_code(form.code.data):
                # 2FA successful, proceed with backup
                return redirect(url_for('perform_backup'))
            else:
                flash('Invalid verification code', 'error')
                return render_template('2fa.html', form=form)

        except Exception as e:
            # Clear sensitive data if there's an error
            session.pop('temp_icloud_username', None)
            session.pop('temp_icloud_password', None)
            session.pop('temp_aws_access_key', None)
            session.pop('temp_aws_secret_key', None)
            session.pop('temp_s3_bucket', None)

            flash(f'Error during 2FA verification: {str(e)}', 'error')
            return render_template('2fa.html', form=form)

    return render_template('2fa.html', form=form)

@app.route('/perform_backup')
@login_required
def perform_backup():
    try:
        # Create a new backup job
        backup_job = BackupJob(
            user_id=current_user.id,
            status='in_progress',
            start_time=datetime.utcnow()
        )
        db.session.add(backup_job)
        db.session.commit()

        auth_manager = AuthenticationManager()

        # Get credentials from session and immediately clear them
        icloud_username = session.pop('temp_icloud_username', None)
        icloud_password = session.pop('temp_icloud_password', None)
        aws_access_key = session.pop('temp_aws_access_key', None)
        aws_secret_key = session.pop('temp_aws_secret_key', None)
        s3_bucket = session.pop('temp_s3_bucket', None)

        if not all([icloud_username, icloud_password, aws_access_key, aws_secret_key, s3_bucket]):
            raise ValueError("Missing required credentials")

        # Authenticate with temporary credentials
        auth_manager.authenticate_icloud(icloud_username, icloud_password)
        auth_manager.authenticate_aws(aws_access_key, aws_secret_key)

        backup_manager = BackupManager(
            auth_manager.get_icloud_api(),
            auth_manager.get_s3_client()
        )

        files = backup_manager.list_icloud_files()
        if not files:
            backup_job.status = 'failed'
            backup_job.error_message = 'No files found in iCloud'
            db.session.commit()
            flash('No files found in iCloud', 'warning')
            return redirect(url_for('dashboard'))

        # Update backup job with total files
        backup_job.total_files = len(files)
        db.session.commit()

        # Perform backup
        backup_manager.backup_to_s3(s3_bucket, files)

        # Update backup job status
        backup_job.status = 'completed'
        backup_job.processed_files = len(files)
        backup_job.end_time = datetime.utcnow()
        db.session.commit()

        flash('Backup completed successfully!', 'success')
        return redirect(url_for('dashboard'))

    except Exception as e:
        if 'backup_job' in locals():
            backup_job.status = 'failed'
            backup_job.error_message = str(e)
            backup_job.end_time = datetime.utcnow()
            db.session.commit()

        flash(f'Error during backup: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/save_credentials', methods=['POST'])
@login_required
def save_credentials():
    form = SaveCredentialsForm()
    if form.validate_on_submit():
        try:
            # Get credentials from session
            credentials = {}
            if form.credential_type.data == 'icloud':
                credentials = {
                    'username': session.get('temp_icloud_username'),
                    'password': session.get('temp_icloud_password')
                }
            elif form.credential_type.data == 'aws':
                credentials = {
                    'access_key': session.get('temp_aws_access_key'),
                    'secret_key': session.get('temp_aws_secret_key'),
                    's3_bucket': session.get('temp_s3_bucket')
                }

            # Create or update credential vault entry
            credential = CredentialVault.query.filter_by(
                user_id=current_user.id,
                credential_type=form.credential_type.data
            ).first()

            if not credential:
                credential = CredentialVault(
                    user_id=current_user.id,
                    credential_type=form.credential_type.data
                )
                db.session.add(credential)

            credential.encrypt_credentials(credentials)
            db.session.commit()

            flash(f'{form.credential_type.data.upper()} credentials saved successfully!', 'success')
        except Exception as e:
            flash(f'Error saving credentials: {str(e)}', 'error')

    return redirect(url_for('dashboard'))

@app.route('/manage_credentials')
@login_required
def manage_credentials():
    stored_credentials = CredentialVault.query.filter_by(user_id=current_user.id).all()
    return render_template('manage_credentials.html', credentials=stored_credentials)

@app.route('/delete_credentials/<int:credential_id>', methods=['POST'])
@login_required
def delete_credentials(credential_id):
    credential = CredentialVault.query.filter_by(id=credential_id, user_id=current_user.id).first()
    if credential:
        db.session.delete(credential)
        db.session.commit()
        flash('Credentials deleted successfully', 'success')
    else:
        flash('Credentials not found', 'error')
    return redirect(url_for('manage_credentials'))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Get port from environment variable or default to 8080
    port = int(os.environ.get('PORT', 8080))

    try:
        # Create tables if they don't exist
        with app.app_context():
            db.create_all()
            logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Error creating database tables: {str(e)}")
        raise

    app.run(host='0.0.0.0', port=port, debug=True)