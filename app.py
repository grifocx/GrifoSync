from flask import Flask, render_template, flash, redirect, url_for, request, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from flask_migrate import Migrate
import os
from models import db, User, BackupJob
from datetime import datetime
from icloud_to_s3.auth import AuthenticationManager
from icloud_to_s3.backup import BackupManager
from icloud_to_s3.utils import handle_2fa_challenge


app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize SQLAlchemy
db.init_app(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

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

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = CloudCredentialsForm()
    if form.validate_on_submit():
        try:
            auth_manager = AuthenticationManager()

            # Authenticate with iCloud
            if not auth_manager.authenticate_icloud(form.icloud_username.data, form.icloud_password.data):
                flash('Failed to authenticate with iCloud', 'error')
                return render_template('dashboard.html', form=form)

            # Check if 2FA is required
            if auth_manager.get_icloud_api().requires_2fa:
                return redirect(url_for('two_factor_auth'))

            # If no 2FA required, proceed with AWS authentication
            if not auth_manager.authenticate_aws(form.aws_access_key.data, form.aws_secret_key.data):
                flash('Failed to authenticate with AWS', 'error')
                return render_template('dashboard.html', form=form)

            return redirect(url_for('start_backup'))

        except Exception as e:
            flash(f'Error: {str(e)}', 'error')
            return render_template('dashboard.html', form=form)

    return render_template('dashboard.html', form=form)


@app.route('/2fa', methods=['GET', 'POST'])
@login_required
def two_factor_auth():
    form = TwoFactorForm()

    if form.validate_on_submit():
        try:
            auth_manager = AuthenticationManager()
            
            #Using session data here is not ideal but follows original code logic
            auth_manager.authenticate_icloud(session.get('icloud_username'), session.get('icloud_password'))

            if auth_manager.get_icloud_api().validate_2fa_code(form.code.data):
                # 2FA successful, proceed with AWS authentication
                if not auth_manager.authenticate_aws(session.get('aws_access_key'), session.get('aws_secret_key')):
                    flash('Failed to authenticate with AWS', 'error')
                    return redirect(url_for('dashboard'))

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
        # Create a new backup job
        backup_job = BackupJob(user_id=current_user.id, status='in_progress')
        db.session.add(backup_job)
        db.session.commit()

        auth_manager = AuthenticationManager()
        auth_manager.authenticate_icloud(session.get('icloud_username'), session.get('icloud_password'))
        auth_manager.authenticate_aws(session.get('aws_access_key'), session.get('aws_secret_key'))

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

        # Store files in session for the actual backup process
        session['files_to_backup'] = len(files)
        backup_manager.backup_to_s3(session.get('s3_bucket'), files)

        # Update backup job status
        backup_job.status = 'completed'
        backup_job.processed_files = len(files)
        backup_job.end_time = datetime.utcnow()
        db.session.commit()

        flash('Backup completed successfully!', 'success')
        return redirect(url_for('dashboard'))

    except Exception as e:
        # Update backup job with error
        if 'backup_job' in locals():
            backup_job.status = 'failed'
            backup_job.error_message = str(e)
            backup_job.end_time = datetime.utcnow()
            db.session.commit()

        flash(f'Error starting backup: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)