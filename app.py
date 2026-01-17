import os
import subprocess
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'vast-ultra-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vast_v2.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- DATABASE MODELS ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    projects = db.relationship('Project', backref='owner', lazy=True)

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scans = db.relationship('Scan', backref='project', lazy=True)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100))
    result = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- AUTH ROUTES ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # 1. Check if the username is already taken
        existing_user = User.query.filter_by(username=username).first()
        
        if existing_user:
            # 2. Provide feedback instead of crashing
            flash('Username already exists. Please choose a different name.', 'error')
            return redirect(url_for('signup'))
        
        # 3. Proceed if the name is unique
        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
        
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.password == request.form['password']:
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('login.html')

# --- PROJECT MANAGEMENT ---
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        p_name = request.form.get('project_name')
        new_p = Project(name=p_name, user_id=current_user.id)
        db.session.add(new_p)
        db.session.commit()
        return redirect(url_for('dashboard'))
    
    user_projects = Project.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', projects=user_projects)

# --- ANALYSIS ENGINE ---
@app.route('/analysis/<int:project_id>', methods=['GET', 'POST'])
@login_required
def analysis(project_id):
    project = Project.query.get_or_404(project_id)
    results = ""
    
    if request.method == 'POST':
        filepath = ""
        # Handle File Upload
        if 'file_upload' in request.files and request.files['file_upload'].filename != '':
            file = request.files['file_upload']
            fname = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], fname)
            file.save(filepath)
        # Handle Paste
        elif request.form.get('code_input'):
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], "pasted_code.c")
            with open(filepath, "w") as f:
                f.write(request.form.get('code_input'))

        if filepath:
            # This is the absolute path to your venv's semgrep
            semgrep_binary = "/home/naqash/VAST_Project/venv/bin/semgrep"
            
            cmd = [
                semgrep_binary, 
                "scan", 
                "--config=auto", 
                "--lang=c", 
                filepath
            ]
            
            # Use subprocess to run the scan
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            # Check if Semgrep actually found something
            if process.stdout.strip():
                results = process.stdout
            else:
                # If stdout is empty, check stderr for errors
                if process.stderr:
                    results = f"System Error:\n{process.stderr}"
                else:
                    results = "Success: No vulnerabilities found."
            
            # Use 'stderr' capture as well, just in case there's an error message
            process = subprocess.run(cmd, capture_output=True, text=True)
            
            # If stdout is empty, check if stderr has a message, else show Success
            if process.stdout.strip():
                results = process.stdout
            else:
                results = "Success: No vulnerabilities found."
            
            # Save Scan to History
            new_scan = Scan(filename=os.path.basename(filepath), result=results, project_id=project.id)
            db.session.add(new_scan)
            db.session.commit()

    return render_template('analysis.html', project=project, results=results)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
