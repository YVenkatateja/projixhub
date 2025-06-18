from flask import Flask, render_template, request, redirect, session, url_for, flash, send_file
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from dotenv import load_dotenv
from pymongo import MongoClient
from bson.objectid import ObjectId
import pandas as pd
import os
from models import db, User  # Assuming ContactMessage unused now
from functools import wraps


# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')
app.permanent_session_lifetime = timedelta(days=7)

# MongoDB setup
mongo_uri = os.getenv("MONGO_URI")
client = MongoClient(mongo_uri)
mongo_db = client['Projixhub']
projects_collection = mongo_db['projects']
comments_collection = mongo_db['comments']
contacts_collection = mongo_db['contact_submissions']
analytics_collection = mongo_db['site_analytics']

# Email setup
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)

ADMIN_USERNAME = os.getenv('ADMIN_USERNAME')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD')

# SQLAlchemy setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'static/profile_pics'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)
with app.app_context():
    db.create_all()

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            print('Checking admin_logged_in:', session.get('admin_logged_in'))
            return redirect(url_for('admin_login'))
        user = User.query.get(session['user_id'])
        if not user or not user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Analytics logging on every non-static, non-admin request
@app.before_request
def log_analytics():
    if request.endpoint not in ['static'] and not request.path.startswith('/admin'):
        analytics_collection.insert_one({
            "ip": request.remote_addr,
            "path": request.path,
            "method": request.method,
            "timestamp": datetime.utcnow()
        })

# Inject logged-in user into templates
@app.context_processor
def inject_user():
    user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
    return {'user': user}

@app.route('/')
def home():
    user = User.query.get(session.get('user_id')) if 'user_id' in session else None
    # Fetch one project per domain for homepage
    dev_project = projects_collection.find_one({'domain': 'Development'})
    data_project = projects_collection.find_one({'domain': 'Data Science'})
    iot_project = projects_collection.find_one({'domain': 'IoT'})
    projects = [p for p in [dev_project, data_project, iot_project] if p]
    comments = list(comments_collection.find().limit(10))
    return render_template('base.html', projects=projects, user=user, comments=comments)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        profile_pic_file = request.files['profile_pic']
        pic_path = os.path.join(app.config['UPLOAD_FOLDER'], profile_pic_file.filename)
        profile_pic_file.save(pic_path)

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please log in.', 'error')
            return redirect(url_for('login'))

        new_user = User(name=name, email=email, password=password, profile_pic=profile_pic_file.filename)
        db.session.add(new_user)
        db.session.commit()
        session['user_id'] = new_user.id
        flash('Signup successful! Welcome!', 'success')
        return redirect('/')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email, password=password).first()
        if user:
            session.permanent = True
            session['user_id'] = user.id
            session['user_name'] = user.name
            session['logged_in'] = True
            send_email(user.email, user.name)
            flash('Logged in successfully!', 'success')
            return redirect('/')
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/project/<project_id>')
def project_detail(project_id):
    try:
        project = projects_collection.find_one({'_id': ObjectId(project_id)})
        if not project:
            return "Project not found", 404
    except Exception:
        return "Invalid project ID", 400
    return render_template('project_detail.html', project=project)

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    project_name = request.args.get('project')
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form.get('phone')
        description = request.form['description']

        # Validate inputs
        if not all([name, email, phone, description]):
            flash("All fields are required!", "error")
            return redirect(url_for('contact', project=project_name))
        if '@' not in email:
            flash("Invalid email address!", "error")
            return redirect(url_for('contact', project=project_name))
        if len(description) < 10 or len(description) > 500:
            flash("Message should be between 10 to 500 characters!", "error")
            return redirect(url_for('contact', project=project_name))
        if len(name) < 3 or len(name) > 50:
            flash("Name must be between 3 and 50 characters!", "error")
            return redirect(url_for('contact', project=project_name))

        contact_data = {
            "name": name,
            "email": email,
            "phone": phone,
            "project": project_name,
            "message": description,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        contacts_collection.insert_one(contact_data)

        # Auto-reply only to user (no admin emails)
        auto_reply = Message(
            subject='Thanks for reaching out to ProjectHub!',
            sender=app.config['MAIL_USERNAME'],
            recipients=[email],
            body=f"Hi {name},\n\nThanks for your interest in '{project_name}'. We'll get back to you soon.\n\n- ProjectHub Team"
        )
        mail.send(auto_reply)

        flash('Message sent successfully! Confirmation email sent.', 'success')
        return redirect(url_for('thank_you'))

    return render_template('contact.html', project_name=project_name)

@app.route('/thank_you')
def thank_you():
    return render_template('thank_you.html')

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/portfolio/venkata-teja')
def portfolio_teja():
    return render_template('portfolio_teja.html')

@app.route('/portfolio/leela-krishna')
def portfolio_leela():
    return render_template('portfolio_leela.html')

@app.route('/portfolio/john-paul')
def portfolio_john():
    return render_template('portfolio_john.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')
# Protected domain views for logged-in users only
import random

import random

@app.route("/domains")
def show_domains():
    # Get all unique domain names from MongoDB projects collection
    unique_domains = projects_collection.distinct("domain")

    # Define static animations and descriptions for known domains
    DOMAIN_DETAILS = {
        "Development": {
            "description": "Web, app, and software development projects.",
            "animation": "https://assets1.lottiefiles.com/packages/lf20_tno6cg2w.json"
        },
        "Data Science": {
            "description": "Machine learning, data analysis, and AI projects.",
            "animation": "https://assets3.lottiefiles.com/packages/lf20_jtbfg2nb.json"
        },
        "Cyber Security": {
            "description": "Security, cryptography, and ethical hacking projects.",
            "animation": "https://lottie.host/edd965ac-2cdd-4480-a29c-ac92482adc9d/7UVRoAppyf.json"
        },
        "IoT": {
            "description": "Smart devices, sensors, and automation projects.",
            "animation": "https://assets3.lottiefiles.com/packages/lf20_pwohahvd.json"
        },
        "Deep Learning": {
            "description": "Neural networks and advanced AI applications.",
            "animation": "https://lottie.host/066e32ba-b28f-488e-a310-06cac83557e5/RPswh2Gb75.json"
        },
        "Machine Learning": {
            "description": "Models and algorithms for learning from data.",
            "animation": "https://lottie.host/0793abf3-de76-4dcd-a7ce-e30fc24f4586/X23pWVuQJX.json"
        },
        # Default fallback
        "default": {
            "description": "Exciting projects in this domain.",
            "animations": [
                "https://lottie.host/26ce02b7-4494-4497-959a-aeba74e34841/QlswFdRhJL.json",
                "https://lottie.host/967131dd-5913-4cca-84e1-7a78ae7da738/35OXjhhJRu.json",
                "https://lottie.host/85612fa6-6395-4dd3-a977-2ca9e765f167/BFUxR6euqB.json",
                "https://lottie.host/8d9ae477-9d15-4d38-aacf-8fb5df80f381/FLC7Mqf9xs.json",
                "https://lottie.host/0793abf3-de76-4dcd-a7ce-e30fc24f4586/X23pWVuQJX.json",
                "https://lottie.host/066e32ba-b28f-488e-a310-06cac83557e5/RPswh2Gb75.json",
                "https://lottie.host/edd965ac-2cdd-4480-a29c-ac92482adc9d/7UVRoAppyf.json"
            ]
        }
    }

    domains = {}
    for domain in unique_domains:
        if domain in DOMAIN_DETAILS:
            details = DOMAIN_DETAILS[domain]
            animation = details.get("animation")  # Should be a string URL
            description = details.get("description", "No description available.")
        else:
            default_details = DOMAIN_DETAILS["default"]
            animation = random.choice(default_details["animations"])
            description = default_details["description"]

        domains[domain] = {
            "title": domain,
            "description": description,
            "animation": animation,
            "url": f"/domain/{domain}"
        }

    return render_template("domains.html", domains=domains)


@app.route('/domain/<domain_name>')
def domain_projects(domain_name):
    if not session.get('logged_in'):
        flash("Please log in to view domain projects.", "warning")
        return redirect(url_for('login'))

    domain_name_lower = domain_name.lower()
    projects = list(projects_collection.find({'domain': {'$regex': f'^{domain_name_lower}$', '$options': 'i'}}))

    # Provide domain animation URLs same as above
    domain_animations = {
        'development': 'https://assets2.lottiefiles.com/packages/lf20_jtbfg2nb.json',
        'data science': 'https://assets10.lottiefiles.com/packages/lf20_u25cckyh.json',
        'iot': 'https://assets6.lottiefiles.com/packages/lf20_V9t630.json',
        'machine learning': 'https://assets1.lottiefiles.com/packages/lf20_ydo1amjm.json',
        'cyber security': 'https://assets1.lottiefiles.com/packages/lf20_tno6cg2w.json'
    }
    animation_url = domain_animations.get(domain_name_lower, 'https://assets10.lottiefiles.com/packages/lf20_zrqthn6o.json')

    return render_template('domain_view.html', projects=projects, domain=domain_name, animation_url=animation_url)

# --------------------------
# Admin routes
# --------------------------

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session.permanent = True  # <=== ADD THIS LINE
            session['admin_logged_in'] = True
            flash('Admin login successful.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.', 'danger')
    return render_template('admin/login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash('Admin logged out.', 'info')
    return redirect(url_for('admin_login'))

def log_user_activity(action_type, username, email):
    file_path = "user_activity_log.xlsx"
    log_entry = {
        "Username": username,
        "Email": email,
        "Action": action_type,  # 'signup' or 'login'
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    if os.path.exists(file_path):
        df = pd.read_excel(file_path)
        df = pd.concat([df, pd.DataFrame([log_entry])], ignore_index=True)
    else:
        df = pd.DataFrame([log_entry])

    df.to_excel(file_path, index=False)
    
@app.route('/admin/dashboard')
def admin_dashboard():
    total_contacts = contacts_collection.count_documents({})
    total_users = User.query.count()
    total_projects = projects_collection.count_documents({})
    return render_template('admin/dashboard.html', contacts=total_contacts, users=total_users, projects=total_projects)

@app.route('/view_contacts')
def view_contacts():
    if not session.get('admin_logged_in'):
        flash("Please log in as admin.", "error")
        return redirect(url_for('admin_login'))

    contacts = list(contacts_collection.find({}, {'_id': 0}))
    return render_template('view_contacts.html', contacts=contacts)


@app.route('/download_contacts')
def download_contacts():
    try:
        contacts = list(contacts_collection.find())

        if not contacts:
            flash("No contact data to download.", "warning")
            return redirect(url_for('view_contacts'))

        df = pd.DataFrame(contacts)

        # Drop MongoDB _id if present
        if '_id' in df.columns:
            df.drop(columns=['_id'], inplace=True)

        # Use absolute file path
        base_dir = os.path.abspath(os.path.dirname(__file__))
        download_dir = os.path.join(base_dir, 'downloads')
        os.makedirs(download_dir, exist_ok=True)
        file_path = os.path.join(download_dir, 'contact_submissions.xlsx')

        # Save to Excel
        df.to_excel(file_path, index=False, engine='openpyxl')

        # Debug: Confirm path exists before sending
        if not os.path.exists(file_path):
            flash("File was not created. Check folder permissions.", "danger")
            return redirect(url_for('view_contacts'))

        # Send file
        return send_file(
            file_path,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            download_name='contact_submissions.xlsx',
            as_attachment=True
        )

    except Exception as e:
        flash(f"An unexpected error occurred: {str(e)}", "danger")
        return redirect(url_for('view_contacts'))


@app.route('/admin/analytics')
def admin_analytics():
    if not session.get('admin_logged_in'):
        flash("Access denied. Please log in as admin.", "error")
        return redirect(url_for('admin_login'))

    # Prepare data for daily views
    pipeline = [
        {
            '$group': {
                '_id': {'$dateToString': {'format': "%Y-%m-%d", 'date': "$timestamp"}},
                'count': {'$sum': 1}
            }
        },
        {'$sort': {'_id': 1}}
    ]
    daily_data = list(analytics_collection.aggregate(pipeline))

    # Data for most visited paths
    top_paths = analytics_collection.aggregate([
        {'$group': {'_id': "$path", 'count': {'$sum': 1}}},
        {'$sort': {'count': -1}},
        {'$limit': 5}
    ])
    top_paths = list(top_paths)

    return render_template("admin_analytics.html", daily_data=daily_data, top_paths=top_paths)




from pymongo import DESCENDING

@app.route('/user_logs')
def user_logs():
    if not session.get('admin_logged_in'):
        flash("Access denied. Please log in as admin.", "error")
        return redirect(url_for('admin_login'))

    try:
        df = pd.read_excel("user_activity_log.xlsx")

        # Convert 'Timestamp' column to datetime
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])

        # Sort by timestamp descending and keep only the latest log per username
        df = df.sort_values('Timestamp', ascending=False)
        df = df.drop_duplicates(subset='Username', keep='first')

        logs = df.to_dict(orient='records')
    except FileNotFoundError:
        logs = []

    return render_template("user_logs.html", logs=logs)


from datetime import datetime

def login():
    # after verifying user credentials
    user['last_login'] = datetime.now()
    user['notified_stages'] = []  # reset if needed
    db.users.update_one({"email": user['email']}, {"$set": user}, upsert=True)

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

def send_email(to_email, name):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "🚀 Discover Projects on ProjixHub!"
    msg["From"] = "projixhub@gmail.com"
    msg["To"] = to_email

    html = f"""
    <html>
      <body>
        <h2>Hello {name},</h2>
        <p>Haven't been back in a while? Discover top student projects in Web, IoT, and Data Science-Etc...</p>
        <img src="https://i.imgur.com/yourimageid.png"" width="100%" />
        <p><a href="https://projixhub.com" style="padding:10px 20px;background:#28a745;color:white;text-decoration:none;">Visit Now</a></p>
      </body>
    </html>
    """
    msg.attach(MIMEText(html, "html"))

    server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
    server.login("projixhub@gmail.com", "vosp jipm ozyn bvyz")
    server.sendmail(msg["From"], to_email, msg.as_string())
    server.quit()

def check_and_send_promos():
    now = datetime.now()
    users = db.users.find({})  # or read from Excel

    for user in users:
        if 'last_login' not in user:
            continue
        last_login = user['last_login']
        stages = user.get('notified_stages', [])

        delays = {
            '3hr': timedelta(hours=3),
            '1d': timedelta(days=1),
            '4d': timedelta(days=4)
        }

        for stage, delay in delays.items():
            if stage not in stages and now >= last_login + delay:
                send_email(user['email'], user['username'])
                stages.append(stage)
                db.users.update_one({"email": user['email']}, {"$set": {"notified_stages": stages}})

from flask_mail import Message
from app import mail  # or however you initialized Flask-Mail

def send_login_email(user_email, user_name):
    subject = "Welcome back to Project Hub!"
    html = f"""
    <html>
      <body>
        <h2>Hello {user_name},</h2>
        <p>Welcome back to Project Hub!</p>
        <p>We are glad to see you again. Here is your account address: {user_email}</p>
        <p>Enjoy exploring amazing projects.</p>
        <img src="https://i.imgur.com/yourimageid.png" width="100%" />
        <p>Best regards,<br>Project Hub Team</p>
      </body>
    </html>
    """
    msg = Message(subject=subject, recipients=[user_email], html=html)
    mail.send(msg)

# --------------------------
# Run the app
# --------------------------
if __name__ == '__main__':
    app.run(debug=True)
