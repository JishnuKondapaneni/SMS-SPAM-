from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline

# Initialize the Flask application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the database and login manager
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # Ensure that users will be redirected to the login page

# User model for authentication
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# User loader for login management
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Load and preprocess the spam detection dataset
url = "https://raw.githubusercontent.com/justmarkham/pycon-2016-tutorial/master/data/sms.tsv"
data = pd.read_csv(url, sep='\t', header=None, names=['label', 'message'])
X = data['message']
y = data['label'].map({'ham': 0, 'spam': 1})

# Train the Naive Bayes spam detection model
model = make_pipeline(CountVectorizer(), MultinomialNB())
model.fit(X, y)

# Routes for the application

# Home page (Spam detection form)
@app.route('/', methods=['GET', 'POST'])
def index():
    if current_user.is_authenticated:
        result = ""
        input_message = ""  # Store the input message

        if request.method == 'POST':
            input_message = request.form['sms']  # Get user input
            prediction = model.predict([input_message])[0]
            result = "Spam" if prediction == 1 else "Not Spam"

        return render_template('index.html', result=result, input_message=input_message)  # Pass both values
    else:
        return redirect(url_for('login'))


# Register page
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
            return redirect(url_for('register'))
        
        # Hash the password and create the new user
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))  # Redirect to home page after successful login
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

# Forgot password page
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Password reset instructions have been sent to your email.', 'info')
        else:
            flash('Username not found.', 'error')
    return render_template('forgot_password.html')

# Dashboard page (Accessible only after login)
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

# Logout page
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))  # Ensure that logout redirects to login page

# Initialize the database
with app.app_context():
    db.create_all()

# Run the application
if __name__ == '__main__':
    app.run(debug=True)
