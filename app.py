from flask import Flask, render_template, request, redirect, url_for, flash, session
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
import os
import jwt
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-key")
bcrypt = Bcrypt(app)

# MongoDB setup
MONGO_URI = "mongodb+srv://bhadramohit:mohit123@cluster0.sy9g9rx.mongodb.net/Python_OAuth?retryWrites=true&w=majority"
client = MongoClient(MONGO_URI)
db = client.get_database()
users_collection = db.users

SECRET_KEY = app.config['SECRET_KEY']

# ---------------------
# JWT decorator
# ---------------------
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get("token")
        if not token:
            flash("Please login first!", "danger")
            return redirect(url_for("login"))
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            flash("Session expired! Please login again.", "danger")
            session.pop("token", None)
            return redirect(url_for("login"))
        except jwt.InvalidTokenError:
            flash("Invalid token! Please login again.", "danger")
            session.pop("token", None)
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ---------------------
# Routes
# ---------------------
@app.route("/")
def index():
    return render_template("index.html")

# Register
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        if not username or not email or not password:
            flash("All fields are required!", "danger")
            return redirect(url_for("register"))

        if "@" not in email or "." not in email:
            flash("Invalid email address!", "danger")
            return redirect(url_for("register"))

        if len(password) < 6:
            flash("Password must be at least 6 characters!", "danger")
            return redirect(url_for("register"))

        if users_collection.find_one({"email": email}):
            flash("Email already registered!", "danger")
            return redirect(url_for("register"))

        hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
        users_collection.insert_one({
            "username": username,
            "email": email,
            "password": hashed_pw
        })

        flash("Account created successfully! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")

# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        if not email or not password:
            flash("Both fields are required!", "danger")
            return redirect(url_for("login"))

        user = users_collection.find_one({"email": email})
        if user and bcrypt.check_password_hash(user["password"], password):
            payload = {
                "email": user["email"],
                "exp": datetime.utcnow() + timedelta(hours=1)
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
            session["token"] = token
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password!", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

# Dashboard
@app.route("/dashboard")
@token_required
def dashboard():
    token = session.get("token")
    decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    user_email = decoded["email"]
    user = users_collection.find_one({"email": user_email})
    return render_template("dashboard.html", user=user)

# Logout
@app.route("/logout")
def logout():
    session.pop("token", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))

# Change password
@app.route("/change-password", methods=["GET", "POST"])
@token_required
def change_password():
    token = session.get("token")
    decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    user_email = decoded["email"]

    if request.method == "POST":
        current = request.form.get("current_password", "").strip()
        new_pw = request.form.get("new_password", "").strip()
        confirm = request.form.get("confirm_password", "").strip()

        if not current or not new_pw or not confirm:
            flash("All fields are required!", "danger")
            return redirect(url_for("change_password"))

        user = users_collection.find_one({"email": user_email})
        if not bcrypt.check_password_hash(user["password"], current):
            flash("Current password is incorrect!", "danger")
            return redirect(url_for("change_password"))

        if new_pw != confirm:
            flash("New passwords do not match!", "danger")
            return redirect(url_for("change_password"))

        if len(new_pw) < 6:
            flash("New password must be at least 6 characters!", "danger")
            return redirect(url_for("change_password"))

        hashed_pw = bcrypt.generate_password_hash(new_pw).decode("utf-8")
        users_collection.update_one({"email": user_email}, {"$set": {"password": hashed_pw}})
        flash("Password updated successfully!", "success")
        return redirect(url_for("dashboard"))

    return render_template("change_password.html")

# ---------------------
# Run app
# ---------------------
if __name__ == "__main__":
    app.run(debug=True)
