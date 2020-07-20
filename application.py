import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, lookup, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///covid.db")


@app.route("/", methods = ["GET", "POST"])
@login_required
def index():
    """Homepage (Search for Corona-Virus Country)"""

    # User submits country by submitting form via POST
    if request.method == "POST":

        # Ensure country was submitted
        if not request.form.get("country"):
            return apology("must provide country", 403)

        else:
            country = request.form.get("country")
            dictionary = lookup(country)
            name = dictionary["name"]
            confirmed = dictionary["confirmed"]
            recovered = dictionary["recovered"]
            critical = dictionary["critical"]
            deaths = dictionary["deaths"]

            db.execute("INSERT INTO history (country, confirmed, critical, recovered, deaths, user_id) VALUES (:country, :confirmed, :critical, :recovered, :deaths, :user_id)",
            country = country, confirmed = confirmed, critical = critical, recovered = recovered, deaths = deaths, user_id = session["user_id"])

            return render_template("stats.html", name = name, confirmed = confirmed, recovered = recovered, critical = critical, deaths = deaths)


    return render_template("index.html")

@app.route("/history", methods = ["GET"])
@login_required
def history():

    rows = db.execute("SELECT * FROM history WHERE user_id = :user_id GROUP BY country ORDER BY confirmed DESC LIMIT 10" ,
                        user_id = session["user_id"])

    return render_template("history.html", rows = rows)

@app.route("/register", methods = ["GET", "POST"])
def register():
    """Register user"""
    # Forget any registration_attempts
    session.clear()

    #If registering with POST method
    if request.method == "POST":

        # Ensure username is entered
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password is entered and matches
        elif not request.form.get("password"):
            return apology("must enter password", 403)

        # Ensure password matches
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password must match confirmation", 403)
        # Check if username is in database already
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                            username = request.form.get("username"))

        if len(rows) != 0:
            return apology("username already taken", 403)

        #Otherwise insert details into database
        else:
            db.execute("INSERT INTO users (username, hash) VALUES (:username, :password)",
            username = request.form.get("username"), password = generate_password_hash(request.form.get("password"), method ='pbkdf2:sha256', salt_length=8))
            return redirect("/")
    else:
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
