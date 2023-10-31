import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash
import datetime

from helpers import apology, login_required, lookup, usd

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


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]

    transactions_db = db.execute("SELECT symbol, SUM(shares) AS shares, price FROM transactions WHERE user_id = ? GROUP BY symbol", user_id)
    cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
    cash = cash_db[0]["cash"]

    return render_template("index.html", database = transactions_db, cash = cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")

    # Receive the stock symbol and the share in the form
    else:
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        if not symbol:
            return apology("Provide the Symbol")

        # Always leave the received symbol in uppercase
        stock = lookup(symbol.upper())

        if stock == None:
            return apology("Symbol doesn't Exist")

        if shares < 0:
            return apology("Share not Allowed")

        # Calculate the transaction value
        transaction_value = shares * stock["price"]

        # Use session to get user id
        user_id = session["user_id"]

        # See how much money the user has in the bank
        user_cash_db = db.execute("SELECT cash FROM users WHERE id = :id", id=user_id)
        user_cash = user_cash_db[0]["cash"]

        if user_cash < transaction_value:
            return apology("Not enough Money")

        # Update the transaction table value
        uptd_cash = user_cash - transaction_value

        """ UPDATE table_name
        SET column1 = value1, column2 = value2, ...
        WHERE condition; """

        db.execute("UPDATE users SET cash = ? WHERE id = ?", uptd_cash, user_id)

        # Know the date and time the transaction occurred
        date = datetime.datetime.now()

        """ INSERT INTO table_name (column1, column2, column3, ...)
        VALUES (value1, value2, value3, ...); """
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, date) VALUES (?, ?, ?, ?, ?)", user_id, stock["symbol"], shares, stock["price"], date)

        flash("Bought!")

        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    transactions_db = db.execute("SELECT * FROM transactions WHERE user_id = :id", id=user_id)
    return render_template("history.html", transactions = transactions_db)


@app.route("/add_cash", methods=["GET", "POST"])
@login_required
def add_cash():
    """User can add cash"""
    if request.method == "GET":
        return render_template("add.html")
    else:
        new_cash = int(request.form.get("new_cash"))

        if not new_cash:
            return apology("You must give Money")

        user_id = session["user_id"]
        user_cash_db = db.execute("SELECT cash FROM users WHERE id = :id", id=user_id)
        user_cash = user_cash_db[0]["cash"]

        # Update the transaction table value
        uptd_cash = user_cash + new_cash

        """ UPDATE table_name
        SET column1 = value1, column2 = value2, ...
        WHERE condition; """

        db.execute("UPDATE users SET cash = ? WHERE id = ?", uptd_cash, user_id)

        return redirect("/")


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")

    # Receive the stock symbol in the form
    else:
        symbol = request.form.get("symbol")

    if not symbol:
        return apology("Provide the Symbol")

    # Always leave the received symbol in uppercase
    stock = lookup(symbol.upper())

    if stock == None:
        return apology("Symbol doesn't Exist")

    # Returns "quoted.hyml" with name, price and stock symbol
    return render_template("quoted.html", name = stock["name"], price = stock["price"], symbol = stock["symbol"])


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")

    # Getting data from the form
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

    # Returning a warning when the field is blank
    if not username:
        return apology("Provide your Username")

    if not password:
        return apology("Provide your Password")

    if not confirmation:
        return apology("Provide your Confirmation")

    # Returning a warning when the confirmation does not match the password
    if password != confirmation:
        return apology("Passwords don't Match")

    # Storing a "hash" and not the password itself for security
    hash = generate_password_hash(password)

    # Inserting the data in the "users" table
    try:
        new_user = db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash)
    except:
        return apology("Username already exists")

    # After login direct the user to the account
    session["user_id"] = new_user
    return redirect("/")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        user_id = session["user_id"]
        symbols_user = db.execute("SELECT symbol FROM transactions WHERE user_id = :id GROUP BY symbol HAVING SUM(shares) > 0", id=user_id)
        return render_template("sell.html", symbols = [row["symbol"] for row in symbols_user])
    else:
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        if not symbol:
            return apology("Provide the Symbol")

        # Always leave the received symbol in uppercase
        stock = lookup(symbol.upper())

        if stock == None:
            return apology("Symbol doesn't Exist")

        if shares < 0:
            return apology("Share not Allowed")

        # Calculate the transaction value
        transaction_value = shares * stock["price"]

        # Use session to get user id
        user_id = session["user_id"]

        # See how much money the user has in the bank
        user_cash_db = db.execute("SELECT cash FROM users WHERE id = :id", id=user_id)
        user_cash = user_cash_db[0]["cash"]

        user_shares = db.execute("SELECT shares FROM transactions WHERE user_id= :id AND symbol = :symbol GROUP BY symbol", id=user_id, symbol=symbol)
        user_shares_real = user_shares[0]["shares"]

        if shares > user_shares_real:
	        return apology("You do not have this Amount of Shares")

        # Update the transaction table value
        uptd_cash = user_cash + transaction_value

        """ UPDATE table_name
        SET column1 = value1, column2 = value2, ...
        WHERE condition; """

        db.execute("UPDATE users SET cash = ? WHERE id = ?", uptd_cash, user_id)

        # Know the date and time the transaction occurred
        date = datetime.datetime.now()

        """ INSERT INTO table_name (column1, column2, column3, ...)
        VALUES (value1, value2, value3, ...); """
        db.execute("INSERT INTO transactions (user_id, symbol, shares, price, date) VALUES (?, ?, ?, ?, ?)", user_id, stock["symbol"], (-1)*shares, stock["price"], date)

        flash("Sold!")

        return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)