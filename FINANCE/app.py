import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    transactions_db = db.execute(
        "SELECT symbol, SUM(shares) AS shares, price FROM transactions WHERE user_id = ?",
        user_id,
    )
    cash_db = db.execute("SELECT cash FROM users WHERE id=?", user_id)
    cash = cash_db[0]["cash"]
    return render_template("index.html", database=transactions_db, cash=cash)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure stock was submitted
        if not request.form.get("symbol"):
            return apology("must provide symbol")

        # Ensure shares was submitted
        elif not request.form.get("shares"):
            return apology("must provide shares")

        # Ensure shares is greater than 0
        elif int(request.form.get("shares")) < 0:
            return apology("must provide a valid number of shares")

        # Ensure shock exists
        if not request.form.get("symbol"):
            return apology("must provide an existing symbol")

        # Lookup function
        symbol = request.form.get("symbol").upper()
        stock = lookup(symbol)
        if stock is None:
            return apology("symbol does not exist")

        # Value of transaction
        shares = int(request.form.get("shares"))
        transactionb = shares * stock["price"]

        # Check if user has enough cash for transaction
        user_cash = db.execute(
            "SELECT cash FROM users WHERE id=:id", id=session["user_id"]
        )
        cash = user_cash[0]["cash"]

        # Subtract user_cash by value of transaction
        updt_cash = cash - transactionb

        if updt_cash < 0:
            return apology("you do not have enough cash")

        # Update how much left in his account (cash) after the transaction
        db.execute(
            "UPDATE users SET cash=:updt_cash WHERE id=:id",
            updt_cash=updt_cash,
            id=session["user_id"],
        )
        # Update de transactions table
        db.execute(
            "INSERT INTO transactions (user_id, symbol, shares, price) VALUES (:user_id, :symbol, :shares, :price)",
            user_id=session["user_id"],
            symbol=stock["symbol"],
            shares=shares,
            price=stock["price"],
        )
        flash("Bought!")
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    transactions_db = db.execute(
        "SELECT * FROM transactions WHERE user_id= :id", id=user_id
    )
    return render_template("history.html")


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = :username",
            username=request.form.get("username"),
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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
    else:
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Must give symbol")
        stock = lookup(symbol.upper())

        if stock == None:
            return apology("Symbol does not exist")
        return render_template(
            "quoted.html",
            name=stock["name"],
            price=stock["price"],
            symbol=stock["symbol"],
        )


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (submitting the register form)
    if request.method == "POST":
        # ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # ensure passwords match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        # save username and password hash in variables
        username = request.form.get("username")
        hash = generate_password_hash(request.form.get("password"))

        # Query database to ensure username isn't already taken
        rows = db.execute(
            "SELECT * FROM users WHERE username = :username", username=username
        )
        if len(rows) != 0:
            return apology("username is already taken", 400)

        # insert username and hash into database
        db.execute(
            "INSERT INTO users (username, hash) VALUES (:username, :hash)",
            username=username,
            hash=hash,
        )

        # redirect to login page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == "GET":
        user_id = session["user_id"]
        symbols_user = db.execute(
            "SELECT symbol FROM transactions WHERE user_id = :id GROUP BY symbol HAVING SUM(shares)>0"
        )
        return render_template(
            "sell.html", symbols=[row["symbol"] for row in symbols_user]
        )

    else:
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        if not symbol:
            return apology("Must give symbol")
        stock = lookup(symbol.upper())
        if stock == None:
            return apology("Symbol does not exist")
        if shares < 0:
            return apology("Share not allowed")

        transaction_value = shares * stock["price"]
        user_id = session["user_id"]
        user_cash_db = db.execute("SELECT cash FROM users WHERE id = :id", id=user_id)
        user_cash = user_cash_db[0]["cash"]

        user_shares = db.execute(
            "SELECT shares FROM transactions WHERE id=:id AND symbol= :symbol GROUP BY symbol",
            id=user_id,
            symbol=symbol,
        )
        user_shares_real = user_shares[0]["shares"]
        if shares > user_shares_real:
            return apology("You do not have this amount of shares")

        uptd_cash = user_cash + transaction_value

        db.execute("UPDATE users SET cash = ? WHERE id = ?", user_id)
        date = datetime.datetime.now()
        db.execute(
            "INSERT INTO transactions(user_id,symbol,shares,price,date) VALUES(?,?,?,?,?)",
            user_id,
            stock["symbol"],
            (-1) * shares,
            stock["price"],
            date,
        )
        flash("sold!")
        return redirect("/")
