import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/github.io/")
@login_required
def index():
    """Show portfolio of stocks"""
    try:
        buys = db.execute("SELECT symbol, name, SUM(shares), price FROM buys WHERE user_id = ? GROUP BY name", session["user_id"])
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    except:
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

    delete = []
    for i in range(0, len(buys)):
        try:
            sold = db.execute("SELECT symbol, name, SUM(shares), price FROM sells WHERE user_id = ? AND symbol = ? GROUP BY name",
                              session["user_id"], buys[i]["symbol"])
            buys[i]["SUM(shares)"] = buys[i]["SUM(shares)"] - sold[0]["SUM(shares)"]
            if buys[i]["SUM(shares)"] == 0:
                delete.append(i)
                continue
        except:
            continue

    # reverse list to delete last element first
    delete.reverse()

    try:
        for each in delete:
            del buys[each]
    except:
        print("okay")

    # absolute price
    sum = 0
    i = 0
    for each in buys:
        stock = lookup(buys[i]["symbol"])
        buys[i]["abs_price"] = usd(stock["price"] * buys[i]["SUM(shares)"])
        sum += (stock["price"] * buys[i]["SUM(shares)"])
        buys[i]["price"] = usd(stock["price"])
        i += 1

    return render_template("index.html", buys=buys, cash=usd(cash[0]["cash"]), total=usd(cash[0]["cash"]+sum), delete=delete)
    return apology("Homepage")


@app.route("/github.io/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        stock = lookup(request.form.get("symbol"))

        # check if stock is legit
        if stock == None:
            return apology("Stock doesn't exist")

        # check if shares num is legit
        shares = int(request.form.get("shares"))
        if not shares > 0:
            return apology("Input is not a positive Integer")

        # look if user has enough cash
        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        if user[0]["cash"] < shares * stock["price"]:
            return apology("not enough cash for transaction")

        db.execute("INSERT INTO buys (user_id, username, price, symbol, shares, name) VALUES(?, ?, ?, ?, ?, ?)",
                   user[0]["id"], user[0]["username"], stock["price"], stock["symbol"], shares, stock["name"])

        db.execute("UPDATE users SET cash = ? WHERE id = ?", user[0]["cash"] - (shares * stock["price"]), user[0]["id"])

        # Redirect user to home page
        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/github.io/history")
@login_required
def history():
    """Show history of transactions"""
    buys = db.execute("SELECT * FROM buys WHERE user_id = ?", session["user_id"])

    # get usd value of price
    i = 0
    for each in buys:
        buys[i]["price"] = usd(buys[i]["price"])
        i += 1

    sells = db.execute("SELECT * FROM sells WHERE user_id = ?", session["user_id"])

    # get usd value of price
    i = 0
    for each in sells:
        sells[i]["price"] = usd(sells[i]["price"])
        i += 1

    return render_template("history.html", buys=buys, sells=sells)


@app.route("/github.io/login", methods=["GET", "POST"])
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


@app.route("/github.io/logout")
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
    if request.method == "POST":
        # get stock
        stock = lookup(request.form.get("symbol"))
        if stock != None:
            return render_template("quoted.html", name=stock["name"], price=usd(stock["price"]), symbol=stock["symbol"])
        return apology("stock doesn't exist")

    else:
        return render_template("quote.html")


@app.route("/github.io/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        # look if passwords match
        if not request.form.get("password") == request.form.get("confirmation"):
            return apology("Passwords don't match")

        # look if username is empty
        if len(request.form.get("username")) == 0:
            return apology("Type in a username", 400)

        # look if username already taken
        check_username = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
        if len(check_username) != 0:
            return redirect("Username is already taken", 400)

        username = request.form.get("username")
        password = generate_password_hash(request.form.get("password"), 'pbkdf2:sha256', 8)
        # create user
        db.execute("INSERT INTO users (username, hash, cash) VALUES(?, ?, ?)", username, password, 10000)

        # Remember which user has logged in
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/github.io/changepw", methods=["GET", "POST"])
@login_required
def changepw():
    """change pw of user"""
    if request.method == "POST":

        rows = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        if not check_password_hash(rows[0]["hash"], request.form.get("old_password")):
            return apology("invalid password", 403)

        # look if passwords match
        if not request.form.get("new_password") == request.form.get("new_password2"):
            return apology("Passwords don't match")

        password = generate_password_hash(request.form.get("new_password"), 'pbkdf2:sha256', 8)
        # Update password
        db.execute("UPDATE users SET hash = ? WHERE id = ?", password, rows[0]["id"])

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("changepw.html")

@app.route("/github.io/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    symbols = db.execute("SELECT symbol FROM buys WHERE user_id = ? AND shares != 0 GROUP BY symbol", session["user_id"])

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        stock = lookup(symbol)

        if not shares > 0:
            return apology("No positive integer")

        #shares_bought = db.execute("SELECT shares FROM buys WHERE user_id = ? AND symbol = ? GROUP BY name", session["user_id"], symbol)
        shares_bought = db.execute(
            "SELECT symbol, name, SUM(shares), price FROM buys WHERE user_id = ? AND symbol = ? GROUP BY name", session["user_id"], symbol)
        if shares_bought[0]["SUM(shares)"] < shares:
            return apology("You don't own that many shares")

        # update cash
        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])
        db.execute("UPDATE users SET cash = ? WHERE id = ?", user[0]["cash"] + (shares * stock["price"]), user[0]["id"])

        # update sells table
        db.execute("INSERT INTO sells (user_id, username, price, symbol, shares, name) VALUES(?, ?, ?, ?, ?, ?)",
                   user[0]["id"], user[0]["username"], stock["price"], stock["symbol"], shares, stock["name"])

        # Redirect user to home page
        return redirect("/")

    return render_template("sell.html", symbols=symbols)