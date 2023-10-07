import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

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
    id = session["user_id"]
    stocks = db.execute("SELECT * FROM user_stocks WHERE user_id = ?", id)
    prices = []
    total = []
    total_cash = db.execute("SELECT cash FROM users WHERE id = ?", id)[0]["cash"]
    final = 0
    for stock in stocks:
        temp = lookup(stock["stock_symbol"])["price"]
        prices.append(usd(temp))
        total.append(usd(temp * stock["shares"]))
        final += temp * stock["shares"]
    return render_template(
        "display-stocks.html",
        stocks=stocks,
        len=len(stocks),
        prices=prices,
        total=total,
        total_cash=usd(total_cash),
        final=usd(final+total_cash),
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Must provide valid stock symbol", 400)

        if not request.form.get("shares"):
            return apology("Must provide valid number of stock shares to buy", 400)

        symbol = request.form.get("symbol").strip()
        shares = request.form.get("shares").strip()

        try:
            shares = float(shares)
        except:
            return apology("Number of shares can not contain letters or symbols", 400)

        if shares < 0 or int(shares) != shares:
            return apology("Can't do that", 400)

        shares = int(shares)

        stock_info = lookup(symbol)

        if stock_info == None:
            return apology("Stock not found", 400)

        user_info = db.execute("SELECT * FROM users WHERE id=?", session["user_id"])

        if user_info[0]["cash"] < shares * stock_info["price"]:
            return apology("Insufficient cash amount", 400)

        prev_stocks = db.execute(
            "SELECT * FROM user_stocks WHERE stock_symbol = ? AND user_id = ?",
            symbol,
            session["user_id"],
        )

        if len(prev_stocks) == 1:
            db.execute(
                "UPDATE user_stocks SET shares = ? WHERE user_id = ? AND stock_symbol = ?",
                prev_stocks[0]["shares"] + shares,
                session["user_id"],
                symbol,
            )
        else:
            db.execute(
                "INSERT INTO user_stocks (user_id, stock_symbol, shares) VALUES(?, ? ,?)",
                session["user_id"],
                symbol,
                shares,
            )

        db.execute(
            "INSERT INTO buy_history (user_id, stock_symbol, shares, buy_price) VALUES(?, ? ,? , ?)",
            session["user_id"],
            symbol,
            shares,
            shares * stock_info["price"],
        )
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?",
            user_info[0]["cash"] - shares * stock_info["price"],
            session["user_id"],
        )

        return redirect("/", code=200)

    else:
        id = session["user_id"]
        total_cash = db.execute("SELECT cash FROM users WHERE id = ?", id)[0]["cash"]
        return render_template("buy.html", total_cash=usd(total_cash))


@app.route("/history")
@login_required
def history():
    id = session["user_id"]
    stocks = db.execute("SELECT * FROM buy_history WHERE user_id = ?", id)
    prices = []
    total = []
    amount = db.execute("SELECT * FROM cash_history WHERE user_id = ?", id)
    cash = []
    total_cash = db.execute("SELECT cash FROM users WHERE id = ?", id)[0]["cash"]
    for stock in stocks:
        temp = stock["buy_price"]
        prices.append(usd(temp / stock["shares"]))
        total.append(usd(temp))
    for a in amount:
        cash.append(usd(a["amount"]))
    return render_template(
        "history.html",
        stocks=stocks,
        len=len(stocks),
        prices=prices,
        total=total,
        cash=cash,
        len2=len(cash),
        total_cash=usd(total_cash),
    )


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
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
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
    if request.method == "POST":
        # Ensuring stock symbol is given
        if not request.form.get("symbol"):
            return apology("You must enter a stock symbol", 400)

        symbol = request.form.get("symbol")
        result = lookup(symbol)

        # Returning apology if stock not found
        if result is None:
            return apology("No stock was found with this symbol", 400)

        return render_template(
            "quote-result.html", result=result, amount=usd(result["price"])
        )

    else:
        id = session["user_id"]
        total_cash = db.execute("SELECT cash FROM users WHERE id = ?", id)[0]["cash"]
        return render_template("quote.html", total_cash=usd(total_cash))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Ensure that username is given
        if not request.form.get("username"):
            return apology("Must provide username", 400)

        # Ensure that password is given
        if not request.form.get("password"):
            return apology("Must provide password", 400)

        if not request.form.get("confirmation"):
            return apology("Confirm your password", 400)

        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirmation")

        if not password == confirm_password:
            return apology("Password does not match", 400)

        # Checking if there is a previous user with same username
        check = db.execute("SELECT * FROM users WHERE username = ?", username)

        if len(check) > 0:
            return apology("Username already in use try a different one", 400)

        # Inserting new user with 0 chas
        db.execute(
            "INSERT INTO users (username, hash, cash) VALUES(?, ? , ?)",
            username,
            generate_password_hash(password),
            10000,
        )

        # Remembering session
        session["user_id"] = db.execute(
            "SELECT * FROM users WHERE username = ?", username
        )[0]["id"]

        return redirect("/", code=200)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        if not request.form.get("stock-symbol"):
            return apology("Must provide valid stock symbol", 403)

        if not request.form.get("num-shares"):
            return apology("Must provide valid number of stock shares to buy", 403)

        symbol = request.form.get("stock-symbol").strip()
        shares = request.form.get("num-shares").strip()

        try:
            shares = int(shares)
        except:
            return apology("Number of shares can not contain letters or symbols", 403)

        stock_info = lookup(symbol)

        if stock_info == None:
            return apology("Stock not found", 403)

        prev_stocks = db.execute(
            "SELECT * FROM user_stocks WHERE stock_symbol = ? AND user_id = ?",
            symbol,
            session["user_id"],
        )
        user_info = db.execute("SELECT * FROM users WHERE id=?", session["user_id"])

        if len(prev_stocks) == 0 or shares > prev_stocks[0]["shares"]:
            return apology("You do not have the given stock to sell", 403)

        if shares == prev_stocks[0]["shares"]:
            db.execute(
                "DELETE FROM user_stocks WHERE user_id = ? AND stock_symbol = ?",
                session["user_id"],
                symbol,
            )
        else:
            db.execute(
                "UPDATE user_stocks SET shares = ? WHERE user_id = ? AND stock_symbol = ?",
                prev_stocks[0]["shares"] - shares,
                session["user_id"],
                symbol,
            )
        db.execute(
            "INSERT INTO buy_history (user_id, stock_symbol, shares, buy_price) VALUES(?, ? ,?, ?)",
            session["user_id"],
            symbol,
            shares,
            -shares * stock_info["price"],
        )
        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?",
            user_info[0]["cash"] + shares * stock_info["price"],
            session["user_id"],
        )

        return redirect("/")
    else:
        id = session["user_id"]
        total_cash = db.execute("SELECT cash FROM users WHERE id = ?", id)[0]["cash"]
        return render_template("sell.html", total_cash=usd(total_cash))


@app.route("/add-cash", methods=["POST", "GET"])
@login_required
def add_cash():
    if request.method == "POST":
        if not request.form.get("amount"):
            return apology("Must input a valid cash amount", 403)

        amount = request.form.get("amount")

        try:
            amount = float(amount)
        except:
            return apology("Cash amount must not contain letters or characters", 403)

        if amount < 0:
            return apology("Can't add", 403)

        db.execute(
            "INSERT INTO cash_history (user_id, amount) VALUES(?, ?)",
            session["user_id"],
            amount,
        )
        db.execute(
            "UPDATE users SET cash = cash + ? WHERE id = ?", amount, session["user_id"]
        )

        return redirect("/")

    else:
        id = session["user_id"]
        total_cash = db.execute("SELECT cash FROM users WHERE id = ?", id)[0]["cash"]
        return render_template("add-cash.html", total_cash=usd(total_cash))
