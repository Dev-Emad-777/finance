import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from flask_avatars import Avatars


from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)
avatars = Avatars(app)


# Custom filter
app.jinja_env.filters["usd"] = usd
app.jinja_env.filters["lookup"] = lookup
app.jinja_env.filters["float"] = float
app.jinja_env.filters["int"] = int

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
    cash = db.execute("SELECT cash FROM users WHERE id = ? ", session["user_id"])

    try:
        cash = cash[0]["cash"]
    except:
        return apology("Cash $ Error!")

    shares = db.execute(
        "SELECT DISTINCT symbol, sum(shares) AS total_shares from trades WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0;",
        session["user_id"],
    )
    return render_template("index.html", cash=cash, shares=shares)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":

        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        try:
            shares = int(shares)
        except:
            return apology("invalid shares", 403)

        if not lookup(symbol):
            return apology("invalid symbol", 403)
        elif shares < 1:
            return apology("invalid shares", 403)
        else:
            share = lookup(symbol)

            price = share["price"]
            symbol = share["symbol"]

            cash = db.execute(
                "SELECT cash FROM users WHERE id = ? ", session["user_id"]
            )
            cash = cash[0]["cash"]
            cost = price * shares
            # check user budget
            if cost > cash:
                return apology("you don't have enough cash")
            else:
                try:

                    # record buy purchase
                    db.execute(
                        "INSERT INTO trades (user_id, symbol, shares, price) VALUES(?,?,?,?)",
                        session["user_id"],
                        symbol,
                        shares,
                        price,
                    )

                    cash = cash - cost
                    db.execute(
                        "UPDATE users SET cash = ? WHERE id = ? ",
                        cash,
                        session["user_id"],
                    )

                    return redirect("/"), flash("Bought!")
                except:
                    return apology("purchase failed!")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute(
        "SELECT symbol, shares, price, time FROM trades WHERE user_id = ?;",
        session["user_id"],
    )

    return render_template("history.html", history=history)


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
    """Get stock quote."""
    if request.method == "POST":
        symbol = request.form.get("symbol")
        try:
            share = lookup(symbol)

            symbol = share["symbol"]
            price = usd(share["price"])
            return render_template("quoted.html", symbol=symbol, price=price)
        except:
            return apology("invalid symbol")

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Ensure username was submitted
        if not username:
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not password:
            return apology("must provide password", 403)

        elif not confirmation:
            return apology("must provide password confirmation", 403)

        elif password != confirmation:
            return apology("passwords doesn't match", 403)
        else:
            try:
                hash = generate_password_hash(password)
                db.execute(
                    "INSERT INTO users (username, hash) VALUES(?,?)", username, hash
                )
                user = db.execute("SELECT * FROM users WHERE username = ?", username)
                session["user_id"] = user[0]["id"]

                return redirect("/"), flash("Registered!")
            except ValueError:
                return apology("username taken!", 403)

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":

        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        try:
            symbol = symbol.upper()
        except:
            return apology("invalid symbol", 403)

        try:
            shares = int(shares)
        except:
            return apology("invalid shares", 403)

        sell_share = db.execute(
            "SELECT symbol, SUM(shares) AS total_shares FROM trades WHERE user_id = ? AND symbol = ? GROUP BY symbol; ",
            session["user_id"],
            symbol,
        )

        if not lookup(symbol):
            return apology("invalid symbol", 403)
        elif shares < 1:
            return apology("invalid shares", 403)
        elif int(sell_share[0]["total_shares"]) < shares:
            return apology("you don't have enough shares to sell")
        else:
            share = lookup(symbol)

            price = share["price"]
            symbol = share["symbol"]

            cash = db.execute(
                "SELECT cash FROM users WHERE id = ? ", session["user_id"]
            )
            cash = cash[0]["cash"]
            cost = price * shares
            try:

                # record buy purchase
                db.execute(
                    "INSERT INTO trades (user_id, symbol, shares, price) VALUES(?,?,?,?)",
                    session["user_id"],
                    symbol,
                    shares * -1,
                    price,
                )

                cash = cash + cost
                db.execute(
                    "UPDATE users SET cash = ? WHERE id = ? ",
                    cash,
                    session["user_id"],
                )

                return redirect("/"), flash("Sold!")
            except:
                return apology("purchase failed!", 203)
    else:
        owned_shares = db.execute(
            "SELECT DISTINCT symbol, sum(shares) AS total_shares from trades WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0;",
            session["user_id"],
        )
        return render_template("sell.html", owned_shares=owned_shares)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    user = db.execute("SELECT * FROM users WHERE id = ? ;", session["user_id"])
    user = user[0]

    shares = db.execute(
        "SELECT DISTINCT symbol, sum(shares) AS total_shares from trades WHERE user_id = ? GROUP BY symbol HAVING total_shares > 0;",
        session["user_id"],
    )
    total_price = 0
    for share in shares:
        total_price = total_price + float(lookup(share["symbol"])["price"]) * int(
            share["total_shares"]
        )

    companies = 0
    for share in shares:
        companies = companies + 1

    shares_count = 0
    for share in shares:
        shares_count = shares_count + share["total_shares"]
    cash = db.execute("SELECT cash FROM users WHERE id = ? ", session["user_id"])

    try:
        cash = cash[0]["cash"]
    except:
        return apology("Cash $ Error!")

    return render_template(
        "profile.html",
        user=user,
        shares_count=shares_count,
        companies=companies,
        total_price=total_price,
        cash=cash,
        avatars=avatars,
    )


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():

    user = db.execute("SELECT * FROM users WHERE id=? ", session["user_id"])
    user = user[0]
    if request.method == "POST":
        # server-side validation
        if not request.form.get("current_password"):
            return apology("must provide current_password", 403)
        elif not request.form.get("new_password"):
            return apology("must provide new password", 403)
        elif request.form.get("again") != request.form.get("new_password"):
            return apology("new passwords doesn't match", 403)
        elif not check_password_hash(
            user["hash"], request.form.get("current_password")
        ):
            return apology("wrong password")
        else:

            hash = generate_password_hash(request.form.get("new_password"))

            db.execute(
                "UPDATE users SET hash = ? WHERE id = ? ",
                hash,
                session["user_id"],
            )
            return redirect("/"), flash("password was changed successfully")

    else:
        return render_template("password.html")
