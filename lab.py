"""
Lab 7:  Python Flask Web Application
Author: Andrew Rios
Class: SDEV300
Date: Dec 5 2022
"""
import re
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, abort, session
from passlib.hash import sha256_crypt

PASSWORD_FILE = 'passwordFile.txt'
COMMON_PASSWORD_FILE = 'CommonPassword.txt'
LOG_FILE = 'log.txt'

app = Flask(__name__)
app.config['SECRET_KEY'] = b'_5#y2L"F4Q8z\n\xec]/'


def common_password_check(password_input):
    """ Check if the given password exists in the common password file
        return True if password is found
    """
    try:
        with open(COMMON_PASSWORD_FILE, "r") as pw:
            for record in pw:
                if record.strip() == password_input:
                    return True
    except FileNotFoundError:
        print('File not found: ' ' + COMMON_PASSWORD_FILE')
        abort(400)  # Flask method to abort the whole web app
    except Exception as e:
        print('No permissions to open this file or data '
              'in it not in correct format: + COMMON_PASSWORD_FILE')
        abort(400)  # Flask method to abort the whole web app
    return False


def password_valid(password):
    """
    takes in a password
    checks password for complexity requirements
    returns boolean
    """
    if len(password) < 12:
        return False

    has_uppercase = False
    has_lowercase = False
    has_digit = False
    has_special_char = False

    for i in password:
        if i.isupper():
            has_uppercase = True
        elif i.islower():
            has_lowercase = True
        elif i.isdigit():
            has_digit = True
        elif re.search(r'[@_!#$%^&*()<>?/|}{~:]', i):
            has_special_char = True

    return has_uppercase and has_lowercase and has_digit and has_special_char


def check_username(username_input):
    """ Check if the given username does not already exist in our password file
        return none of the username does not exist
        otherwise return the password hash
    """
    try:
        with open(PASSWORD_FILE, "r") as users:
            for record in users:
                if len(record) == 0:
                    print('password file is empty')
                    return None
                username, hash_pass = record.split()
                if username == username_input:
                    return hash_pass
    except FileNotFoundError:
        print('File not found: ' ' + PASSWORD_FILE')
        abort(400)  # Flask method to abort the whole web app
    except Exception as e:
        print('No permissions to open this file or data '
              'in it not in correct format: + PASSWORD_FILE')
        abort(400)  # Flask method to abort the whole web app
    return None


def update_password_file(session_user, new_password):
    """
    update password and remove previous user data from file
    """
    try:
        with open(PASSWORD_FILE, "r") as user_file:
            user_list = user_file.readlines()
    except FileNotFoundError:
        print('File not found: ' ' + PASSWORD_FILE')
        abort(400)  # Flask method to abort the whole web app
    else:
        for user in user_list:  # loop through list of users
            username, hash_pass = user.split()
            if session_user == username:
                user_list.remove(user)
                print(user_list)
        # save remaining users to the PW file
        with open(PASSWORD_FILE, "w") as new_user_file:
            for user in user_list:
                new_user_file.write(user)
    save_user(session_user, new_password)  # save user data


def save_user(username, password):
    """
    Encrypt and Store credentials
    """
    hash_pass = sha256_crypt.hash(password)
    new_record = '' + username + ' ' + hash_pass + '\n'

    with open(PASSWORD_FILE, "a") as file:  # auto-closes the fle when append is done
        file.writelines(new_record)


def update_log():
    """
    log failed login attempts
    """
    # get current date and time
    now = datetime.now()
    # format date and time
    date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
    # create new login attempt record
    new_record = '' + date_time + ', ' + request.remote_addr + '\n'
    # update file with new record
    with open(LOG_FILE, "a") as my_file:  # auto-closes the fle when append is done
        my_file.writelines(new_record)


def verify_password(password_input, pass_hash):
    """
    compares password input to hash
    returns true if password is verified
    """
    return sha256_crypt.verify(password_input, pass_hash)


def get_date():
    """
    get current date and time
    returns a formatted datetime string
    """
    date_time = None

    try:
        # get current date and time
        now = datetime.now()
        # format date and time
        date_time = now.strftime("%m/%d/%Y, %H:%M:%S")
    except ValueError:
        print('Error getting datetime.')

    return date_time


@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    function to check registration information
    returns a route or redirect
    """
    # If there is an active session, redirect to home page
    if session.get("username"):
        return redirect(url_for("home"))

    # render reg page if request is GET
    if request.method == "GET":
        return render_template('register.html')

    # save form inputs
    username = request.form["username"].lower()
    password = request.form["password"]
    print(password)

    # error message variable
    error = None

    # input validation
    if not username:
        error = "Username is required."
    elif not password:
        error = "Password is required."
    elif check_username(username) is not None:
        error = "Username taken"
    elif common_password_check(password):
        error = "Password too common"
    elif not password_valid(password):
        error = "Password must be at least 12 characters long and " \
                "contain at least 1 uppercase character, " \
                "1 lowercase character, 1 number, and 1 special character."
    if error is None:
        save_user(username, password)
        return redirect(url_for("login"))
    if error is not None:
        return render_template('register.html', error=error)
    return None


# Route for handling the login page
@app.route('/login', methods=["POST", "GET"])
def login():
    """
    function to check login information
    returns a route or redirect
    """
    # If there is an active session, redirect to home page
    if session.get("username"):
        return redirect(url_for("home"))

    # render login page if request is GET
    if request.method == "GET":
        return render_template("login.html")

    # save form inputs
    username = request.form['username'].lower()
    password = request.form['password']

    # error message variable
    error = None

    # input validation
    if not username:
        error = "Username is required."
    elif not password:
        error = "Password is required."
    elif check_username(username) is not None:
        hash_pass = check_username(username)
        if not verify_password(password, hash_pass):
            error = "Invalid login Information. Please try again. [PW]"
    else:
        error = "Invalid login Information. Please try again. [USER]"
    if error is None:
        session["username"] = username
        return redirect(url_for("home"))
    if error is not None:
        update_log()
        return render_template('login.html', error=error)
    return None


@app.route('/update', methods=['GET', 'POST'])
def update_password():
    """
    function to update password
    returns a route or redirect
    """
    # Check for session and redirect to login page if no session is found
    if not session.get("username"):
        return redirect(url_for("login"))

    # get username
    username = session.get("username")

    # render reg page if request is GET
    if request.method == "GET":
        return render_template('update.html', username=username)

    # get form input
    password = request.form["password"]
    print(password)

    # message variables
    error = None
    message = None

    # input validation
    if not password:
        error = "Password is required."
    elif common_password_check(password):
        error = "Password too common"
    elif not password_valid(password):
        error = "Password must be at least 12 characters long and " \
                "contain at least 1 uppercase character, " \
                "1 lowercase character, 1 number, and 1 special character."
    if error is None:
        message = "Password successfully updated."
        update_password_file(username, password)
        return render_template('update.html', message=message, username=username)
    if error is not None:
        return render_template('update.html', error=error, username=username)
    return None


@app.route('/')
def home():
    """
    route for home page
    """
    # Check for session and redirect to login page if no session is found
    if not session.get("username"):
        return redirect(url_for("login"))
    return render_template('home.html', date_time=get_date())  # pass in datetime as argument


@app.route('/snow')
def snow():
    """
    route for snow page
     """
    # Check for session and redirect to login page if no session is found
    if not session.get("username"):
        return redirect(url_for("login"))

    # pass in datetime as argument
    return render_template('snow.html', date_time=get_date())


@app.route('/beach')
def beach():
    """
    route for beach page
     """
    # Check for session and redirect to login page if no session is found
    if not session.get("username"):
        return redirect(url_for("login"))

    # pass in datetime as argument
    return render_template('beach.html', date_time=get_date())


@app.route('/backyard')
def backyard():
    """
    route for home page
    """
    # Check for session and redirect to login page if no session is found
    if not session.get("username"):
        return redirect(url_for("login"))
    return render_template('backyard.html', date_time=get_date())


@app.route("/logout")
def logout():
    """
        route for logout
    """
    session["username"] = None
    return redirect(url_for("login"))


if __name__ == '__main__':
    app.run()
