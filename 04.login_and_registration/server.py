from flask import Flask, redirect, render_template, session, request, flash
import re
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt
app = Flask(__name__)
app.secret_key = "DoYouKnowTheMuffinMan"
bcrypt = Bcrypt(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    # set variables for form inputs
    session['first_name'] = request.form['first_name']
    session['last_name'] = request.form['last_name']
    session['email'] = request.form['email']
    password = request.form['password']
    EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
    PW_REGEX = re.compile(r'\d.*[A-Z]|[A-Z].*\d')
    # validate first_name
    if not request.form['first_name']:
        flash('First name cannot be blank!', 'first_name')
    elif not request.form['first_name'].isalpha():
        flash('First name can only contain letters', 'first_name')
    elif len(request.form['first_name']) < 3:
        flash('First name must be longer than 2 characters', 'first_name')
    # validate last_name
    if not request.form['last_name']:
        flash('Last name cannot be blank', 'last_name')
    elif not request.form['last_name'].isalpha():
        flash('Last name can only contain letters', 'last_name')
    elif len(request.form['last_name']) < 3:
        flash('Last name must be longer than 2 characters', 'last_name')
    # validate email
    if not EMAIL_REGEX.match(request.form['email']):
        flash('Invalid email address', 'email')
    # check to see if given email already exists
    mysql = connectToMySQL('registration')
    query = "SELECT * FROM users WHERE email = %(email)s;"
    data = {
        'email': request.form['email']
    }
    in_use = mysql.query_db(query,data)
    # checks if the query returned any users where email = given email
    if in_use:
        flash('Email already in use', 'email')
    # validate password
    if not request.form['password']:
        flash('Password cannot be blank', 'password')
    elif len(request.form['password']) < 8:
        flash('Password must be at least 8 characters', 'password')
    elif not PW_REGEX.match(request.form['password']):
        flash('Password must contain at least 1 uppercase letter and 1 number', 'password')
    elif request.form['password'] != request.form['pw_confirm']:
        flash('Passwords must match', 'pw_confirm')
    # if validations passed, adds new user to db
    else:
        hashed_pw = bcrypt.generate_password_hash(password)
        mysql = connectToMySQL('registration')
        query = "INSERT INTO users (first_name, last_name, email, pw_hash) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s);"
        data = {
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name'],
            'email': request.form['email'],
            'password': hashed_pw
        }
        new_user = mysql.query_db(query, data)
        session['logged_in'] = True
    if '_flashes' in session.keys():
        return redirect('/')
    else:
        flash('You\'ve been successfully registered', 'register')
        return redirect('/success')

@app.route('/login', methods=['POST'])
def login():
    # check if given email exists in db
    mysql = connectToMySQL('registration')
    query = "SELECT * FROM users WHERE email = %(email)s;"
    data = {
        'email': request.form['email']
    }
    current_user = mysql.query_db(query, data)
    # if email exists, check if passwords match
    if current_user:
        session['id'] = current_user[0]['id']
        session['current_first_name'] = current_user[0]['first_name']
        hashed_pw = current_user[0]['pw_hash']
        if bcrypt.check_password_hash(hashed_pw, request.form['password']):
            session['logged_in'] = True
            return redirect('/success')
        else:
            session['logged_in'] = False
            flash('Sorry, you could not be logged in', 'login')
            return redirect('/')
    else:
        flash('Sorry, you could not be logged in', 'login')
        return redirect('/')


@app.route('/success')
def success():
    if session['logged_in']:
        return render_template('success.html')
    else:
        flash('Please log in or register', 'login')
        return redirect('/')

@app.route('/logout')
def logout():
    session['logged_in'] = False
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)