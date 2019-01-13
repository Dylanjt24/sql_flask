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
    mysql = connectToMySQL('simple_wall')
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
        mysql = connectToMySQL('simple_wall')
        query = "INSERT INTO users (first_name, last_name, email, pw_hash) VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s);"
        data = {
            'first_name': request.form['first_name'],
            'last_name': request.form['last_name'],
            'email': request.form['email'],
            'password': hashed_pw
        }
        new_user = mysql.query_db(query, data)
        session['logged_in'] = True
    # if any validation error, redirect to root page
    if '_flashes' in session.keys():
        return redirect('/')
    else:
        mysql = connectToMySQL('simple_wall')
        query = "SELECT * FROM users WHERE email = %(email)s;"
        data = {
            'email': request.form['email']
        }
        current_user = mysql.query_db(query, data)
        session['id'] = current_user[0]['id']
        return redirect('/home')

@app.route('/login', methods=['POST'])
def login():
    # check if given email exists in db
    mysql = connectToMySQL('simple_wall')
    query = "SELECT * FROM users WHERE email = %(email)s;"
    data = {
        'email': request.form['email']
    }
    current_user = mysql.query_db(query, data)
    # if email exists, check if passwords match
    if current_user:
        session['id'] = current_user[0]['id']
        session['first_name'] = current_user[0]['first_name']
        hashed_pw = current_user[0]['pw_hash']
        if bcrypt.check_password_hash(hashed_pw, request.form['password']):
            session['logged_in'] = True
            return redirect('/home')
        else:
            session['logged_in'] = False
            flash('Sorry, you could not be logged in', 'login')
            return redirect('/')
    else:
        flash('Sorry, you could not be logged in', 'login')
        return redirect('/')


@app.route('/home')
def success():
    # if logged in, show the proper home page
    if session['logged_in']:
        session['attempts'] = 0
        print(session['attempts'])
        mysql = connectToMySQL('simple_wall')
        query = "SELECT first_name, id FROM users WHERE id != %(current_id)s;"
        data = {
            'current_id': session['id']
        }
        users = mysql.query_db(query, data)
        mysql = connectToMySQL('simple_wall')
        message_query = "SELECT first_name, last_name, content, messages.id, messages.user_id, messages.created_at FROM messages JOIN users ON messages.user_id = users.id WHERE messages.recipient = %(current_id)s ORDER BY messages.created_at DESC ;"
        data = {
            'current_id': session['id']
        }
        messages = mysql.query_db(message_query, data)
        return render_template('home.html', users=users, messages=messages)
    else:
        # redirect to root if no user is logged in
        flash('Please log in or register', 'login')
        return redirect('/')

@app.route('/create_message', methods=['POST'])
def create_message():
    # insert user's message to the database
    mysql = connectToMySQL('simple_wall')
    query = "INSERT INTO messages (content, user_id, recipient) VALUES (%(content)s, %(user_id)s, %(recipient)s);"
    data = {
        'content': request.form['new_message'],
        'user_id': session['id'],
        'recipient': request.form['recipient_id']
    }
    mysql.query_db(query,data)
    return redirect('/home')

@app.route('/delete_message/<id>')
def delete(id):
    mysql = connectToMySQL('simple_wall')
    delete_query = "DELETE FROM messages WHERE messages.id = %(id)s;"
    data = {
        'id': id
    }
    message_query = "SELECT recipient, id FROM messages"
    current_message = mysql.query_db(message_query)
    # if user tries to delete a message that does not belong to them
    if current_message[0]['recipient'] != session['id']:
        session['message_id'] = current_message[0]['id']
        session['user_ip'] = request.environ['REMOTE_ADDR']
        return redirect('/danger')
    else:
        # if message belongs to the user, delete the message
        mysql = connectToMySQL('simple_wall')
        mysql.query_db(delete_query, data)
        return redirect('/home')

@app.route('/danger')
def danger():
    if session['attempts'] > 1:
        session['logged_in'] = False
        return redirect('/')
    print('*' * 80)
    session['attempts'] += 1
    print(session['attempts'])
    return render_template('danger.html')

@app.route('/logout')
def logout():
    session['logged_in'] = False
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)