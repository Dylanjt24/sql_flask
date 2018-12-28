from flask import Flask, redirect, render_template, request, session, flash
import re
from mysqlconnection import connectToMySQL
app = Flask(__name__)
app.secret_key = "NumaNumaYay"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    mysql = connectToMySQL('email_validation')
    EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
    if not EMAIL_REGEX.match(request.form['email']):
        flash('Email is not valid!')
    else:
        session['email'] = request.form['email']
        query = "INSERT INTO emails (email) VALUES (%(email)s);"
        data = {
            'email': request.form['email']
        }
        new_email = mysql.query_db(query, data)

    if '_flashes' in session.keys():
        return redirect('/')
    else:
        return redirect('/success')

@app.route('/success')
def success():
    mysql = connectToMySQL('email_validation')
    all_emails = mysql.query_db('SELECT * FROM emails')
    return render_template('success.html', current_email = session['email'], emails = all_emails)

@app.route('/delete', methods=['POST'])
def delete():
    email_id = request.form['email_id']
    mysql = connectToMySQL('email_validation')
    query = "DELETE FROM emails WHERE id = %(email_id)s"
    data = {
        'email_id': email_id
    }
    mysql.query_db(query, data)
    return redirect('/success')
if __name__ == '__main__':
    app.run(debug=True)