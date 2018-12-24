from flask import Flask, render_template, redirect, request
from mysqlconnection import connectToMySQL
app = Flask(__name__)
app.secret_key = "HeyNowYoureAnAllstar"

@app.route('/')
def index():
    mysql = connectToMySQL('c_r_friends')
    all_friends = mysql.query_db('SELECT * FROM friends')
    return render_template('index.html', friends = all_friends)

@app.route('/create_friend', methods=['POST'])
def create():
    mysql = connectToMySQL('c_r_friends')
    query = "INSERT INTO friends (first_name, last_name, occupation) VALUES (%(first_name)s, %(last_name)s, %(occupation)s);"
    data = {
        'first_name': request.form['first_name'],
        'last_name': request.form['last_name'],
        'occupation': request.form['occupation']
    }
    new_friend = mysql.query_db(query, data)
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)