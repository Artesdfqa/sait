from flask import Flask, render_template_string, request, redirect, url_for, session
import sqlite3
import os
import hashlib
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Секретный ключ для сессий

DATABASE = 'users.db'

# Инициализация базы данных, если нет
def init_db():
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('''CREATE TABLE users
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT UNIQUE NOT NULL,
                      password_hash TEXT NOT NULL)''')
        conn.commit()
        conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def get_user(username):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    return user

def add_user(username, password):
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, hash_password(password)))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

@app.route('/')
def index():
    if 'username' in session:
        return f"Привет, {session['username']}! <a href='/logout'>Выйти</a>"
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username)
        if user and user[2] == hash_password(password):
            session['username'] = username
            return redirect(url_for('index'))
        else:
            error = 'Неверный логин или пароль'
    return render_template_string('''
        <h2>Вход</h2>
        <form method="post">
            Логин: <input type="text" name="username" required><br>
            Пароль: <input type="password" name="password" required><br>
            <input type="submit" value="Войти">
        </form>
        <p style="color:red;">{{error}}</p>
        <p>Нет аккаунта? <a href="/register">Зарегистрироваться</a></p>
    ''', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = ''
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if add_user(username, password):
            return redirect(url_for('login'))
        else:
            error = 'Пользователь с таким именем уже существует'
    return render_template_string('''
        <h2>Регистрация</h2>
        <form method="post">
            Логин: <input type="text" name="username" required><br>
            Пароль: <input type="password" name="password" required><br>
            <input type="submit" value="Зарегистрироваться">
        </form>
        <p style="color:red;">{{error}}</p>
        <p>Уже есть аккаунт? <a href="/login">Войти</a></p>
    ''', error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000)
