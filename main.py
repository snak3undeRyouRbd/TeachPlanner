import socket
import os
import sqlite3
import secrets
import bcrypt
from flask import Flask, render_template, request, flash, redirect, url_for, session, send_from_directory
from flask_socketio import SocketIO, emit, join_room


app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')
secretToken = secrets.token_hex(16)
app.secret_key = secretToken
print(f"Секретний ключ цієї сесії: {secretToken}")

#хеширования паролей
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# база данных
def get_db():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

#лютый вебчик и логика

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed = hash_password(password)

        conn = get_db()
        try:
            conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed))
            conn.commit()
            flash('Реєстрація успішна!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Користувач з таким іменем вже існує!', 'danger')
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password(password, user['password']):
            session['username'] = username
            session['user_id'] = user['id']  # Для WebSocket
            flash('Увійшли успішно!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Невірний логін або пароль!', 'danger')

    return render_template('login.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

#сокеты
@socketio.on('connect')
def handle_connect():
    user_id = session.get("user_id")
    if user_id:
        join_room(str(user_id))
        print(f"Пользователь {user_id} подключён к своей комнате.")
    else:
        print("Гость подключился")

def send_message_to_user(user_id, msg):
    socketio.emit('notification', {'msg': msg}, room=str(user_id))

#запуск

# Проверка доступности порта
def is_port_available(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        result = s.connect_ex(('127.0.0.1', port))
        return result != 0

def find_free_port(start_port=5000):
    port = start_port
    while not is_port_available(port):
        port += 1
    return port

if __name__ == '__main__':
    init_db()
    port = find_free_port(5000)
    print(f"Сервер буде запущений на порту {port}")
    socketio.run(app, debug=True, port=port)
