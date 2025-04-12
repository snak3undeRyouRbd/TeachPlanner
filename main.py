import socket
import os
import secrets
import bcrypt
from flask import Flask, render_template, request, flash, redirect, url_for, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')
app.secret_key = secrets.token_hex(16)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')

        print("==== ПОЛУЧЕН POST ====")
        print(f"Username: {username}")
        print(f"Password: {password}")
        print(f"Role: {role}")

        if not username or not password or not role:
            print("❌ Не всі поля заповнені!")
            flash("Усі поля повинні бути заповнені!", "danger")
            return redirect(url_for('register'))

        hashed = hash_password(password)
        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            print("❌ Користувач з таким імʼям вже існує.")
            flash('Користувач з таким іменем вже існує!', 'danger')
        else:
            try:
                user = User(username=username, password=hashed, role=role)
                db.session.add(user)
                db.session.commit()
                print("✅ Користувача успішно збережено в базу.")
                flash('Реєстрація успішна!', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                print("❌ ПОМИЛКА ПРИ ЗБЕРЕЖЕННІ КОРИСТУВАЧА:", e)
                db.session.rollback()
                flash('Помилка при збереженні користувача!', 'danger')

    return render_template('register.html')

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and check_password(password, user.password):
            session['username'] = username
            session['user_id'] = user.id
            flash('Увійшли успішно!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Невірний логін або пароль!', 'danger')

    return render_template('login.html')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@socketio.on('connect')
def handle_connect():
    user_id = session.get("user_id")
    if user_id:
        join_room(str(user_id))
    else:
        pass

def send_message_to_user(user_id, msg):
    socketio.emit('notification', {'msg': msg}, room=str(user_id))

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
    with app.app_context():
        db.create_all()
    port = find_free_port(5000)
    socketio.run(app, debug=True, port=port)
