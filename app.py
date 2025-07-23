from flask import Flask, render_template, redirect, request, session, url_for, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///chatapp.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
socketio = SocketIO(app)
db = SQLAlchemy(app)

# DB Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(50), nullable=False)
    recipient = db.Column(db.String(50), nullable=True)
    msg_type = db.Column(db.String(10), nullable=False)  # public, private, group
    text = db.Column(db.Text, nullable=False)
    group = db.Column(db.String(50), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# In-memory
online_users = {}         # username -> sid
user_roles = {}           # username -> role
GROUPS = ['Admin', 'Staff', 'Faculty']

first_run = True
@app.before_request
def create_tables_once():
    global first_run
    if first_run:
        db.create_all()
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", password="adminpw", role="Admin")
            db.session.add(admin)
            db.session.commit()
        first_run = False

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session or user_roles.get(session["username"]) != "Admin":
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

@app.route('/', methods=["GET"])
@login_required
def index():
    username = session.get("username")
    role = user_roles.get(username, "")
    return render_template('index.html', username=username, role=role, groups=GROUPS)

@app.route('/login', methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if user and user.password == request.form["password"]:
            session["username"] = user.username
            user_roles[user.username] = user.role
            return redirect(url_for("index"))
        else:
            error = "Invalid credentials"
    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    session.pop("username", None)
    return redirect(url_for("login"))

# ---------- ADMIN DASHBOARD -----------------
@app.route('/admin', methods=["GET"])
@admin_required
def admin_dashboard():
    users = User.query.order_by(User.role, User.username).all()
    all_messages = Message.query.order_by(Message.timestamp.desc()).limit(100).all()
    return render_template('admin.html', users=users, all_messages=all_messages, username=session['username'])

@app.route('/create_user', methods=["POST"])
@admin_required
def admin_create_user():
    username = request.form["username"].strip()
    password = request.form["password"].strip()
    role = request.form["role"]
    if not username or not password or not role:
        return jsonify({'status': 'error', 'msg': 'All fields required'})
    if User.query.filter_by(username=username).first():
        return jsonify({'status': 'error', 'msg': 'Username already exists'})
    u = User(username=username, password=password, role=role)
    db.session.add(u)
    db.session.commit()
    return jsonify({'status': 'success', 'msg': 'User created'})

@app.route('/reset_password', methods=["POST"])
@admin_required
def admin_reset_password():
    uid = request.form["user_id"]
    pw = request.form["new_password"]
    u = User.query.get(uid)
    if not u:
        return jsonify({'status': 'error', 'msg': 'No such user.'})
    u.password = pw
    db.session.commit()
    return jsonify({'status': 'success', 'msg': 'Password reset'})

@app.route('/delete_user', methods=["POST"])
@admin_required
def admin_delete_user():
    uid = request.form["user_id"]
    u = User.query.get(uid)
    if not u or u.username == "admin":
        return jsonify({'status': 'error', 'msg': 'Cannot delete.'})
    db.session.delete(u)
    db.session.commit()
    return jsonify({'status': 'success', 'msg': 'User deleted'})

@app.route('/admin/messages', methods=["GET"])
@admin_required
def admin_list_messages():
    messages = Message.query.order_by(Message.timestamp.desc()).limit(200).all()
    data = [
        {
            'id': m.id,
            'time': m.timestamp.strftime('%Y-%m-%d %H:%M'),
            'from': m.sender,
            'to': m.recipient or '',
            'type': m.msg_type,
            'group': m.group or '',
            'text': m.text
        }
        for m in messages
    ]
    return jsonify({'messages': data})

# ---------------------------------------------

# REST API for loading chat history for users
@app.route('/history/<chat_type>/<target>', methods=['GET'])
@login_required
def get_history(chat_type, target):
    username = session['username']
    if chat_type == 'public':
        messages = Message.query.filter_by(msg_type='public').order_by(Message.timestamp).all()
    elif chat_type == 'private':
        messages = Message.query.filter(
            db.or_(
                db.and_(Message.sender == username, Message.recipient == target),
                db.and_(Message.sender == target, Message.recipient == username),
            ),
            Message.msg_type=='private'
        ).order_by(Message.timestamp).all()
    elif chat_type == 'group':
        messages = Message.query.filter_by(msg_type='group', group=target).order_by(Message.timestamp).all()
    else:
        messages = []
    return {
        'messages': [
            {
                'from': m.sender,
                'msg': m.text,
                'time': m.timestamp.strftime('%Y-%m-%d %H:%M')
            } for m in messages
        ]
    }

@socketio.on('connect')
def handle_connect():
    username = session.get("username")
    user = User.query.filter_by(username=username).first()
    if not username or not user:
        return False
    online_users[username] = request.sid
    user_roles[username] = user.role
    emit('online_users', [{"username": u, "role": user_roles.get(u)} for u in online_users.keys()], broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    user = None
    for uname, sid in online_users.items():
        if sid == request.sid:
            user = uname
            break
    if user:
        del online_users[user]
        emit('online_users', [{"username": u, "role": user_roles.get(u)} for u in online_users.keys()], broadcast=True)

@socketio.on('send_message')
def handle_send_message(data):
    msg_type = data.get('type')
    sender = session.get('username')
    msg = data.get('message')
    to = data.get('to')
    timestamp = datetime.utcnow()

    # Store message in DB
    recipient = to if msg_type in ['private', 'group'] else None
    group = to if msg_type == 'group' else None
    m = Message(sender=sender, recipient=recipient, msg_type=msg_type, text=msg, group=group, timestamp=timestamp)
    db.session.add(m)
    db.session.commit()

    if msg_type == 'public':
        emit('message', f"{sender}: {msg}", broadcast=True)
    elif msg_type == 'private' and to in online_users:
        recipient_sid = online_users[to]
        emit('private_message', {'from': sender, 'message': msg}, room=recipient_sid)
        emit('private_message', {'from': sender, 'message': msg}, room=request.sid)
    elif msg_type == 'group' and to in GROUPS:
        emit('group_message', {'from': sender, 'message': msg, 'group': to}, room=to)

@socketio.on('join_group')
def on_join_group(data):
    username = session.get("username")
    group = data.get('group')
    join_room(group)
    emit('group_notification', f"{username} has joined the group {group}.", room=group)

@socketio.on('create_group')
def on_create_group(data):
    username = session.get("username")
    user = User.query.filter_by(username=username).first()
    if not user or user.role != 'Admin':
        emit('admin_response', "Only Admin can create groups.")
        return
    group = data.get("group")
    if group and group not in GROUPS:
        GROUPS.append(group)
        emit('group_created', group, broadcast=True)

if __name__ == "__main__":
    app.secret_key = "supersecret"
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
