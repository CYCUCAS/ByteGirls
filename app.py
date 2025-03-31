from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import os
import sqlite3
from openai import OpenAI
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, jsonify, redirect, url_for, session

app = Flask(__name__, static_folder='logo')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///conversations.db'
app.config['SECRET_KEY'] = os.urandom(24)
db = SQLAlchemy(app)

client = OpenAI(
    base_url="https://ark.cn-beijing.volces.com/api/v3",
    api_key=os.environ.get("ARK_API_KEY")
)


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversation.id'))
    role = db.Column(db.String(20))
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username is None or username.strip() == '':
            return 'The phone number cannot be empty, please try again.'
        
        if password is not None:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        else:
            return 'The password cannot be empty, please try again.'

        existing_user = User.query.filter_by(username=username).first()
        
        if existing_user:
            return 'The phone number is already registered, please select another phone number.'
        
        new_user = User(username=username, password=hashed_password)
       
        try:
            db.session.add(new_user)
            db.session.commit()
            return 'You have successfully registered your account, please return to the login page.'
        except:
            return 'Registration failed, please try again.'

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and password is not None and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('index'))
        else:
            return 'Wrong phone number or password, please try again.'

    return render_template('login.html')


@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('index.html')


@app.route('/conversations', methods=['POST'])
def create_conversation():
    new_conv = Conversation()
    db.session.add(new_conv)
    db.session.commit()
    return jsonify({"id": new_conv.id})


active_streams = {}

@app.route('/stop_chat/<int:conversation_id>', methods=['POST'])
def stop_chat(conversation_id):
    if conversation_id in active_streams:
        try:
            active_streams[conversation_id].close()
            del active_streams[conversation_id]
            return jsonify({"message": "Conversation stopped successfully"}), 200
        except Exception as e:
            return jsonify({"error": f"Error stopping conversation: {str(e)}"}), 500
    else:
        return jsonify({"error": "Conversation not found or already stopped"}), 404


@app.route('/chat', methods=['POST'])
def chat():
    data = request.json
    if data is None:
        return jsonify({"error": "No data provided in the request"}), 400
    conversation_id = data.get('conversation_id')
    user_input = data['message']

    if user_input == '/logout':
        session.pop('user_id', None)
        return f'<meta http-equiv="refresh" content="0;url={url_for("login")}">'


    if not db.session.get(Conversation, conversation_id):
        return jsonify({"error": "Conversation not found"}), 404

    new_message = Message(
        conversation_id=conversation_id,
        role='user',
        content=user_input
    )
    db.session.add(new_message)
    
    try:
        with open('prompt_system.txt', 'r', encoding='utf-8') as file:
            system_prompt = file.read().strip()
        
        stream = client.chat.completions.create(
            model="ep-20250319190645-2k76x",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_input}
            ],
            stream=True,
            temperature=0.7,
        )

        active_streams[conversation_id] = stream

    except Exception as e:
        return jsonify({"error": f"OpenAI API error: {str(e)}"}), 500

    def generate():
        full_response = ""
        for chunk in stream:
            if conversation_id not in active_streams:
                break

            if chunk.choices[0].delta.content:
                delta = chunk.choices[0].delta.content
                full_response += delta
                yield delta

        if conversation_id in active_streams:
            del active_streams[conversation_id]

        ai_message = Message(
            conversation_id=conversation_id,
            role='assistant',
            content=full_response
        )

        try:
            with app.app_context():
                db.session.add(ai_message)
                db.session.commit()
        except Exception as e:
            with app.app_context():
                db.session.rollback()
            return jsonify({"error": f"Database error: {str(e)}"}), 500

    return app.response_class(generate(), mimetype='text/plain')


@app.route('/conversations', methods=['GET'])
def get_conversations():
    conversations = Conversation.query.order_by(Conversation.created_at.desc()).all()
    return jsonify([{"id": conv.id} for conv in conversations])


@app.route('/messages', methods=['GET'])
def get_messages():
    conversation_id = request.args.get('conversation_id')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    messages = Message.query.filter_by(conversation_id=conversation_id).order_by(Message.timestamp).paginate(page=page, per_page=per_page)
    return jsonify([{"role": msg.role, "content": msg.content} for msg in messages.items])


@app.route('/generate_summary', methods=['POST'])
def generate_summary():
    data = request.get_json()
    messages = data.get('messages')
    try:
        with open('prompt_summary.txt', 'r', encoding='utf-8') as file:
            summary_prompt = file.read().strip()
        
        completion = client.chat.completions.create(
            model="ep-20250319190645-2k76x",
            messages=[
                {"role": "system", "content": "你是人工智能助手"},
                {"role": "user", "content": f"{summary_prompt}{messages}"},
            ],
        )
        if completion.choices and completion.choices[0].message and completion.choices[0].message.content:
            summary = completion.choices[0].message.content.strip()
        else:
            summary = "Failed to generate summary."
        return jsonify({'summary': summary})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def init_chat_history_db():
    conn = sqlite3.connect('chat_history.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS chat_history
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER,
                 timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                 title TEXT,
                 messages TEXT)''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_chat_history_id ON chat_history (id)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_chat_history_user_id_timestamp ON chat_history (user_id, timestamp DESC)")
    conn.commit()
    conn.close()


def init_shared_chat_db():
    conn = sqlite3.connect('shared_chat.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS shared_chat
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                 title TEXT,
                 messages TEXT,
                 likes INTEGER DEFAULT 0)''')
    conn.commit()
    conn.close()


def init_user_likes_db():
    conn = sqlite3.connect('user_likes.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS user_likes
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER,
                 chat_id INTEGER,
                 UNIQUE (user_id, chat_id))''')
    conn.commit()
    conn.close()


@app.route('/save_chat', methods=['POST'])
def save_chat():
    data = request.get_json()
    messages = data.get('messages')
    title = data.get('title')
    
    user_id = session.get('user_id')
    if user_id is None:
        return jsonify({'error': 'User not logged in'}), 401

    conn = sqlite3.connect('chat_history.db')
    c = conn.cursor()
    c.execute("INSERT INTO chat_history (user_id, title, messages) VALUES (?,?,?)", (user_id, title, messages))
    conn.commit()
    chat_id = c.lastrowid
    conn.close()
    return jsonify({'id': chat_id, 'title': title})


@app.route('/get_recent_chats', methods=['GET'])
def get_recent_chats():
    user_id = session.get('user_id')
    if user_id is None:
        return jsonify({'error': 'User not logged in'}), 401

    conn = sqlite3.connect('chat_history.db')
    c = conn.cursor()
    c.execute("SELECT id, title, messages FROM chat_history WHERE user_id =? ORDER BY timestamp DESC LIMIT 8", (user_id,))
    chats = c.fetchall()
    conn.close()
    chat_list = [{'id': chat[0], 'title': chat[1], 'messages': chat[2]} for chat in chats]
    return jsonify(chat_list)


@app.route('/get_chat_title_chat_history/<int:chat_id>', methods=['GET'])
def get_chat_title_chat_history(chat_id):
    user_id = session.get('user_id')
    if user_id is None:
        return jsonify({'error': 'User not logged in'}), 401
    
    conn = sqlite3.connect('chat_history.db')
    c = conn.cursor()
    c.execute("SELECT title FROM chat_history WHERE id =? AND user_id =?", (chat_id, user_id))
    result = c.fetchone()
    conn.close()
    
    if result:
        return jsonify({'title': result[0]})
    else:
        return jsonify({'error': 'Chat not found'}), 404


@app.route('/get_chat_title_shared_chat/<int:chat_id>', methods=['GET'])
def get_chat_title_shared_chat(chat_id):    
    conn = sqlite3.connect('shared_chat.db')
    c = conn.cursor()
    c.execute("SELECT title FROM shared_chat WHERE id =?", (chat_id,))
    result = c.fetchone()
    conn.close()
    
    if result:
        return jsonify({'title': result[0]})
    else:
        return jsonify({'error': 'Chat not found'}), 404


@app.route('/delete_chat/<int:chat_id>', methods=['POST'])
def delete_chat(chat_id):
    conn = sqlite3.connect('chat_history.db')
    c = conn.cursor()
    c.execute("DELETE FROM chat_history WHERE id =?", (chat_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})


@app.route('/upload_chat', methods=['POST'])
def upload_chat():
    data = request.get_json()
    title = data.get('title')
    messages = data.get('messages')

    conn = sqlite3.connect('shared_chat.db')
    c = conn.cursor()
    c.execute("INSERT INTO shared_chat (title, messages, likes) VALUES (?,?,?)", (title, messages, 0))
    conn.commit()
    chat_id = c.lastrowid
    conn.close()
    return jsonify({'id': chat_id, 'title': title})


@app.route('/check_like/<int:chat_id>', methods=['GET'])
def check_like(chat_id):
    user_id = session.get('user_id')
    if user_id is None:
        return jsonify({'error': 'User not logged in'}), 401

    conn = sqlite3.connect('user_likes.db')
    c = conn.cursor()
    c.execute("SELECT * FROM user_likes WHERE user_id =? AND chat_id =?", (user_id, chat_id))
    result = c.fetchone()
    conn.close()

    return jsonify({'liked': result is not None})


@app.route('/like_chat/<int:chat_id>', methods=['POST'])
def like_chat(chat_id):
    user_id = session.get('user_id')
    if user_id is None:
        return jsonify({'error': 'User not logged in'}), 401

    try:
        conn = sqlite3.connect('user_likes.db')
        c = conn.cursor()
        c.execute("INSERT INTO user_likes (user_id, chat_id) VALUES (?,?)", (user_id, chat_id))
        conn.commit()
        conn.close()

        conn = sqlite3.connect('shared_chat.db')
        c = conn.cursor()
        c.execute("UPDATE shared_chat SET likes = likes + 1 WHERE id =?", (chat_id,))
        conn.commit()
        conn.close()

        return jsonify({"message": "Chat liked successfully"}), 200
    except sqlite3.IntegrityError:
        return jsonify({'error': 'You have already liked this chat'}), 400


@app.route('/get_shared_chats', methods=['GET'])
def get_shared_chats():
    conn = sqlite3.connect('shared_chat.db')
    c = conn.cursor()
    c.execute("SELECT id, title, messages, likes FROM shared_chat ORDER BY likes DESC, timestamp DESC LIMIT 8")
    chats = c.fetchall()
    conn.close()
    chat_list = [{'id': chat[0], 'title': chat[1], 'messages': chat[2]} for chat in chats]
    return jsonify(chat_list)


@app.route('/search_chats', methods=['POST'])
def search_chats():
    data = request.get_json()
    query = data.get('query')
    user_id = session.get('user_id')
    
    if not query:
        return jsonify({'error': 'No search query provided'}), 400
    
    try:
        shared_conn = sqlite3.connect('shared_chat.db')
        shared_c = shared_conn.cursor()
        shared_c.execute("""
            SELECT id, title, messages 
            FROM shared_chat 
            WHERE title LIKE ? OR messages LIKE ?
            ORDER BY likes DESC
            LIMIT 8
        """, (f'%{query}%', f'%{query}%'))
        shared_chats = [{'id': row[0], 'title': row[1], 'messages': row[2]} for row in shared_c.fetchall()]
        shared_conn.close()
        
        if user_id:
            history_conn = sqlite3.connect('chat_history.db')
            history_c = history_conn.cursor()
            history_c.execute("""
                SELECT id, title, messages 
                FROM chat_history 
                WHERE user_id = ? AND (title LIKE ? OR messages LIKE ?)
                ORDER BY timestamp DESC
                LIMIT 8
            """, (user_id, f'%{query}%', f'%{query}%'))
            downloaded_chats = [{'id': row[0], 'title': row[1], 'messages': row[2]} for row in history_c.fetchall()]
            history_conn.close()
        else:
            return jsonify({'error': 'User not logged in'}), 401
        
        return jsonify({
            'shared_chats': shared_chats,
            'downloaded_chats': downloaded_chats
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        init_chat_history_db()
        init_shared_chat_db()
        init_user_likes_db()
    app.run(host='0.0.0.0', port=6006, debug=True)
else:
    gunicorn_app = app


# export ARK_API_KEY="" && python app.py
