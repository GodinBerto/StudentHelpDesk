from flask_mail import Message
from flask import Flask, request, jsonify, url_for, render_template
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import sqlite3
from flask_socketio import SocketIO, emit, join_room, leave_room
import random


# Configuration
app = Flask(__name__)
app.config.from_object('config.Config')
CORS(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['JWT_SECRET_KEY'])
# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*",
                    ping_timeout=5, ping_interval=5)


# -------------------------Tables----------------------
def get_db_connection():
    conn = sqlite3.connect('instance/HelpDesk.db')
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn, conn.cursor()


# Users Table
def create_users_tables():
    conn, cursor = get_db_connection()
    cursor.execute('''CREATE TABLE IF NOT EXISTS Users (
                            UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                            Username TEXT UNIQUE NOT NULL,
                            Email TEXT UNIQUE NOT NULL,
                            Password TEXT NOT NULL,
                            Index_Number TEXT,
                            Role TEXT DEFAULT "Student",
                            Profile_Image BLOB,
                            Phone_Number INTEGER NOT NULL,
                            Department TEXT NOT NULL,
                            AdminID NUMBER,
                            CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                        )''')
    conn.commit()
    conn.close()


# FAQ Table
def create_faq_tables():
    conn, cursor = get_db_connection()
    cursor.execute('''CREATE TABLE IF NOT EXISTS FAQ (
                            QuestionID INTEGER PRIMARY KEY AUTOINCREMENT,
                            UserID INTEGER NOT NULL,
                            Topic TEXT NOT NULL,
                            Question TEXT NOT NULL,
                            Answer TEXT NOT NULL,
                            FOREIGN KEY (UserID) REFERENCES Users(UserID)
                        )''')
    conn.commit()
    conn.close()


# Messages
def create_messages_tables():
    conn, cursor = get_db_connection()
    cursor.execute('''CREATE TABLE IF NOT EXISTS Messages (
                            MessageID INTEGER PRIMARY KEY AUTOINCREMENT,
                            SenderID INTEGER,
                            ReceiverID INTEGER,
                            Content TEXT,
                            Subject TEXT,
                            CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (SenderID) REFERENCES Users(UserID),
                            FOREIGN KEY (ReceiverID) REFERENCES Users(UserID)
                        )''')
    conn.commit()
    conn.close()


# Notifications Table
def create_notifications_table():
    conn, cursor = get_db_connection()
    cursor.execute('''CREATE TABLE IF NOT EXISTS Notifications (
                            NotificationID INTEGER PRIMARY KEY AUTOINCREMENT,
                            UserID INTEGER NOT NULL,
                            Message TEXT NOT NULL,
                            IsRead BOOLEAN DEFAULT FALSE,
                            CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (UserID) REFERENCES Users(UserID)
                        )''')
    conn.commit()
    conn.close()


# ------------------- Real-Time Connection -------------------
@socketio.on('connect')
@jwt_required()
def handle_connect():
    current_user = get_jwt_identity()
    user_id = current_user["UserID"]
    join_room(f'user_{user_id}')
    print(f'User {user_id} connected to WebSocket.')


@socketio.on('disconnect')
@jwt_required()
def handle_disconnect():
    current_user = get_jwt_identity()
    user_id = current_user["UserID"]
    leave_room(f'user_{user_id}')
    print(f'User {user_id} disconnected from WebSocket.')


# ----------------------------Super Admin Authentication------------------------------
@app.route('/api/v1/superadmin/register', methods=['POST'])
@jwt_required()
def super_admin_register():
    current_user = get_jwt_identity()

    if current_user["Role"] != "Super Admin":
        return jsonify({"message": "Super Admin rights required"}), 403

    data = request.get_json()

    # Check if 'users' is a list or a single user
    users = data.get('users')
    if isinstance(users, dict):
        users = [users]  # Convert single user object to list
    elif not isinstance(users, list):
        return jsonify({"msg": "Invalid input format"}), 400

    conn, cursor = get_db_connection()
    success_users = []
    failed_users = []

    for user in users:
        username = user.get('username')
        index_number = user.get('index_number')
        department = user.get('department')
        email = user.get('email')
        password = user.get('password')
        role = user.get('role')
        phone_number = user.get('phone_number')

        # Validate required fields
        if not username or not email or not password or not role or not phone_number or not department:
            failed_users.append(
                {"username": username, "reason": "Missing required parameters"})
            continue

        # Validate email
        if not email:
            failed_users.append(
                {"username": username, "reason": "Email does not exist"})
            continue

        # Check if username or email already exists
        cursor.execute(
            "SELECT * FROM Users WHERE Username = ? OR Email = ?", (username, email))
        existing_user = cursor.fetchone()

        if existing_user:
            failed_users.append(
                {"username": username, "reason": "Username or Email already exists"})
            continue

        # Send email with username, password, and Play Store link
        msg = Message('Registration Successful',
                      sender='godfredquarm123@gmail.com', recipients=[email])
        msg.body = f'''
        Hello {username},

        You have been successfully registered as {role}.

        Your login credentials are as follows:
        Username: {username}
        Password: {password}

        Please use the following link to download the app from the Play Store:
        [Your Play Store Link Here]

        Best regards,
        Your Team
        '''
        try:
            mail.send(msg)
        except Exception as e:
            failed_users.append(
                {"username": username, "reason": f"Failed to send email: {str(e)}"})
            continue  # Skip to the next user

        # If the email was sent successfully, proceed with registration
        hashed_password = bcrypt.generate_password_hash(
            password).decode('utf-8')

        if role == "Super Admin" or role == "Admin":
            cursor.execute("INSERT INTO Users (Username, Email, Password, Role, Department, Phone_Number) VALUES (?, ?, ?, ?, ?, ?)",
                           (username, email, hashed_password, role, department, phone_number))
        elif role == "Student":
            # Assign an admin
            cursor.execute(
                "SELECT UserID FROM Users WHERE Role = 'Admin' AND Department = ?", (department,))
            admins_in_department = cursor.fetchall()

            if admins_in_department:
                assigned_admin_id = random.choice(
                    admins_in_department)['UserID']
            else:
                cursor.execute("SELECT UserID FROM Users WHERE Role = 'Admin'")
                all_admins = cursor.fetchall()
                assigned_admin_id = random.choice(all_admins)['UserID']

            cursor.execute("INSERT INTO Users (Username, Email, Password, Role, Department, Phone_Number, Index_Number, AdminID) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                           (username, email, hashed_password, role, department, phone_number, index_number, assigned_admin_id))

        success_users.append(username)

    conn.commit()
    conn.close()

    return jsonify({
        "msg": "Registration completed",
        "successful_registrations": success_users,
        "failed_registrations": failed_users
    }), 201


@app.route('/api/v1/staff/login', methods=['POST'])
def super_admin_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    conn, cursor = get_db_connection()
    cursor.execute("SELECT * FROM Users WHERE Username = ?", (username,))
    user = cursor.fetchone()

    if user:
        username_exists = True
        if bcrypt.check_password_hash(user['password'], password):
            # Check if the user is a super admin
            if user['Role'] == "Super Admin" or user['Role'] == "Admin":
                access_token = create_access_token(
                    identity={'Username': user['Username'], "Role": user["Role"], "UserID": user["UserID"], "Department": user["Department"]})
                return jsonify(access_token=access_token, username_exists=username_exists, username=user['Username'], role=user['Role']), 200
            else:
                return jsonify({"error": "Master Admin rights required", "username_exists": username_exists}), 403
        else:
            return jsonify({"error": "Invalid credentials", "username_exists": username_exists}), 401
    else:
        return jsonify({"error": "User not found", "username_exists": False}), 404


# ------------------- User Authentication -------------------------
@app.route('/api/v1/user/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    conn, cursor = get_db_connection()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if user:
        username_exists = True
        if bcrypt.check_password_hash(user['password'], password):
            if user['Role'] == "Student":
                access_token = create_access_token(
                    identity={'Username': user['Username'], "UserID": user['UserID'], "Department": user["Department"], "Index Number": user["Index_Number"], "AdminID": user["AdminID"]})
                return jsonify(access_token=access_token, username_exists=username_exists, username=user['username']), 200
            else:
                return jsonify({"message": "Invalid Role"})
    return jsonify({"error": "Invalid credentials", "username_exists": False}), 401


# -------------------------- User ----------------------------------
# User
@app.route('/api/v1/getUser', methods=['GET'])
@jwt_required()
def getUser():
    current_user = get_jwt_identity()

    conn, cursor = get_db_connection()
    cursor.execute("SELECT * FROM Users WHERE Username = ?",
                   (current_user["Username"],))
    userDetails = cursor.fetchone()
    conn.close()

    if userDetails:
        return jsonify({'Users': [dict(userDetails)], 'username': userDetails["Username"], "email": userDetails["Email"]}), 200
    else:
        return jsonify({"Message": "User not found"}), 404


@app.route('/api/v1/updateUser', methods=['PUT'])
@jwt_required()
def updateUser():
    current_user = get_jwt_identity()
    data = request.get_json()

    new_password = data.get('password')
    new_phone_number = data.get('phone_number')
    new_profile_photo = data.get('profile_photo')
    new_username = data.get('username')
    new_email = data.get('email')
    new_department = data.get('department')
    new_index_number = data.get('index_number')
    new_role = data.get('role')
    new_

    if not new_profile or not new_email or not new_password:
        return jsonify({"Message": "Missing required fields"}), 400

    conn, cursor = get_db_connection()

    try:
        if new_username != current_user["Username"]:
            cursor.execute(
                "SELECT COUNT(*) FROM Users WHERE Username = ?", (new_username,)
            )
            username_exists = cursor.fetchone()[0]

            if username_exists > 0:
                return jsonify({"Message": "Username already taken"}), 400

        if new_email != current_user["Email"]:
            cursor.execute(
                "SELECT COUNT(*) FROM Users WHERE Email = ? AND Username != ?", (new_email,
                                                                                 current_user["Username"])
            )
            email_exists = cursor.fetchone()[0]

            if email_exists > 0:
                return jsonify({"Message": "Email already taken"}), 400

        hashed_password = bcrypt.generate_password_hash(
            new_password).decode('utf-8')

        cursor.execute("""
            UPDATE Users
            SET Username = ?, Email = ?, Password = ?
            WHERE Username = ?
        """, (new_username, new_email, hashed_password, current_user["Username"]))

        conn.commit()
        updated_rows = cursor.rowcount
        if updated_rows > 0:
            return jsonify({"Message": "User updated successfully"}), 200
        else:
            return jsonify({"Message": "No changes made"}), 400
    except Exception as e:
        return jsonify({"Message": str(e)}), 500
    finally:
        conn.close()


@app.route('/api/v1/usersAdmin', methods=['GET'])
@jwt_required()
def get_all_users_admin():
    conn, cursor = get_db_connection()
    cursor.execute("SELECT * FROM Users WHERE Role = 'Admin'")
    users = cursor.fetchall()
    conn.close()

    if users:
        return jsonify({"Users": [dict(user) for user in users]}), 200
    else:
        return jsonify({"Message": "No users found"}), 404


@app.route('/api/v1/usersStudent', methods=['GET'])
@jwt_required()
def get_all_users_student():
    conn, cursor = get_db_connection()
    cursor.execute("SELECT * FROM Users WHERE Role = 'Student'")
    users = cursor.fetchall()
    conn.close()

    if users:
        return jsonify({"Users": [dict(user) for user in users]}), 200
    else:
        return jsonify({"Message": "No users found"}), 404


@app.route('/api/v1/users', methods=['GET'])
@jwt_required()
def get_all_users():
    conn, cursor = get_db_connection()
    cursor.execute("SELECT * FROM Users")
    users = cursor.fetchall()
    conn.close()

    if users:
        return jsonify({"Users": [dict(user) for user in users]}), 200
    else:
        return jsonify({"Message": "No users found"}), 404


@app.route('/api/v1/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    conn, cursor = get_db_connection()

    cursor.execute("DELETE FROM Users WHERE UserID = ?", (user_id,))
    conn.commit()
    deleted_rows = cursor.rowcount
    conn.close()

    if deleted_rows > 0:
        return jsonify({"Message": "User deleted successfully"}), 200
    else:
        return jsonify({"Message": "User not found"}), 404


@app.route('/api/v1/users', methods=['DELETE'])
@jwt_required()
def delete_all_users():
    conn, cursor = get_db_connection()

    cursor.execute("DELETE FROM Users")
    conn.commit()
    deleted_rows = cursor.rowcount
    conn.close()

    if deleted_rows > 0:
        return jsonify({"Message": "All users deleted successfully"}), 200
    else:
        return jsonify({"Message": "No users found to delete"}), 404


@app.route('/api/v1/studentsForAdmin', methods=['GET'])
@jwt_required()
def get_students_for_admin():
    current_user = get_jwt_identity()

    # Get admin_id from query parameters
    admin_id = current_user['UserID']

    if not admin_id:
        return jsonify({"Message": "Admin ID is required"}), 400

    conn, cursor = get_db_connection()

    # Query to find students assigned to the specific admin
    cursor.execute("""
        SELECT * FROM Users
        WHERE AdminID = ?
        AND Role = 'Student'
    """, (admin_id,))

    students = cursor.fetchall()
    conn.close()

    if students:
        return jsonify({"Students": [dict(student) for student in students]}), 200
    else:
        return jsonify({"Message": "No students found for this admin"}), 404


# ----------------------------------------Messages----------------------------------
# Send Message
@app.route('/api/v1/sendMessage', methods=['POST'])
@jwt_required()
def sendMessage():
    current_user = get_jwt_identity()
    sender_id = current_user["UserID"]
    data = request.get_json()

    receiver_id = current_user["AdminID"]
    content = data.get('content')
    subject = data.get('subject')

    if not sender_id or not receiver_id or not content:
        return jsonify({'error': 'Invalid input'}), 400

    conn, cursor = get_db_connection()

    cursor.execute('SELECT 1 FROM Users WHERE UserID = ?', (sender_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Sender does not exist'}), 400

    cursor.execute('SELECT 1 FROM Users WHERE UserID = ?', (receiver_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Receiver does not exist'}), 400

    try:
        cursor.execute('INSERT INTO Messages (SenderID, ReceiverID, Content, Subject) VALUES (?, ?, ?, ?)',
                       (sender_id, receiver_id, content, subject))
        conn.commit()
        message_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Foreign key constraint failed'}), 400

    conn.close()

    # Emit a WebSocket event for the new message
    socketio.emit('new_message', {
        'message_id': message_id,
        'sender_id': sender_id,
        'receiver_id': receiver_id,
        'content': content,
        'subject': subject
    }, room=f'user_{receiver_id}')

    return jsonify({'message': 'Message sent successfully'}), 200


@app.route('/api/v1/sendMessageAdmin', methods=['POST'])
@jwt_required()
def send_message_admin():
    current_user = get_jwt_identity()
    sender_id = current_user["UserID"]
    data = request.get_json()

    receiver_index = data.get('receiver_index')
    content = data.get('content')
    subject = data.get('subject')

    if not receiver_index or not content or not subject:
        return jsonify({'error': 'Invalid input'}), 400

    conn, cursor = get_db_connection()

    # Find the receiver's UserID based on index number
    cursor.execute(
        'SELECT UserID FROM Users WHERE Index_Number = ?', (receiver_index,))
    receiver = cursor.fetchone()
    if not receiver:
        conn.close()
        return jsonify({'error': 'Receiver not found'}), 404

    receiver_id = receiver['UserID']

    cursor.execute('SELECT 1 FROM Users WHERE UserID = ?', (sender_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Sender does not exist'}), 400

    cursor.execute('SELECT 1 FROM Users WHERE UserID = ?', (receiver_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({'error': 'Receiver does not exist'}), 400

    try:
        cursor.execute('INSERT INTO Messages (SenderID, ReceiverID, Content, Subject) VALUES (?, ?, ?, ?)',
                       (sender_id, receiver_id, content, subject))
        conn.commit()
        message_id = cursor.lastrowid
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Failed to send message'}), 500

    conn.close()

    # Emit a WebSocket event for the new message
    socketio.emit('new_message', {
        'message_id': message_id,
        'sender_id': sender_id,
        'receiver_id': receiver_id,
        'content': content,
        'subject': subject
    }, room=f'user_{receiver_id}')

    return jsonify({'message': 'Message sent successfully'}), 200


# Get Message
@app.route('/api/v1/getMessages', methods=['GET'])
@jwt_required()
def getMessages():
    current_user = get_jwt_identity()
    user_id = current_user["UserID"]

    # Fetch messages where the user is either the sender or the receiver
    conn, cursor = get_db_connection()

    try:
        cursor.execute('''
            SELECT m.*, s.Username AS SenderName, r.Username AS ReceiverName,
                CASE
                    WHEN m.SenderID = ? THEN 'Sent'
                    ELSE 'Received'
                END AS MessageType
            FROM Messages m
            JOIN Users s ON m.SenderID = s.UserID
            JOIN Users r ON m.ReceiverID = r.UserID
            WHERE m.SenderID = ? OR m.ReceiverID = ?
            ORDER BY m.CreatedAt ASC
        ''', (user_id, user_id, user_id))
        messages = cursor.fetchall()

        # Convert to a list of dictionaries
        message_list = [dict(message) for message in messages]

    except sqlite3.Error as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

    conn.close()
    return jsonify({"message_list": message_list, "user_id": user_id}), 200


@app.route('/api/v1/getSentMessages', methods=['GET'])
@jwt_required()
def getSentMessages():
    current_user = get_jwt_identity()
    user_id = current_user["UserID"]

    # Fetch messages where the user is the sender
    conn, cursor = get_db_connection()

    try:
        cursor.execute('''
            SELECT m.*, r.Username AS ReceiverName
            FROM Messages m
            JOIN Users r ON m.ReceiverID = r.UserID
            WHERE m.SenderID = ?
            ORDER BY m.CreatedAt ASC
        ''', (user_id,))
        messages = cursor.fetchall()

        # Convert to a list of dictionaries
        message_list = [dict(message) for message in messages]

    except sqlite3.Error as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

    conn.close()
    return jsonify({"message_list": message_list, "user_id": user_id}), 200


@app.route('/api/v1/getReceivedMessages', methods=['GET'])
@jwt_required()
def getReceivedMessages():
    current_user = get_jwt_identity()
    user_id = current_user["UserID"]

    # Fetch messages where the user is the receiver
    conn, cursor = get_db_connection()

    try:
        cursor.execute('''
            SELECT m.*, s.Username AS SenderName
            FROM Messages m
            JOIN Users s ON m.SenderID = s.UserID
            WHERE m.ReceiverID = ?
            ORDER BY m.CreatedAt ASC
        ''', (user_id,))
        messages = cursor.fetchall()

        # Convert to a list of dictionaries
        message_list = [dict(message) for message in messages]

    except sqlite3.Error as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

    conn.close()
    return jsonify({"message_list": message_list, "user_id": user_id}), 200


# Search Messages
@app.route('/api/v1/searchMessages', methods=['GET'])
@jwt_required()
def searchMessages():
    current_user = get_jwt_identity()
    user_id = current_user["UserID"]

    # Retrieve search parameters from query string
    query = request.args.get('query', '')

    if not query:
        return jsonify({'error': 'No search query provided'}), 400

    conn, cursor = get_db_connection()

    try:
        cursor.execute('''
            SELECT m.*, s.Username AS SenderName, r.Username AS ReceiverName,
                CASE
                    WHEN m.SenderID = ? THEN 'Sent'
                    ELSE 'Received'
                END AS MessageType
            FROM Messages m
            JOIN Users s ON m.SenderID = s.UserID
            JOIN Users r ON m.ReceiverID = r.UserID
            WHERE (m.SenderID = ? OR m.ReceiverID = ?)
              AND (m.Content LIKE ? OR m.Subject LIKE ?)
            ORDER BY m.CreatedAt ASC
        ''', (user_id, user_id, user_id, f'%{query}%', f'%{query}%'))
        messages = cursor.fetchall()

        # Convert to a list of dictionaries
        message_list = [dict(message) for message in messages]

    except sqlite3.Error as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

    conn.close()
    return jsonify({"message_list": message_list, "user_id": user_id}), 200


# Message Details
@app.route('/api/v1/getMessageByID/<int:message_id>', methods=['GET'])
@jwt_required()
def getMessageDetails(message_id):
    current_user = get_jwt_identity()
    user_id = current_user["UserID"]

    # Fetch message details where the user is either the sender or the receiver
    conn, cursor = get_db_connection()

    try:
        cursor.execute('''
            SELECT m.*, s.Username AS SenderName, r.Username AS ReceiverName,
                CASE
                    WHEN m.SenderID = ? THEN 'Sent'
                    ELSE 'Received'
                END AS MessageType
            FROM Messages m
            JOIN Users s ON m.SenderID = s.UserID
            JOIN Users r ON m.ReceiverID = r.UserID
            WHERE m.MessageID = ? AND (m.SenderID = ? OR m.ReceiverID = ?)
        ''', (user_id, message_id, user_id, user_id))
        message = cursor.fetchone()

        if not message:
            return jsonify({'error': 'Message not found or access denied'}), 404

        # Convert to a dictionary
        message_detail = dict(message)

    except sqlite3.Error as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

    conn.close()
    return jsonify({"message": message_detail}), 200


# Message Delete
@app.route('/api/v1/deleteMessage/<int:message_id>', methods=['DELETE'])
@jwt_required()
def deleteMessage(message_id):
    current_user = get_jwt_identity()
    user_id = current_user["UserID"]

    # Delete message where the user is either the sender or the receiver
    conn, cursor = get_db_connection()

    try:
        cursor.execute('''
            DELETE FROM Messages
            WHERE MessageID = ? AND (SenderID = ? OR ReceiverID = ?)
        ''', (message_id, user_id, user_id))

        if cursor.rowcount == 0:
            return jsonify({'error': 'Message not found or access denied'}), 404

        conn.commit()

    except sqlite3.Error as e:
        conn.close()
        return jsonify({'error': str(e)}), 500

    conn.close()
    return jsonify({"message": "Message deleted successfully"}), 200


# ---------------------------Frequently Asked Questions -------------------------
# Get FAQ
@app.route('/api/v1/getAllFaqQuestions', methods=['GET'])
@jwt_required()
def get_all_faq_questions():
    current_user = get_jwt_identity()

    conn, cursor = get_db_connection()
    cursor.execute("SELECT * FROM FAQ")
    questions = cursor.fetchall()
    conn.close()

    return jsonify({'questions': [dict(question) for question in questions], 'user': current_user, 'message': 'found'}), 200


@app.route('/api/v1/getFaqQuestions/<string:topic>', methods=['GET'])
@jwt_required()
def get_questions(topic):
    current_user = get_jwt_identity()

    conn, cursor = get_db_connection()
    cursor.execute("SELECT * FROM FAQ WHERE Topic = ?", (topic,))
    questions = cursor.fetchall()
    conn.close()

    return jsonify({'questions': [dict(question) for question in questions], 'message': 'found'}), 200


# Add FAQ
@app.route('/api/v1/addFaqQuestions/<string:topic>', methods=['POST'])
@jwt_required()
def add_faq_questions(topic):
    current_user = get_jwt_identity()
    try:
        data = request.get_json()

        if not all(k in data for k in ("question", "answer")):
            return jsonify({"error": "Missing required fields"}), 400

        question = data['question']
        answer = data['answer']

        conn, cursor = get_db_connection()
        cursor.execute("INSERT INTO FAQ (Topic, Question, Answer, UserID) VALUES (?, ?, ?, ?)",
                       (topic, question, answer, current_user["UserID"]))
        conn.commit()  # Ensure changes are committed
        conn.close()
        return jsonify({'Message': "FAQ successfully added", 'user': current_user, 'message': 'found'}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Update FAQ
@app.route('/api/v1/updateFaqQuestion/<int:question_id>', methods=['PUT'])
@jwt_required()
def update_faq_question(question_id):
    current_user = get_jwt_identity()

    try:
        data = request.get_json()

        if not all(k in data for k in ("question", "answer")):
            return jsonify({"error": "Missing required fields"}), 400

        question = data['question']
        answer = data['answer']

        conn, cursor = get_db_connection()
        cursor.execute('''
            UPDATE FAQ
            SET Question = ?, Answer = ?
            WHERE QuestionID = ? AND UserID = ?
        ''', (question, answer, question_id, current_user["UserID"]))
        conn.commit()

        if cursor.rowcount == 0:
            conn.close()
            return jsonify({"error": "FAQ not found or user not authorized"}), 404

        conn.close()
        return jsonify({'message': "FAQ successfully updated", 'user': current_user}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Delete FAQ
@app.route('/api/v1/deleteFaqQuestion/<int:question_id>', methods=['DELETE'])
@jwt_required()
def delete_faq_question(question_id):
    current_user = get_jwt_identity()

    try:
        conn, cursor = get_db_connection()
        cursor.execute('''
            DELETE FROM FAQ
            WHERE QuestionID = ? AND UserID = ?
        ''', (question_id, current_user["UserID"]))
        conn.commit()

        if cursor.rowcount == 0:
            conn.close()
            return jsonify({"error": "FAQ not found or user not authorized"}), 404

        conn.close()
        return jsonify({'message': "FAQ successfully deleted", 'user': current_user}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ------------------- Notifications API ------------------------
@app.route('/api/v1/notifications', methods=['POST'])
@jwt_required()
def create_notification():
    current_user = get_jwt_identity()
    data = request.get_json()
    message = data.get('message')
    user_id = current_user['UserID']

    if not message:
        return jsonify({"msg": "Message content is required"}), 400

    conn, cursor = get_db_connection()
    cursor.execute("INSERT INTO Notifications (UserID, Message) VALUES (?, ?)",
                   (user_id, message))
    conn.commit()

    # Fetch the last inserted notification
    cursor.execute(
        "SELECT * FROM Notifications WHERE NotificationID = last_insert_rowid()")
    new_notification = cursor.fetchone()

    if new_notification:
        # Convert the Row object to a dictionary
        new_notification_dict = {
            'NotificationID': new_notification['NotificationID'],
            'UserID': new_notification['UserID'],
            'Message': new_notification['Message'],
            'CreatedAt': new_notification['CreatedAt']
        }

        try:
            socketio.emit('notification_update', {
                'notification_id': new_notification_dict['NotificationID'],
                'message': new_notification_dict['Message'],
                'created_at': new_notification_dict['CreatedAt']
            }, room=str(user_id))

            print(f'''Notification sent to user {
                  user_id}: {new_notification_dict}''')

        except Exception as e:
            print("Failed to emit notification")

        conn.close()

        return jsonify({"msg": "Notification created successfully", "notification": new_notification_dict}), 201

    return ({"message": "Error emitting notification"})


@app.route('/api/v1/notifications', methods=['GET'])
@jwt_required()
def get_notifications():
    current_user = get_jwt_identity()
    user_id = current_user['UserID']

    conn, cursor = get_db_connection()
    cursor.execute(
        "SELECT * FROM Notifications WHERE UserID = ? ORDER BY CreatedAt DESC", (user_id,))
    notifications = cursor.fetchall()
    conn.close()

    return jsonify([dict(notification) for notification in notifications]), 200


@app.route('/api/v1/notifications/read/<int:notification_id>', methods=['POST'])
@jwt_required()
def mark_notification_as_read(notification_id):
    current_user = get_jwt_identity()
    user_id = current_user['UserID']

    conn, cursor = get_db_connection()
    cursor.execute("UPDATE Notifications SET IsRead = 1 WHERE NotificationID = ? AND UserID = ?",
                   (notification_id, user_id))
    conn.commit()
    conn.close()

    return jsonify({"msg": "Notification marked as read"}), 200


@app.route('/api/v1/notifications/count', methods=['GET'])
@jwt_required()
def get_notification_count():
    # Get the current user's ID from the JWT token
    current_user = get_jwt_identity()
    user_id = current_user['UserID']

    # Connect to the database
    conn, cursor = get_db_connection()

    # Query to get the count of unread notifications
    cursor.execute(
        "SELECT COUNT(*) FROM Notifications WHERE UserID = ? AND IsRead = 0", (user_id,)
    )
    count = cursor.fetchone()[0]  # Fetch the count from the result

    # Close the database connection
    conn.close()

    # Return the count as JSON
    return jsonify({"unreadCount": count}), 200


@app.route('/api/v1/loggs', methods=['GET'])
@jwt_required()
def get_loggs():
    return ({"Loggs": "Get all logs"})


# Run the app
if __name__ == '__main__':
    create_users_tables()
    create_faq_tables()
    create_messages_tables()
    create_notifications_table()
    socketio.run(app, host='0.0.0.0', port=8000, debug=True)
