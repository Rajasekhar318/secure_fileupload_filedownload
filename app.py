from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, unset_jwt_cookies
from itsdangerous import URLSafeSerializer
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = '0ea6be63c8f750305f7c461dba1c50da90db2ce147aecc393250b3aa001c4bb0'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'd3519767d6f42c7bcd5ad9cbb882763ce4227f304b710cf5851ad3af57dfbac5'

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'dronamrajurajasekhar318@gmail.com'
app.config['MAIL_PASSWORD'] = 'atiz oqpa dqlf vold'
app.config['UPLOAD_FOLDER'] = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pptx', 'docx', 'xlsx'}  # Can expand later

db = SQLAlchemy(app)
mail = Mail(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
serializer = URLSafeSerializer(app.config['SECRET_KEY'])

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(128), unique=True)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_name = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(255), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'))

# Utils
def send_verification_email(email, token):
    msg = Message(subject='Verify Your Email', sender=app.config['MAIL_USERNAME'], recipients=[email])
    url = f"http://localhost:5000/api/verify_email/{token}"
    msg.body = f"Click the link to verify: {url}"
    mail.send(msg)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes
@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data['email']
    password = data['password']
    role = data['role'].capitalize()

    if role not in ['Ops', 'Client']:
        return jsonify({'message': 'Invalid role'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'Email already exists'}), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
    token = serializer.dumps(email)
    new_user = User(email=email, password=hashed_pw, role=role, verification_token=token)
    db.session.add(new_user)
    db.session.commit()
    send_verification_email(email, token)
    return jsonify({'message': 'User created. Verify email.', 'verification_link': f"/api/verify_email/{token}"}), 201

@app.route('/api/verify_email/<token>', methods=['GET'])
def verify_email(token):
    try:
        email = serializer.loads(token)
    except:
        return jsonify({'message': 'Invalid or expired token'}), 400

    user = User.query.filter_by(email=email).first()
    if user:
        user.verified = True
        user.verification_token = None
        db.session.commit()
        return jsonify({'message': 'Email verified successfully'})
    return jsonify({'message': 'User not found'}), 404

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']
    user = User.query.filter_by(email=email).first()

    if user and bcrypt.check_password_hash(user.password, password):
        if not user.verified:
            return jsonify({'message': 'Email not verified'}), 403
        token = create_access_token(identity={'id': user.id, 'role': user.role})
        return jsonify({'token': token, 'role': user.role}), 200
    return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    response = jsonify({'message': 'Logged out successfully'})
    unset_jwt_cookies(response)
    return response, 200

@app.route('/api/upload', methods=['POST'])
@jwt_required()
def upload():
    print("Reached upload route")
    user_data = get_jwt_identity()
    user = User.query.get(user_data['id'])

    if not user.verified:
        return jsonify({'message': 'Email not verified'}), 403

    if user.role != 'Ops':
        return jsonify({'message': 'Only Ops users can upload files'}), 403

    if 'file' not in request.files:
        return jsonify({'message': 'No file uploaded'}), 400

    file = request.files['file']
    filename = secure_filename(file.filename)

    if not filename:
        return jsonify({'message': 'Invalid file name'}), 422

    if not allowed_file(filename):
        return jsonify({'message': 'File type not allowed'}), 422

    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(path)

    db_file = File(file_name=filename, file_path=path, uploaded_by=user.id)
    db.session.add(db_file)
    db.session.commit()

    download_token = serializer.dumps(filename)
    return jsonify({'message': 'File uploaded', 'download_link': f"/api/download/{download_token}"}), 201

@app.route('/api/files', methods=['GET'])
@jwt_required()
def list_files():
    files = File.query.all()
    return jsonify([
        {
            'filename': f.file_name,
            'download_link': f"/api/download/{serializer.dumps(f.file_name)}"
        } for f in files
    ])

@app.route('/api/download/<token>', methods=['GET'])
@jwt_required()
def download(token):
    try:
        filename = serializer.loads(token)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        return send_file(path, as_attachment=True)
    except:
        return jsonify({'message': 'Invalid or expired download token'}), 400

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
