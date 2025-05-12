"""
Online Clearance System Backend for a School Project
Flask + PostgreSQL (Neon.tech)
"""

# Import necessary libraries
from flask import Flask, request, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask import current_app
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
import jwt
import os
import uuid
from functools import wraps
import re
from flask import current_app

# Initialize Flask application
app = Flask(__name__)
CORS(app)  # Enable CORS for all domains on all routes

# Configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key_here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'postgresql://neondb_owner:npg_B1fTMGAEU8nq@ep-shiny-tree-a4ee97lq-pooler.us-east-1.aws.neon.tech/neondb?sslmode=require')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Create upload folder if it doesn't exist
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'profiles'), exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'documents'), exist_ok=True)

# Initialize database
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Define Database Models
class Student(db.Model):
    __tablename__ = 'students'
    id = db.Column(db.Integer, primary_key=True)
    matric_number = db.Column(db.String(20), unique=True, nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    faculty = db.Column(db.String(100), nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    program = db.Column(db.String(20), nullable=False)
    profile_photo = db.Column(db.String(200), nullable=True)
    registration_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    status = db.Column(db.String(20), default='Active', nullable=False)
    clearance_requests = db.relationship('ClearanceRequest', backref='student', lazy=True)

    def __repr__(self):
        return f'<Student {self.matric_number}>'

class Staff(db.Model):
    __tablename__ = 'staff'
    id = db.Column(db.Integer, primary_key=True)
    staff_id = db.Column(db.String(20), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    department = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), default='Active', nullable=False)
    approvals = db.relationship('ClearanceApproval', backref='staff', lazy=True)

    def __repr__(self):
        return f'<Staff {self.staff_id}>'

class ClearanceRequest(db.Model):
    __tablename__ = 'clearance_requests'
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('students.id'), nullable=False)
    request_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False)
    documents = db.relationship('SupportingDocument', backref='clearance_request', lazy=True)
    comments = db.Column(db.Text, nullable=True)
    approvals = db.relationship('ClearanceApproval', backref='clearance_request', lazy=True)

    def __repr__(self):
        return f'<ClearanceRequest {self.id}>'

class SupportingDocument(db.Model):
    __tablename__ = 'supporting_documents'
    id = db.Column(db.Integer, primary_key=True)
    clearance_request_id = db.Column(db.Integer, db.ForeignKey('clearance_requests.id'), nullable=False)
    file_path = db.Column(db.String(200), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    file_type = db.Column(db.String(50), nullable=False)

    def __repr__(self):
        return f'<SupportingDocument {self.id}>'

class ClearanceApproval(db.Model):
    __tablename__ = 'clearance_approvals'
    id = db.Column(db.Integer, primary_key=True)
    clearance_request_id = db.Column(db.Integer, db.ForeignKey('clearance_requests.id'), nullable=False)
    staff_id = db.Column(db.Integer, db.ForeignKey('staff.id'), nullable=False)
    status = db.Column(db.String(20), default='pending', nullable=False)
    remarks = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.now(timezone.utc), nullable=False)

    def __repr__(self):
        return f'<ClearanceApproval {self.id}>'

# Define authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user_id = data['user_id']
            user_type = data['user_type']
            
            if user_type == 'student':
                current_user = Student.query.get(current_user_id)
            elif user_type == 'staff':
                current_user = Staff.query.get(current_user_id)
            else:
                return jsonify({'message': 'Invalid user type!'}), 401
            
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
                
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_user, user_type, *args, **kwargs)
    
    return decorated

# Helper function to validate email
def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

# Helper function to validate phone number
def is_valid_phone(phone):
    pattern = r'^\+?[0-9]{10,15}$'
    return re.match(pattern, phone) is not None

# Helper function to create initial Super Admin account

def create_super_admin():
    """Create initial super admin account if it doesn't exist."""
    admin = Staff.query.filter_by(staff_id='SupAdmin').first()
    if not admin:
        password_hash = generate_password_hash('super@ID123')
        super_admin = Staff(
            staff_id='SupAdmin',
            full_name='Super Administrator',
            department='Administration',
            email='superadmin@school.edu',
            password_hash=password_hash,
            phone_number='+1234567890',
            role='super_admin',
            status='Active'
        )
        db.session.add(super_admin)
        db.session.commit()
        if not current_app.config.get('TESTING'):  # Only print in non-test mode
            print('Super Admin created successfully!')

# At the bottom of app.py:
with app.app_context():
    db.create_all()
    if not app.config.get('TESTING'):  # Skip during tests
        create_super_admin()

# Define routes
@app.route('/')
def index():
    return jsonify({'message': 'Welcome to the Online Clearance System API'})

# Student registration
@app.route('/api/student/register', methods=['POST'])
def register_student():
    data = request.form.to_dict()
    
    # Validate required fields
    required_fields = ['matric_number', 'first_name', 'last_name', 'department', 
                      'faculty', 'gender', 'email', 'phone_number', 'password', 'program']
    for field in required_fields:
        if field not in data:
            return jsonify({'message': f'Missing required field: {field}'}), 400
    
    # Check if student already exists
    existing_student = Student.query.filter_by(matric_number=data['matric_number']).first()
    if existing_student:
        return jsonify({'message': 'Student with this matriculation number already exists!'}), 400
    
    existing_email = Student.query.filter_by(email=data['email']).first()
    if existing_email:
        return jsonify({'message': 'Email address already in use!'}), 400
    
    # Validate email
    if not is_valid_email(data['email']):
        return jsonify({'message': 'Invalid email address!'}), 400
    
    # Validate phone number
    if not is_valid_phone(data['phone_number']):
        return jsonify({'message': 'Invalid phone number!'}), 400
    
    # Handle profile photo upload if present
    profile_photo_path = None
    if 'profile_photo' in request.files:
        file = request.files['profile_photo']
        if file.filename != '':
            filename = secure_filename(str(uuid.uuid4()) + os.path.splitext(file.filename)[1])
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'profiles', filename)
            file.save(file_path)
            profile_photo_path = 'profiles/' + filename
    
    # Create new student
    new_student = Student(
        matric_number=data['matric_number'],
        first_name=data['first_name'],
        last_name=data['last_name'],
        department=data['department'],
        faculty=data['faculty'],
        gender=data['gender'],
        email=data['email'],
        phone_number=data['phone_number'],
        password_hash=generate_password_hash(data['password']),
        program=data['program'],
        profile_photo=profile_photo_path,
        status='Active'
    )
    
    db.session.add(new_student)
    db.session.commit()
    
    return jsonify({'message': 'Student registered successfully!'}), 201

# Student login
@app.route('/api/student/login', methods=['POST'])
def login_student():
    data = request.get_json()
    
    if not data or not data.get('matric_number') or not data.get('password'):
        return jsonify({'message': 'Missing matriculation number or password!'}), 400
    
    student = Student.query.filter_by(matric_number=data['matric_number']).first()
    
    if not student:
        return jsonify({'message': 'Student not found!'}), 404
    
    if not check_password_hash(student.password_hash, data['password']):
        return jsonify({'message': 'Invalid password!'}), 401
    
    if student.status != 'Active':
        return jsonify({'message': 'Account is not active!'}), 403
    
    # Generate JWT token
    token = jwt.encode({
        'user_id': student.id,
        'user_type': 'student',
        'exp': datetime.now(timezone.utc).timestamp() + 86400  # 24 hours
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({
        'message': 'Login successful!',
        'token': token,
        'student': {
            'id': student.id,
            'matric_number': student.matric_number,
            'first_name': student.first_name,
            'last_name': student.last_name,
            'department': student.department,
            'faculty': student.faculty,
            'email': student.email,
            'profile_photo': student.profile_photo,
            'status': student.status
        }
    }), 200

# Staff login
@app.route('/api/staff/login', methods=['POST'])
def login_staff():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing email or password!'}), 400
    
    staff = Staff.query.filter_by(email=data['email']).first()
    
    if not staff:
        return jsonify({'message': 'Staff not found!'}), 404
    
    if not check_password_hash(staff.password_hash, data['password']):
        return jsonify({'message': 'Invalid password!'}), 401
    
    if staff.status != 'Active':
        return jsonify({'message': 'Account is not active!'}), 403
    
    # Generate JWT token
    token = jwt.encode({
        'user_id': staff.id,
        'user_type': 'staff',
        'role': staff.role,
        'exp': datetime.now(timezone.utc)().timestamp() + 86400  # 24 hours
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({
        'message': 'Login successful!',
        'token': token,
        'staff': {
            'id': staff.id,
            'staff_id': staff.staff_id,
            'full_name': staff.full_name,
            'department': staff.department,
            'email': staff.email,
            'role': staff.role,
            'status': staff.status
        }
    }), 200

# Create staff (for super admin)
@app.route('/api/staff/register', methods=['POST'])
@token_required
def register_staff(current_user, user_type):
    # Check if current user is super admin
    if user_type != 'staff' or current_user.role != 'super_admin':
        return jsonify({'message': 'Permission denied!'}), 403
    
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['staff_id', 'full_name', 'department', 'email', 'password', 'phone_number', 'role']
    for field in required_fields:
        if field not in data:
            return jsonify({'message': f'Missing required field: {field}'}), 400
    
    # Check if staff already exists
    existing_staff = Staff.query.filter_by(staff_id=data['staff_id']).first()
    if existing_staff:
        return jsonify({'message': 'Staff with this ID already exists!'}), 400
    
    existing_email = Staff.query.filter_by(email=data['email']).first()
    if existing_email:
        return jsonify({'message': 'Email address already in use!'}), 400
    
    # Validate email
    if not is_valid_email(data['email']):
        return jsonify({'message': 'Invalid email address!'}), 400
    
    # Validate phone number
    if not is_valid_phone(data['phone_number']):
        return jsonify({'message': 'Invalid phone number!'}), 400
    
    # Create new staff
    new_staff = Staff(
        staff_id=data['staff_id'],
        full_name=data['full_name'],
        department=data['department'],
        email=data['email'],
        password_hash=generate_password_hash(data['password']),
        phone_number=data['phone_number'],
        role=data['role'],
        status='Active'
    )
    
    db.session.add(new_staff)
    db.session.commit()
    
    return jsonify({'message': 'Staff registered successfully!'}), 201

# Get all staff (for super admin)
@app.route('/api/staff', methods=['GET'])
@token_required
def get_all_staff(current_user, user_type):
    # Check if current user is super admin
    if user_type != 'staff' or current_user.role != 'super_admin':
        return jsonify({'message': 'Permission denied!'}), 403
    
    all_staff = Staff.query.all()
    output = []
    
    for staff in all_staff:
        staff_data = {
            'id': staff.id,
            'staff_id': staff.staff_id,
            'full_name': staff.full_name,
            'department': staff.department,
            'email': staff.email,
            'phone_number': staff.phone_number,
            'role': staff.role,
            'status': staff.status
        }
        output.append(staff_data)
    
    return jsonify({'staff': output}), 200

# Update staff details (for super admin)
@app.route('/api/staff/<int:id>', methods=['PUT'])
@token_required
def update_staff(current_user, user_type, id):
    # Check permissions
    if user_type != 'staff':
        return jsonify({'message': 'Permission denied!'}), 403
        
    if current_user.role != 'super_admin' and current_user.id != id:
        return jsonify({'message': 'Permission denied!'}), 403
    
    staff = Staff.query.get_or_404(id)
    data = request.get_json()
    
    # Staff can only update specific fields about themselves
    if current_user.role != 'super_admin' and current_user.id == id:
        allowed_fields = ['phone_number', 'password']
        for field in data:
            if field not in allowed_fields:
                return jsonify({'message': f'You cannot update {field}!'}), 403
    
    # Update fields
    if 'full_name' in data:
        staff.full_name = data['full_name']
    if 'department' in data:
        staff.department = data['department']
    if 'email' in data and data['email'] != staff.email:
        # Check if email already exists
        existing_email = Staff.query.filter_by(email=data['email']).first()
        if existing_email and existing_email.id != staff.id:
            return jsonify({'message': 'Email address already in use!'}), 400
        staff.email = data['email']
    if 'phone_number' in data:
        if not is_valid_phone(data['phone_number']):
            return jsonify({'message': 'Invalid phone number!'}), 400
        staff.phone_number = data['phone_number']
    if 'password' in data:
        staff.password_hash = generate_password_hash(data['password'])
    if 'role' in data and current_user.role == 'super_admin':
        staff.role = data['role']
    if 'status' in data and current_user.role == 'super_admin':
        staff.status = data['status']
    
    db.session.commit()
    return jsonify({'message': 'Staff updated successfully!'}), 200

# Delete staff (for super admin)
@app.route('/api/staff/<int:id>', methods=['DELETE'])
@token_required
def delete_staff(current_user, user_type, id):
    # Check if current user is super admin
    if user_type != 'staff' or current_user.role != 'super_admin':
        return jsonify({'message': 'Permission denied!'}), 403
    
    staff = Staff.query.get_or_404(id)
    
    # Prevent deletion of super admin
    if staff.role == 'super_admin':
        return jsonify({'message': 'Cannot delete super admin account!'}), 403
    
    db.session.delete(staff)
    db.session.commit()
    
    return jsonify({'message': 'Staff deleted successfully!'}), 200

# Get all students (for super admin and staff)
@app.route('/api/students', methods=['GET'])
@token_required
def get_all_students(current_user, user_type):
    # Check if current user is staff
    if user_type != 'staff':
        return jsonify({'message': 'Permission denied!'}), 403
    
    all_students = Student.query.all()
    output = []
    
    for student in all_students:
        student_data = {
            'id': student.id,
            'matric_number': student.matric_number,
            'first_name': student.first_name,
            'last_name': student.last_name,
            'department': student.department,
            'faculty': student.faculty,
            'gender': student.gender,
            'email': student.email,
            'program': student.program,
            'status': student.status,
            'registration_date': student.registration_date.strftime('%Y-%m-%d %H:%M:%S')
        }
        output.append(student_data)
    
    return jsonify({'students': output}), 200

# Update student details (for super admin or self)
@app.route('/api/student/<int:id>', methods=['PUT'])
@token_required
def update_student(current_user, user_type, id):
    # Check permissions
    if user_type == 'student' and current_user.id != id:
        return jsonify({'message': 'Permission denied!'}), 403
    
    if user_type == 'staff' and current_user.role != 'super_admin':
        return jsonify({'message': 'Permission denied!'}), 403
    
    student = Student.query.get_or_404(id)
    data = request.form.to_dict()
    
    # Student can only update specific fields about themselves
    if user_type == 'student':
        allowed_fields = ['phone_number', 'password']
        for field in data:
            if field not in allowed_fields and field != 'profile_photo':
                return jsonify({'message': f'You cannot update {field}!'}), 403
    
    # Update fields
    if 'first_name' in data:
        student.first_name = data['first_name']
    if 'last_name' in data:
        student.last_name = data['last_name']
    if 'department' in data:
        student.department = data['department']
    if 'faculty' in data:
        student.faculty = data['faculty']
    if 'gender' in data:
        student.gender = data['gender']
    if 'email' in data and data['email'] != student.email:
        # Check if email already exists
        existing_email = Student.query.filter_by(email=data['email']).first()
        if existing_email and existing_email.id != student.id:
            return jsonify({'message': 'Email address already in use!'}), 400
        student.email = data['email']
    if 'phone_number' in data:
        if not is_valid_phone(data['phone_number']):
            return jsonify({'message': 'Invalid phone number!'}), 400
        student.phone_number = data['phone_number']
    if 'password' in data:
        student.password_hash = generate_password_hash(data['password'])
    if 'program' in data:
        student.program = data['program']
    if 'status' in data and user_type == 'staff':
        student.status = data['status']
    
    # Handle profile photo update
    if 'profile_photo' in request.files:
        file = request.files['profile_photo']
        if file.filename != '':
            # Delete old profile photo if exists
            if student.profile_photo:
                old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], student.profile_photo)
                if os.path.exists(old_file_path):
                    os.remove(old_file_path)
            
            # Save new profile photo
            filename = secure_filename(str(uuid.uuid4()) + os.path.splitext(file.filename)[1])
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'profiles', filename)
            file.save(file_path)
            student.profile_photo = 'profiles/' + filename
    
    db.session.commit()
    return jsonify({'message': 'Student updated successfully!'}), 200

# Delete student (for super admin)
@app.route('/api/student/<int:id>', methods=['DELETE'])
@token_required
def delete_student(current_user, user_type, id):
    # Check if current user is super admin
    if user_type != 'staff' or current_user.role != 'super_admin':
        return jsonify({'message': 'Permission denied!'}), 403
    
    student = Student.query.get_or_404(id)
    
    # Delete related records (cascade not working automatically due to ORM)
    clearance_requests = ClearanceRequest.query.filter_by(student_id=student.id).all()
    for request in clearance_requests:
        # Delete supporting documents
        documents = SupportingDocument.query.filter_by(clearance_request_id=request.id).all()
        for doc in documents:
            # Delete the actual file
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], doc.file_path)
            if os.path.exists(file_path):
                os.remove(file_path)
            db.session.delete(doc)
        
        # Delete approvals
        approvals = ClearanceApproval.query.filter_by(clearance_request_id=request.id).all()
        for approval in approvals:
            db.session.delete(approval)
        
        db.session.delete(request)
    
    # Delete profile photo if exists
    if student.profile_photo:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], student.profile_photo)
        if os.path.exists(file_path):
            os.remove(file_path)
    
    db.session.delete(student)
    db.session.commit()
    
    return jsonify({'message': 'Student deleted successfully!'}), 200

# Student submits clearance request
@app.route('/api/clearance/request', methods=['POST'])
@token_required
def submit_clearance_request(current_user, user_type):
    # Check if current user is student
    if user_type != 'student':
        return jsonify({'message': 'Permission denied!'}), 403
    
    data = request.form.to_dict()
    
    # Create clearance request
    new_request = ClearanceRequest(
        student_id=current_user.id,
        status='pending',
        comments=data.get('comments', '')
    )
    
    db.session.add(new_request)
    db.session.flush()  # Get the ID without committing
    
    # Handle document uploads
    if 'documents' in request.files:
        files = request.files.getlist('documents')
        for file in files:
            if file.filename != '':
                # Save file
                filename = secure_filename(str(uuid.uuid4()) + os.path.splitext(file.filename)[1])
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'documents', filename)
                file.save(file_path)
                
                # Create document record
                doc = SupportingDocument(
                    clearance_request_id=new_request.id,
                    file_path='documents/' + filename,
                    file_type=os.path.splitext(file.filename)[1][1:].lower()
                )
                db.session.add(doc)
    
    # Create approval requests for all required departments
    departments = [
        'Head of Department',
        'Polytechnic Librarian',
        'Dean Student Affairs',
        'School Officer',
        'Bursary Unit (Academic Gown Store)',
        'Bursary Unit'
    ]
    
    for dept in departments:
        # Find staff members in this department
        staff_members = Staff.query.filter_by(department=dept, status='Active').all()
        if staff_members:
            # Create approval request for the first active staff member
            approval = ClearanceApproval(
                clearance_request_id=new_request.id,
                staff_id=staff_members[0].id,
                status='pending'
            )
            db.session.add(approval)
    
    db.session.commit()
    
    return jsonify({'message': 'Clearance request submitted successfully!'}), 201

# Get student's clearance requests
@app.route('/api/student/clearance/requests', methods=['GET'])
@token_required
def get_student_clearance_requests(current_user, user_type):
    # Check if current user is student
    if user_type != 'student':
        return jsonify({'message': 'Permission denied!'}), 403
    
    requests = ClearanceRequest.query.filter_by(student_id=current_user.id).all()
    output = []
    
    for request in requests:
        # Get approval status
        approvals = ClearanceApproval.query.filter_by(clearance_request_id=request.id).all()
        approval_data = []
        
        for approval in approvals:
            staff = Staff.query.get(approval.staff_id)
            approval_data.append({
                'id': approval.id,
                'department': staff.department,
                'staff_name': staff.full_name,
                'status': approval.status,
                'remarks': approval.remarks,
                'timestamp': approval.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            })
        
# Continuing from where the code was cut off, completing the get_student_clearance_requests function:

        # Get supporting documents
        documents = SupportingDocument.query.filter_by(clearance_request_id=request.id).all()
        doc_data = []
        
        for doc in documents:
            doc_data.append({
                'id': doc.id,
                'file_path': doc.file_path,
                'file_type': doc.file_type,
                'upload_date': doc.upload_date.strftime('%Y-%m-%d %H:%M:%S')
            })
        
        request_data = {
            'id': request.id,
            'request_date': request.request_date.strftime('%Y-%m-%d %H:%M:%S'),
            'status': request.status,
            'comments': request.comments,
            'approvals': approval_data,
            'documents': doc_data
        }
        output.append(request_data)
    
    return jsonify({'clearance_requests': output}), 200

# Get staff's pending approvals
@app.route('/api/staff/pending-approvals', methods=['GET'])
@token_required
def get_staff_pending_approvals(current_user, user_type):
    # Check if current user is staff
    if user_type != 'staff':
        return jsonify({'message': 'Permission denied!'}), 403
    
    approvals = ClearanceApproval.query.filter_by(staff_id=current_user.id, status='pending').all()
    output = []
    
    for approval in approvals:
        request = ClearanceRequest.query.get(approval.clearance_request_id)
        student = Student.query.get(request.student_id)
        
        # Get supporting documents
        documents = SupportingDocument.query.filter_by(clearance_request_id=request.id).all()
        doc_data = []
        
        for doc in documents:
            doc_data.append({
                'id': doc.id,
                'file_path': doc.file_path,
                'file_type': doc.file_type,
                'upload_date': doc.upload_date.strftime('%Y-%m-%d %H:%M:%S')
            })
        
        approval_data = {
            'approval_id': approval.id,
            'request_id': request.id,
            'student': {
                'id': student.id,
                'matric_number': student.matric_number,
                'first_name': student.first_name,
                'last_name': student.last_name,
                'department': student.department,
                'faculty': student.faculty,
                'program': student.program
            },
            'request_date': request.request_date.strftime('%Y-%m-%d %H:%M:%S'),
            'comments': request.comments,
            'documents': doc_data
        }
        output.append(approval_data)
    
    return jsonify({'pending_approvals': output}), 200

# Staff approves or rejects clearance request
@app.route('/api/clearance/approve/<int:approval_id>', methods=['PUT'])
@token_required
def approve_clearance(current_user, user_type, approval_id):
    # Check if current user is staff
    if user_type != 'staff':
        return jsonify({'message': 'Permission denied!'}), 403
    
    data = request.get_json()
    
    if not data or not data.get('status') or data['status'] not in ['approved', 'rejected']:
        return jsonify({'message': 'Invalid status!'}), 400
    
    approval = ClearanceApproval.query.get_or_404(approval_id)
    
    # Check if this approval belongs to the current staff
    if approval.staff_id != current_user.id:
        return jsonify({'message': 'Permission denied!'}), 403
    
    # Check if approval is already processed
    if approval.status != 'pending':
        return jsonify({'message': 'This approval has already been processed!'}), 400
    
    # Update approval
    approval.status = data['status']
    approval.remarks = data.get('remarks', '')
    approval.timestamp = datetime.now(timezone.utc)
    
    # Check if all approvals are completed for this request
    request = ClearanceRequest.query.get(approval.clearance_request_id)
    all_approvals = ClearanceApproval.query.filter_by(clearance_request_id=request.id).all()
    
    all_completed = True
    any_rejected = False
    
    for app in all_approvals:
        if app.status == 'pending':
            all_completed = False
        elif app.status == 'rejected':
            any_rejected = True
    
    # Update request status if all approvals are completed
    if all_completed:
        if any_rejected:
            request.status = 'rejected'
        else:
            request.status = 'approved'
    
    db.session.commit()
    
    return jsonify({'message': f'Clearance {data["status"]}!'}), 200

# Get all clearance requests (for super admin)
@app.route('/api/clearance/requests', methods=['GET'])
@token_required
def get_all_clearance_requests(current_user, user_type):
    # Check if current user is super admin
    if user_type != 'staff' or current_user.role != 'super_admin':
        return jsonify({'message': 'Permission denied!'}), 403
    
    requests = ClearanceRequest.query.all()
    output = []
    
    for request in requests:
        student = Student.query.get(request.student_id)
        
        # Get approval status
        approvals = ClearanceApproval.query.filter_by(clearance_request_id=request.id).all()
        approval_data = []
        
        for approval in approvals:
            staff = Staff.query.get(approval.staff_id)
            approval_data.append({
                'id': approval.id,
                'department': staff.department,
                'staff_name': staff.full_name,
                'status': approval.status,
                'remarks': approval.remarks,
                'timestamp': approval.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            })
        
        request_data = {
            'id': request.id,
            'student': {
                'id': student.id,
                'matric_number': student.matric_number,
                'first_name': student.first_name,
                'last_name': student.last_name,
                'department': student.department
            },
            'request_date': request.request_date.strftime('%Y-%m-%d %H:%M:%S'),
            'status': request.status,
            'comments': request.comments,
            'approvals': approval_data
        }
        output.append(request_data)
    
    return jsonify({'clearance_requests': output}), 200

# Download file
@app.route('/api/file/<path:filename>', methods=['GET'])
@token_required
def download_file(current_user, user_type, filename):
    # Check if file exists
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not os.path.exists(file_path):
        return jsonify({'message': 'File not found!'}), 404
    
    directory = os.path.dirname(file_path)
    file = os.path.basename(file_path)
    
    return send_from_directory(directory, file)

# Get clearance certificate (for approved students)
@app.route('/api/clearance/certificate/<int:request_id>', methods=['GET'])
@token_required
def get_clearance_certificate(current_user, user_type, request_id):
    # Get the clearance request
    request = ClearanceRequest.query.get_or_404(request_id)
    
    # Check permissions
    if user_type == 'student' and request.student_id != current_user.id:
        return jsonify({'message': 'Permission denied!'}), 403
    
    if user_type == 'staff' and current_user.role != 'super_admin':
        # Check if staff is part of approvers
        approval = ClearanceApproval.query.filter_by(
            clearance_request_id=request.id,
            staff_id=current_user.id
        ).first()
        if not approval:
            return jsonify({'message': 'Permission denied!'}), 403
    
    # Check if request is approved
    if request.status != 'approved':
        return jsonify({'message': 'Clearance not yet approved!'}), 400
    
    # Get student details
    student = Student.query.get(request.student_id)
    
    # Get approval details
    approvals = ClearanceApproval.query.filter_by(clearance_request_id=request.id).all()
    approval_data = []
    
    for approval in approvals:
        staff = Staff.query.get(approval.staff_id)
        approval_data.append({
            'department': staff.department,
            'staff_name': staff.full_name,
            'status': approval.status,
            'remarks': approval.remarks,
            'timestamp': approval.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    # Generate certificate data
    certificate = {
        'certificate_id': f'CERT-{request.id}-{student.matric_number}',
        'issue_date': datetime.now(timezone.utc).strftime('%Y-%m-%d'),
        'student': {
            'matric_number': student.matric_number,
            'first_name': student.first_name,
            'last_name': student.last_name,
            'department': student.department,
            'faculty': student.faculty,
            'program': student.program
        },
        'clearance_date': request.request_date.strftime('%Y-%m-%d'),
        'approvals': approval_data
    }
    
    return jsonify({
        'message': 'Clearance certificate generated successfully!',
        'certificate': certificate
    }), 200

# Dashboard statistics
@app.route('/api/dashboard/stats', methods=['GET'])
@token_required
def dashboard_stats(current_user, user_type):
    stats = {}
    
    if user_type == 'student':
        # Student stats
        requests = ClearanceRequest.query.filter_by(student_id=current_user.id).all()
        
        stats = {
            'total_requests': len(requests),
            'pending_requests': sum(1 for r in requests if r.status == 'pending'),
            'approved_requests': sum(1 for r in requests if r.status == 'approved'),
            'rejected_requests': sum(1 for r in requests if r.status == 'rejected')
        }
    elif user_type == 'staff':
        if current_user.role == 'super_admin':
            # Admin stats
            stats = {
                'total_students': Student.query.count(),
                'total_staff': Staff.query.count(),
                'total_requests': ClearanceRequest.query.count(),
                'pending_requests': ClearanceRequest.query.filter_by(status='pending').count(),
                'approved_requests': ClearanceRequest.query.filter_by(status='approved').count(),
                'rejected_requests': ClearanceRequest.query.filter_by(status='rejected').count()
            }
        else:
            # Staff stats
            approvals = ClearanceApproval.query.filter_by(staff_id=current_user.id).all()
            
            stats = {
                'total_approvals': len(approvals),
                'pending_approvals': sum(1 for a in approvals if a.status == 'pending'),
                'approved_approvals': sum(1 for a in approvals if a.status == 'approved'),
                'rejected_approvals': sum(1 for a in approvals if a.status == 'rejected')
            }
    
    return jsonify({'stats': stats}), 200

# Serve uploaded files
@app.route('/uploads/<path:filename>', methods=['GET'])
@token_required
def uploaded_file(current_user, user_type, filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Create initial super admin account
with app.app_context():
    db.create_all()
    create_super_admin()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
        
        