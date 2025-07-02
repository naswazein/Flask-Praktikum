from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
import os
import uuid
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jenn_skincare.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
db = SQLAlchemy(app)

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    api_key = db.Column(db.String(64), unique=True)
    
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_filename = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'image_url': url_for('get_image', filename=self.image_filename, _external=True) if self.image_filename else None,
            'created_at': self.created_at.isoformat()
        }

# Create tables
with app.app_context():
    db.create_all()

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# API key required decorator
def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key is missing'}), 401
        
        user = User.query.filter_by(api_key=api_key).first()
        if not user:
            return jsonify({'error': 'Invalid API key'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# Helper function to generate API key
def generate_api_key():
    import secrets
    return secrets.token_hex(32)

# Helper function to save uploaded file
def save_image(file):
    if file and allowed_file(file.filename):
        # Generate a unique filename to prevent collisions
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        return unique_filename
    return None

# Routes
@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', products=products)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        # Create new user with API key
        api_key = generate_api_key()
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, api_key=api_key)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price'])
        
        # Handle image upload
        image_filename = None
        if 'image' in request.files:
            image_file = request.files['image']
            image_filename = save_image(image_file)
        
        new_product = Product(
            name=name, 
            description=description, 
            price=price,
            image_filename=image_filename
        )
        db.session.add(new_product)
        db.session.commit()
        
        flash('Product added successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('add.html')

@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_product(id):
    product = Product.query.get_or_404(id)
    
    if request.method == 'POST':
        product.name = request.form['name']
        product.description = request.form['description']
        product.price = float(request.form['price'])
        
        # Handle image upload
        if 'image' in request.files:
            image_file = request.files['image']
            if image_file.filename:  # Only process if a new file was selected
                # Delete old image if it exists
                if product.image_filename:
                    old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image_filename)
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)
                
                # Save new image
                product.image_filename = save_image(image_file)
        
        db.session.commit()
        flash('Product updated successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('edit.html', product=product)

@app.route('/delete/<int:id>')
@login_required
def delete_product(id):
    product = Product.query.get_or_404(id)
    
    # Delete image file if it exists
    if product.image_filename:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image_filename)
        if os.path.exists(image_path):
            os.remove(image_path)
    
    db.session.delete(product)
    db.session.commit()
    
    flash('Product deleted successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/uploads/<filename>')
def get_image(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# API Routes
@app.route('/api/profile', methods=['GET'])
@login_required
def get_api_key():
    user = User.query.get(session['user_id'])
    return render_template('api_key.html', api_key=user.api_key)

@app.route('/api/products', methods=['GET'])
def api_get_products():
    products = Product.query.all()
    return jsonify({
        'success': True,
        'products': [product.to_dict() for product in products]
    })

@app.route('/api/products/<int:id>', methods=['GET'])
def api_get_product(id):
    product = Product.query.get_or_404(id)
    return jsonify({
        'success': True,
        'product': product.to_dict()
    })

@app.route('/api/products', methods=['POST'])
@api_key_required
def api_add_product():
    # Check if the request has the multipart/form-data content type
    if request.content_type and 'multipart/form-data' in request.content_type:
        # Handle form data with possible file upload
        name = request.form.get('name')
        description = request.form.get('description')
        price_str = request.form.get('price')
        
        # Validate required fields
        if not all([name, description, price_str]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        try:
            price = float(price_str)
            if price < 0:
                return jsonify({'error': 'Price must be a positive number'}), 400
        except ValueError:
            return jsonify({'error': 'Price must be a valid number'}), 400
        
        # Handle image upload
        image_filename = None
        if 'image' in request.files:
            image_file = request.files['image']
            image_filename = save_image(image_file)
        
        new_product = Product(
            name=name,
            description=description,
            price=price,
            image_filename=image_filename
        )
        
        db.session.add(new_product)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Product added successfully',
            'product': new_product.to_dict()
        }), 201
    
    # Handle JSON request
    elif request.is_json:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['name', 'description', 'price']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        try:
            price = float(data['price'])
            if price < 0:
                return jsonify({'error': 'Price must be a positive number'}), 400
        except ValueError:
            return jsonify({'error': 'Price must be a valid number'}), 400
        
        # For JSON requests, we can accept base64 encoded image data
        image_filename = None
        if 'image_data' in data and data['image_data']:
            try:
                import base64
                from io import BytesIO
                
                # Extract file info and base64 data
                image_info = data['image_data'].split(';base64,')
                if len(image_info) != 2:
                    return jsonify({'error': 'Invalid image data format'}), 400
                
                # Get file extension from mime type
                mime_type = image_info[0].split(':')[1]
                file_ext = mime_type.split('/')[1]
                
                if file_ext not in app.config['ALLOWED_EXTENSIONS']:
                    return jsonify({'error': 'Invalid image format'}), 400
                
                # Decode base64 data
                image_data = base64.b64decode(image_info[1])
                
                # Generate unique filename
                unique_filename = f"{uuid.uuid4().hex}.{file_ext}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                
                # Save the file
                with open(file_path, 'wb') as f:
                    f.write(image_data)
                
                image_filename = unique_filename
            except Exception as e:
                return jsonify({'error': f'Error processing image: {str(e)}'}), 400
        
        new_product = Product(
            name=data['name'],
            description=data['description'],
            price=price,
            image_filename=image_filename
        )
        
        db.session.add(new_product)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Product added successfully',
            'product': new_product.to_dict()
        }), 201
    
    else:
        return jsonify({'error': 'Unsupported content type'}), 415

@app.route('/api/products/<int:id>', methods=['PUT'])
@api_key_required
def api_update_product(id):
    product = Product.query.get_or_404(id)
    
    # Check if the request has the multipart/form-data content type
    if request.content_type and 'multipart/form-data' in request.content_type:
        # Handle form data with possible file upload
        if 'name' in request.form:
            product.name = request.form['name']
        
        if 'description' in request.form:
            product.description = request.form['description']
        
        if 'price' in request.form:
            try:
                price = float(request.form['price'])
                if price < 0:
                    return jsonify({'error': 'Price must be a positive number'}), 400
                product.price = price
            except ValueError:
                return jsonify({'error': 'Price must be a valid number'}), 400
        
        # Handle image upload
        if 'image' in request.files:
            image_file = request.files['image']
            if image_file.filename:  # Only process if a new file was selected
                # Delete old image if it exists
                if product.image_filename:
                    old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image_filename)
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)
                
                # Save new image
                product.image_filename = save_image(image_file)
    
    # Handle JSON request
    elif request.is_json:
        data = request.get_json()
        
        if 'name' in data:
            product.name = data['name']
        
        if 'description' in data:
            product.description = data['description']
        
        if 'price' in data:
            try:
                price = float(data['price'])
                if price < 0:
                    return jsonify({'error': 'Price must be a positive number'}), 400
                product.price = price
            except ValueError:
                return jsonify({'error': 'Price must be a valid number'}), 400
        
        # For JSON requests, we can accept base64 encoded image data
        if 'image_data' in data and data['image_data']:
            try:
                import base64
                
                # Extract file info and base64 data
                image_info = data['image_data'].split(';base64,')
                if len(image_info) != 2:
                    return jsonify({'error': 'Invalid image data format'}), 400
                
                # Get file extension from mime type
                mime_type = image_info[0].split(':')[1]
                file_ext = mime_type.split('/')[1]
                
                if file_ext not in app.config['ALLOWED_EXTENSIONS']:
                    return jsonify({'error': 'Invalid image format'}), 400
                
                # Delete old image if it exists
                if product.image_filename:
                    old_image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image_filename)
                    if os.path.exists(old_image_path):
                        os.remove(old_image_path)
                
                # Decode base64 data
                image_data = base64.b64decode(image_info[1])
                
                # Generate unique filename
                unique_filename = f"{uuid.uuid4().hex}.{file_ext}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                
                # Save the file
                with open(file_path, 'wb') as f:
                    f.write(image_data)
                
                product.image_filename = unique_filename
            except Exception as e:
                return jsonify({'error': f'Error processing image: {str(e)}'}), 400
    
    else:
        return jsonify({'error': 'Unsupported content type'}), 415
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Product updated successfully',
        'product': product.to_dict()
    })

@app.route('/api/products/<int:id>', methods=['DELETE'])
@api_key_required
def api_delete_product(id):
    product = Product.query.get_or_404(id)
    
    # Delete image file if it exists
    if product.image_filename:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image_filename)
        if os.path.exists(image_path):
            os.remove(image_path)
    
    db.session.delete(product)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': 'Product deleted successfully'
    })

if __name__ == '__main__':
    app.run(debug=True)