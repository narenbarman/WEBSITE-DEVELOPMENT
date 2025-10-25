from flask import Flask, render_template, request, redirect, url_for, flash
from firebase_config import initialize_firebase, db
import os
from dotenv import load_dotenv
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import requests
from firebase_admin import firestore
import json

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'default-secret-key')

# File-based user storage for Datastore Mode
USERS_FILE = 'users.json'

def load_users_from_file():
    """Load users from JSON file for Datastore Mode"""
    try:
        if os.path.exists(USERS_FILE):
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
    except Exception as e:
        print(f"Error loading users from file: {e}")
    return []

def save_users_to_file(users):
    """Save users to JSON file for Datastore Mode"""
    try:
        with open(USERS_FILE, 'w') as f:
            json.dump(users, f, indent=2)
    except Exception as e:
        print(f"Error saving users to file: {e}")

def get_cart_count(user_id):
    """Get the total number of items in the user's cart"""
    if not db:
        return 0
    try:
        cart_ref = db.collection('carts').document(user_id)
        cart_doc = cart_ref.get()
        if cart_doc.exists:
            cart_data = cart_doc.to_dict()
            items = cart_data.get('items', [])
            return sum(item.get('quantity', 0) for item in items)
    except Exception as e:
        print(f"Error getting cart count: {e}")
    return 0

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Context processor to inject cart count into all templates
@app.context_processor
def inject_cart_count():
    if current_user.is_authenticated:
        return {'cart_count': get_cart_count(current_user.id)}
    return {'cart_count': 0}

# Initialize Firebase on app startup
initialize_firebase()

class User(UserMixin):
    def __init__(self, uid, email, role='customer'):
        self.id = uid
        self.email = email
        self.role = role

    def is_admin(self):
        return self.role == 'admin'

@login_manager.user_loader
def load_user(user_id):
    # Load user from Firestore if available
    if db:
        try:
            user_doc = db.collection('users').document(user_id).get()
            if user_doc.exists:
                user_data = user_doc.to_dict()
                role = user_data.get('role', 'user')
                email = user_data.get('email', '')
                return User(user_id, email, role)
        except Exception as e:
            print(f"Error loading user {user_id}: {e}")

    # No fallback admin users - all users must be created through registration
    return User(user_id, None, 'customer')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/account', methods=['GET', 'POST'])
def account():
    if request.method == 'POST':
        if 'login' in request.form:
            # Handle login
            email = request.form['email']
            password = request.form['password']

            # No hardcoded admin login - all users must be created through registration

            # For now, login directly from Firestore without Firebase Auth
            # This bypasses the API key issue
            if db:
                try:
                    # Find user by email in Firestore
                    users_ref = db.collection('users')
                    query = users_ref.where('email', '==', email).limit(1)
                    users = list(query.stream())

                    if users:
                        user_doc = users[0]
                        user_data = user_doc.to_dict()

                        # Check password (Note: This is not secure - just for demo)
                        stored_password = user_data.get('password', '')
                        if stored_password == password:
                            user = User(user_doc.id, email, user_data.get('role', 'customer'))
                            login_user(user)
                            flash("Login successful!", 'success')
                            return redirect(url_for('home'))
                        else:
                            flash("Invalid email or password.", 'error')
                    else:
                        flash("Invalid email or password.", 'error')
                except Exception as e:
                    flash(f"Login failed: {str(e)}", 'error')
            else:
                flash("Database not available. Please configure Firebase credentials.", 'error')
        elif 'register' in request.form:
            # Handle registration
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            email = request.form['email']
            phone = request.form['phone']
            address = request.form['address']
            password = request.form['password']
            confirm_password = request.form['confirm_password']

            # Validate passwords match
            if password != confirm_password:
                flash("Passwords do not match.", 'error')
                return render_template('account.html')

            # Validate email format
            import re
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            if not re.match(email_pattern, email):
                flash("Please enter a valid email address.", 'error')
                return render_template('account.html')

            # Validate phone number format (basic validation for international numbers)
            phone_pattern = r'^\+?[1-9]\d{1,14}$'
            # Remove spaces, dashes, parentheses for validation
            clean_phone = re.sub(r'[\s\-\(\)]', '', phone)
            if not re.match(phone_pattern, clean_phone):
                flash("Please enter a valid phone number (e.g., +1234567890 or 1234567890).", 'error')
                return render_template('account.html')

            # Validate password strength (minimum 6 characters for Firebase)
            if len(password) < 6:
                flash("Password must be at least 6 characters long.", 'error')
                return render_template('account.html')

            # For now, create user directly in Firestore without Firebase Auth
            # This bypasses the API key issue
            if db:
                try:
                    # Test Firestore connection first
                    test_ref = db.collection('test_connection').document('test')
                    test_ref.set({'test': True}, merge=True)
                    test_ref.delete()

                    # Check for duplicate email
                    email_query = db.collection('users').where('email', '==', email).limit(1)
                    existing_email = list(email_query.stream())
                    if existing_email:
                        flash("An account with this email already exists.", 'error')
                        return render_template('account.html')

                    # Check for duplicate phone
                    phone_query = db.collection('users').where('phone', '==', phone).limit(1)
                    existing_phone = list(phone_query.stream())
                    if existing_phone:
                        flash("An account with this phone number already exists.", 'error')
                        return render_template('account.html')

                    # Generate a simple user ID
                    import uuid
                    user_id = str(uuid.uuid4())

                    user_data = {
                        'first_name': first_name,
                        'last_name': last_name,
                        'email': email,
                        'phone': phone,
                        'address': address,
                        'role': 'customer',  # All new users start as customers
                        'created_at': firestore.SERVER_TIMESTAMP,
                        'password': password  # Note: This is not secure - just for demo
                    }

                    db.collection('users').document(user_id).set(user_data)

                    # Create user object and login
                    user = User(user_id, email, 'customer')
                    login_user(user)

                    flash("Account created successfully!", 'success')

                    return redirect(url_for('home'))

                except Exception as e:
                    flash(f"Registration failed: {str(e)}", 'error')
            else:
                flash("Database not available. Please configure Firebase credentials.", 'error')
    return render_template('account.html')

# Keep the old routes for backward compatibility, but redirect to account
@app.route('/login')
def login():
    return redirect(url_for('account'))

@app.route('/register')
def register():
    return redirect(url_for('account'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/products')
@login_required
def products():
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    # Fetch all products
    products = []
    if db:
        try:
            products_ref = db.collection('products')
            products_docs = products_ref.stream()
            for product_doc in products_docs:
                product_data = product_doc.to_dict()
                product_data['id'] = product_doc.id
                products.append(product_data)
        except Exception as e:
            print(f"Error fetching products: {e}")
            flash("Database temporarily unavailable. Some features may not work.", 'warning')

    return render_template('products.html', products=products)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    # Fetch all users
    users = []
    db_available = False

    if db:
        try:
            users_ref = db.collection('users')
            users_docs = users_ref.stream()
            for user_doc in users_docs:
                user_data = user_doc.to_dict()
                user_data['id'] = user_doc.id
                users.append(user_data)
            db_available = True
        except Exception as e:
            print(f"Error fetching users from Firestore: {e}")
            if "Datastore Mode" in str(e):
                # Use file-based storage for Datastore Mode
                users = load_users_from_file()
                flash("Using file-based storage for Datastore Mode. User data will persist locally.", 'info')
            else:
                flash("Database temporarily unavailable. Some features may not work.", 'warning')

    # No longer add hardcoded admin users - they should be created through registration

    # For demo purposes, add some sample users if database is unavailable and no file users
    if not db_available and len(users) <= 1:  # Only admin or empty
        sample_users = [
            {
                'id': 'user1',
                'first_name': 'John',
                'last_name': 'Doe',
                'email': 'john.doe@example.com',
                'phone': '+1-555-0123',
                'role': 'customer',
                'created_at': None
            },
            {
                'id': 'user2',
                'first_name': 'Jane',
                'last_name': 'Smith',
                'email': 'jane.smith@example.com',
                'phone': '+1-555-0456',
                'role': 'customer',
                'created_at': None
            },
            {
                'id': 'user3',
                'first_name': 'Bob',
                'last_name': 'Johnson',
                'email': 'bob.johnson@example.com',
                'phone': '+1-555-0789',
                'role': 'admin',
                'created_at': None
            }
        ]
        users.extend(sample_users)
        # Save sample users to file for persistence
        save_users_to_file(users)

    return render_template('admin.html', users=users)

@app.route('/admin/edit_user/<user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        role = request.form['role']

        # All users can now be updated normally

        # Check if using file-based storage (Datastore Mode)
        if not db or (hasattr(db, '__str__') and "Datastore Mode" in str(db)) or (db and "Datastore Mode" in str(type(db))):
            # Update user in file-based storage
            users = load_users_from_file()
            for user in users:
                if user.get('id') == user_id:
                    user.update({
                        'first_name': first_name,
                        'last_name': last_name,
                        'email': email,
                        'phone': phone,
                        'address': address,
                        'role': role
                    })
                    save_users_to_file(users)
                    flash("User updated successfully.", 'success')
                    return redirect(url_for('admin'))
            flash("User not found.", 'error')
            return redirect(url_for('admin'))
        else:
            # Update user in Firestore
            try:
                user_data = {
                    'first_name': first_name,
                    'last_name': last_name,
                    'email': email,
                    'phone': phone,
                    'address': address,
                    'role': role,
                    'updated_at': firestore.SERVER_TIMESTAMP
                }
                db.collection('users').document(user_id).update(user_data)
                flash("User updated successfully.", 'success')
                return redirect(url_for('admin'))
            except Exception as e:
                flash(f"Error updating user: {str(e)}", 'error')

    # GET request: fetch user data
    # Handle admin users specially
    if user_id in ['admin', 'admin2']:
        admin_emails = {'admin': 'naren.barman@gmail.com', 'admin2': 'admin@admin.com'}
        admin_names = {'admin': 'System', 'admin2': 'Admin'}
        user_data = {
            'id': user_id,
            'first_name': admin_names[user_id],
            'last_name': 'Administrator',
            'email': admin_emails[user_id],
            'phone': 'N/A',
            'address': 'N/A',
            'role': 'admin'
        }
        return render_template('edit_user.html', user=user_data)

    # Check if using file-based storage (Datastore Mode)
    if not db or (hasattr(db, '__str__') and "Datastore Mode" in str(db)) or (db and "Datastore Mode" in str(type(db))):
        users = load_users_from_file()
        for user in users:
            if user.get('id') == user_id:
                return render_template('edit_user.html', user=user)
        flash("User not found.", 'error')
        return redirect(url_for('admin'))
    else:
        # Fetch from Firestore
        try:
            user_doc = db.collection('users').document(user_id).get()
            if user_doc.exists:
                user_data = user_doc.to_dict()
                user_data['id'] = user_id
                return render_template('edit_user.html', user=user_data)
        except Exception as e:
            flash(f"Error fetching user: {str(e)}", 'error')

    flash("User not found.", 'error')
    return redirect(url_for('admin'))

@app.route('/admin/delete_user/<user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    if user_id == current_user.id:
        flash("Cannot delete your own account.", 'error')
        return redirect(url_for('admin'))

    # Check if using file-based storage (Datastore Mode)
    if not db or (hasattr(db, '__str__') and "Datastore Mode" in str(db)) or (db and "Datastore Mode" in str(type(db))):
        # Delete user from file-based storage
        users = load_users_from_file()
        users = [user for user in users if user.get('id') != user_id]
        save_users_to_file(users)
        flash("User deleted successfully.", 'success')
    else:
        # Delete user from Firestore
        try:
            db.collection('users').document(user_id).delete()
            flash("User deleted successfully.", 'success')
        except Exception as e:
            flash(f"Error deleting user: {str(e)}", 'error')

    return redirect(url_for('admin'))

@app.route('/catalog')
@login_required
def catalog():
    # Fetch products from Firestore
    if db is None:
        flash("Database not available. Please configure Firebase credentials.", 'error')
        return redirect(url_for('home'))

    # Check Firestore connectivity
    try:
        # Test Firestore connection with a simple operation
        test_ref = db.collection('test_connection').document('test')
        test_ref.set({'test': True}, merge=True)
        test_ref.delete()
    except Exception as e:
        flash(f"Database connection issue: {str(e)}. Please check Firestore permissions in Firebase Console.", 'error')
        return redirect(url_for('home'))
    try:
        products_ref = db.collection('products')
        products = products_ref.stream()
        product_list = []
        for product in products:
            product_data = product.to_dict()
            product_data['id'] = product.id
            product_list.append(product_data)

        # Get user's cart items to highlight products already in cart
        cart_items = {}
        if db:
            try:
                cart_ref = db.collection('carts').document(current_user.id)
                cart_doc = cart_ref.get()
                if cart_doc.exists:
                    cart_data = cart_doc.to_dict()
                    items = cart_data.get('items', [])
                    for item in items:
                        cart_items[item['product_id']] = item['quantity']
            except Exception as e:
                print(f'Error loading cart for catalog: {str(e)}')

        return render_template('catalog.html', products=product_list, cart_items=cart_items)
    except Exception as e:
        flash("Error fetching products.", 'error')
        return redirect(url_for('home'))

@app.route('/add_to_cart/<product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    quantity = int(request.form.get('quantity', 1))
    if quantity < 1:
        quantity = 1
    if db:
        try:
            cart_ref = db.collection('carts').document(current_user.id)
            cart_doc = cart_ref.get()
            if cart_doc.exists:
                cart_data = cart_doc.to_dict()
                items = cart_data.get('items', [])
            else:
                items = []
            # Check if product already in cart, if yes, increase quantity
            found = False
            for item in items:
                if item['product_id'] == product_id:
                    item['quantity'] += quantity
                    found = True
                    break
            if not found:
                # Add new item
                items.append({'product_id': product_id, 'quantity': quantity})
            cart_ref.set({'items': items, 'updated_at': firestore.SERVER_TIMESTAMP})
            flash('Product added to cart!', 'success')
        except Exception as e:
            flash(f'Error adding to cart: {str(e)}', 'error')
    else:
        flash('Database not available.', 'error')
    return redirect(url_for('catalog'))

@app.route('/cart')
@login_required
def cart():
    cart_items = []
    total = 0
    if db:
        try:
            cart_ref = db.collection('carts').document(current_user.id)
            cart_doc = cart_ref.get()
            if cart_doc.exists:
                cart_data = cart_doc.to_dict()
                items = cart_data.get('items', [])
                for item in items:
                    product_ref = db.collection('products').document(item['product_id'])
                    product_doc = product_ref.get()
                    if product_doc.exists:
                        product_data = product_doc.to_dict()
                        product_data['id'] = item['product_id']
                        product_data['quantity'] = item['quantity']
                        product_data['subtotal'] = product_data['price'] * item['quantity']
                        total += product_data['subtotal']
                        cart_items.append(product_data)
        except Exception as e:
            flash(f'Error loading cart: {str(e)}', 'error')
    return render_template('cart.html', cart_items=cart_items, total=total)

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    if not db:
        flash('Database not available.', 'error')
        return redirect(url_for('cart'))

    try:
        # Get cart items
        cart_ref = db.collection('carts').document(current_user.id)
        cart_doc = cart_ref.get()

        if not cart_doc.exists:
            flash('Your cart is empty.', 'error')
            return redirect(url_for('cart'))

        cart_data = cart_doc.to_dict()
        items = cart_data.get('items', [])

        if not items:
            flash('Your cart is empty.', 'error')
            return redirect(url_for('cart'))

        # Build order items with product details
        order_items = []
        total_amount = 0

        for item in items:
            product_ref = db.collection('products').document(item['product_id'])
            product_doc = product_ref.get()

            if product_doc.exists:
                product_data = product_doc.to_dict()
                item_total = product_data['price'] * item['quantity']
                total_amount += item_total

                order_items.append({
                    'product_id': item['product_id'],
                    'name': product_data.get('name', 'Unknown Product'),
                    'description': product_data.get('description', ''),
                    'price': product_data['price'],
                    'quantity': item['quantity'],
                    'subtotal': item_total,
                    'image_url': product_data.get('image_url', '')
                })

        # Get user information
        user_ref = db.collection('users').document(current_user.id)
        user_doc = user_ref.get()
        user_data = user_doc.to_dict() if user_doc.exists else {}

        # Create order data
        import uuid
        order_id = str(uuid.uuid4())

        order_data = {
            'order_id': order_id,
            'user_id': current_user.id,
            'user_email': current_user.email,
            'user_name': f"{user_data.get('first_name', '')} {user_data.get('last_name', '')}".strip(),
            'user_phone': user_data.get('phone', ''),
            'user_address': user_data.get('address', ''),
            'items': order_items,
            'total_amount': total_amount,
            'status': 'pending',  # pending, processed, waiting_for_payment, bill_generated, delivered, closed
            'order_date': firestore.SERVER_TIMESTAMP,
            'updated_at': firestore.SERVER_TIMESTAMP
        }

        # Save order to database
        db.collection('orders').document(order_id).set(order_data)

        # Clear the cart
        cart_ref.set({'items': [], 'updated_at': firestore.SERVER_TIMESTAMP})

        flash(f'Order placed successfully! Your order ID is {order_id[:8].upper()}. Thank you for shopping with us.', 'success')

    except Exception as e:
        flash(f'Error processing checkout: {str(e)}', 'error')
        return redirect(url_for('cart'))

    return redirect(url_for('catalog'))

@app.route('/update_cart_quantity/<product_id>', methods=['POST'])
@login_required
def update_cart_quantity(product_id):
    quantity = int(request.form.get('quantity', 1))
    if quantity < 1:
        quantity = 1
    if db:
        try:
            cart_ref = db.collection('carts').document(current_user.id)
            cart_doc = cart_ref.get()
            if cart_doc.exists:
                cart_data = cart_doc.to_dict()
                items = cart_data.get('items', [])
                for item in items:
                    if item['product_id'] == product_id:
                        item['quantity'] = quantity
                        break
                cart_ref.set({'items': items, 'updated_at': firestore.SERVER_TIMESTAMP})
                flash('Cart updated!', 'success')
        except Exception as e:
            flash(f'Error updating cart: {str(e)}', 'error')
    return redirect(url_for('cart'))

@app.route('/remove_from_cart/<product_id>', methods=['POST'])
@login_required
def remove_from_cart(product_id):
    if db:
        try:
            cart_ref = db.collection('carts').document(current_user.id)
            cart_doc = cart_ref.get()
            if cart_doc.exists:
                cart_data = cart_doc.to_dict()
                items = cart_data.get('items', [])
                items = [item for item in items if item['product_id'] != product_id]
                cart_ref.set({'items': items, 'updated_at': firestore.SERVER_TIMESTAMP})
                flash('Product removed from cart!', 'success')
        except Exception as e:
            flash(f'Error removing from cart: {str(e)}', 'error')
    return redirect(url_for('cart'))

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        category = request.form['category']
        brand = request.form.get('brand', '')
        weight = request.form.get('weight', '')
        price = float(request.form['price'])
        stock_quantity = int(request.form.get('stock_quantity', 0))
        sku = request.form.get('sku', '')
        image_url = request.form.get('image_url', '')
        tags = request.form.get('tags', '')

        # Add product to Firestore
        if db:
            try:
                product_data = {
                    'name': name,
                    'description': description,
                    'category': category,
                    'brand': brand,
                    'weight': weight,
                    'price': price,
                    'stock_quantity': stock_quantity,
                    'sku': sku,
                    'image_url': image_url,
                    'tags': tags,
                    'created_at': firestore.SERVER_TIMESTAMP,
                    'updated_at': firestore.SERVER_TIMESTAMP
                }
                db.collection('products').add(product_data)
                flash('Product added successfully!', 'success')
                return redirect(url_for('products'))
            except Exception as e:
                flash(f'Error adding product: {str(e)}', 'error')
        else:
            flash('Database not available.', 'error')
    return render_template('add_product.html')

@app.route('/edit_product/<product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        category = request.form['category']
        brand = request.form.get('brand', '')
        weight = request.form.get('weight', '')
        dimensions = request.form.get('dimensions', '')
        price = float(request.form['price'])
        stock_quantity = int(request.form.get('stock_quantity', 0))
        sku = request.form.get('sku', '')
        image_url = request.form.get('image_url', '')
        tags = request.form.get('tags', '')

        # Update product in Firestore
        if db:
            try:
                product_ref = db.collection('products').document(product_id)
                product_ref.update({
                    'name': name,
                    'description': description,
                    'category': category,
                    'brand': brand,
                    'weight': weight,
                    'dimensions': dimensions,
                    'price': price,
                    'stock_quantity': stock_quantity,
                    'sku': sku,
                    'image_url': image_url,
                    'tags': tags,
                    'updated_at': firestore.SERVER_TIMESTAMP
                })
                flash('Product updated successfully!', 'success')
                return redirect(url_for('products'))
            except Exception as e:
                flash(f'Error updating product: {str(e)}', 'error')
        else:
            flash('Database not available.', 'error')
        return redirect(url_for('products'))

    # GET request: fetch product data
    if db:
        try:
            product_ref = db.collection('products').document(product_id)
            product = product_ref.get()
            if product.exists:
                product_data = product.to_dict()
                product_data['id'] = product.id
                return render_template('edit_product.html', product=product_data)
        except Exception as e:
            flash(f'Error fetching product: {str(e)}', 'error')
    else:
        flash('Database not available.', 'error')

    flash('Product not found.', 'error')
    return redirect(url_for('products'))

@app.route('/delete_product/<product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    if db:
        try:
            product_ref = db.collection('products').document(product_id)
            product_ref.delete()
            flash('Product deleted successfully!', 'success')
        except Exception as e:
            flash(f'Error deleting product: {str(e)}', 'error')
    else:
        flash('Database not available.', 'error')

    return redirect(url_for('products'))

@app.route('/purchase_register', methods=['GET', 'POST'])
@login_required
def purchase_register():
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    # Fetch all purchase bills
    purchase_bills = []
    if db:
        try:
            purchases_ref = db.collection('purchase_bills')
            purchases_docs = purchases_ref.stream()
            for purchase_doc in purchases_docs:
                purchase_data = purchase_doc.to_dict()
                purchase_data['id'] = purchase_doc.id
                purchase_bills.append(purchase_data)
        except Exception as e:
            print(f"Error fetching purchase bills: {e}")
            flash("Database temporarily unavailable. Some features may not work.", 'warning')

    return render_template('purchase_register.html', purchase_bills=purchase_bills)

@app.route('/add_purchase', methods=['GET', 'POST'])
@login_required
def add_purchase():
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    # Fetch available products for dropdown
    products = []
    if db:
        try:
            products_ref = db.collection('products')
            products_docs = products_ref.stream()
            for product_doc in products_docs:
                product_data = product_doc.to_dict()
                product_data['id'] = product_doc.id
                products.append(product_data)
        except Exception as e:
            print(f"Error fetching products: {e}")

    # Fetch available suppliers for dropdown
    suppliers = []
    if db:
        try:
            # Get unique suppliers from existing purchase bills
            suppliers_ref = db.collection('purchase_bills')
            suppliers_docs = suppliers_ref.stream()
            supplier_names = set()
            for supplier_doc in suppliers_docs:
                supplier_data = supplier_doc.to_dict()
                supplier_name = supplier_data.get('supplier_name', '').strip()
                if supplier_name:
                    supplier_names.add(supplier_name)
            suppliers = sorted(list(supplier_names))
        except Exception as e:
            print(f"Error fetching suppliers: {e}")

    if request.method == 'POST':
        supplier_name = request.form.get('supplier_name', '').strip()
        bill_number = request.form.get('bill_number', '')
        purchase_date = request.form['purchase_date']
        payment_made = float(request.form.get('payment_made', 0))
        notes = request.form.get('notes', '')

        # Process multiple products
        products_data = []
        total_amount = 0
        total_gst = 0

        # Get all product entries
        product_ids = request.form.getlist('product_id[]')
        quantities = request.form.getlist('quantity[]')
        rates = request.form.getlist('rate[]')
        mrps = request.form.getlist('mrp[]')
        discount_percents = request.form.getlist('discount_percent[]')
        gst_rates = request.form.getlist('gst_rate[]')

        for i in range(len(product_ids)):
            if product_ids[i] and quantities[i] and rates[i]:
                product_id = product_ids[i]
                quantity = int(quantities[i])
                rate = float(rates[i])
                mrp = float(mrps[i]) if mrps[i] else rate  # Use rate as default MRP if not provided
                discount_percent = float(discount_percents[i]) if discount_percents[i] else 0
                gst_rate = float(gst_rates[i]) if gst_rates[i] else 0

                # Find product name and SKU
                product_name = "Unknown Product"
                product_sku = ""
                for product in products:
                    if product['id'] == product_id:
                        product_name = product['name']
                        product_sku = product.get('sku', '')
                        break

                subtotal = quantity * rate
                discount_amount = subtotal * (discount_percent / 100)
                taxable_amount = subtotal - discount_amount
                gst_amount = taxable_amount * (gst_rate / 100)
                total_with_gst = taxable_amount + gst_amount

                product_data = {
                    'product_id': product_id,
                    'product_name': product_name,
                    'product_sku': product_sku,
                    'mrp': mrp,
                    'quantity': quantity,
                    'rate': rate,
                    'discount_percent': discount_percent,
                    'discount_amount': discount_amount,
                    'taxable_amount': taxable_amount,
                    'gst_rate': gst_rate,
                    'gst_amount': gst_amount,
                    'total_with_gst': total_with_gst
                }
                products_data.append(product_data)
                total_amount += taxable_amount
                total_gst += gst_amount

                # Check if MRP was modified and update product in database
                if db and mrp != rate:  # MRP is different from the original rate
                    try:
                        # Get current product data
                        product_ref = db.collection('products').document(product_id)
                        product_doc = product_ref.get()
                        if product_doc.exists:
                            current_price = product_doc.to_dict().get('price', 0)
                            # Only update if MRP is different from current price
                            if abs(float(mrp) - float(current_price)) > 0.01:  # Allow for small floating point differences
                                product_ref.update({
                                    'price': mrp,
                                    'updated_at': firestore.SERVER_TIMESTAMP
                                })
                                print(f"Updated MRP for product {product_name} from {current_price} to {mrp}")
                    except Exception as e:
                        print(f"Error updating product MRP: {str(e)}")

        grand_total = total_amount + total_gst
        balance = grand_total - payment_made

        # Add purchase bill to Firestore
        if db:
            try:
                purchase_data = {
                    'supplier_name': supplier_name,
                    'bill_number': bill_number,
                    'purchase_date': purchase_date,
                    'products': products_data,
                    'total_amount': total_amount,
                    'total_gst': total_gst,
                    'grand_total': grand_total,
                    'payment_made': payment_made,
                    'balance': balance,
                    'notes': notes,
                    'created_at': firestore.SERVER_TIMESTAMP,
                    'created_by': current_user.email
                }
                db.collection('purchase_bills').add(purchase_data)
                flash('Purchase bill added successfully!', 'success')
                return redirect(url_for('purchase_register'))
            except Exception as e:
                flash(f'Error adding purchase bill: {str(e)}', 'error')
        else:
            flash('Database not available.', 'error')
    return render_template('add_purchase.html', products=products, suppliers=suppliers)

@app.route('/delete_purchase/<purchase_id>', methods=['POST'])
@login_required
def delete_purchase(purchase_id):
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    if db:
        try:
            purchase_ref = db.collection('purchase_bills').document(purchase_id)
            purchase_ref.delete()
            flash('Purchase bill deleted successfully!', 'success')
        except Exception as e:
            flash(f'Error deleting purchase bill: {str(e)}', 'error')
    else:
        flash('Database not available.', 'error')

    return redirect(url_for('purchase_register'))

@app.route('/view_orders')
@login_required
def view_orders():
    orders = []

    if db:
        try:
            # Fetch orders for the current user (or all orders if admin)
            if current_user.is_admin():
                # Admin can see all orders
                orders_ref = db.collection('orders')
                orders_docs = orders_ref.stream()
            else:
                # Regular users can only see their own orders
                orders_ref = db.collection('orders').where('user_id', '==', current_user.id)
                orders_docs = orders_ref.stream()

            for order_doc in orders_docs:
                order_data = order_doc.to_dict()
                order_data['id'] = order_doc.id

                # Format order date
                if order_data.get('order_date'):
                    if hasattr(order_data['order_date'], 'strftime'):
                        order_data['date'] = order_data['order_date'].strftime('%Y-%m-%d %H:%M')
                    else:
                        order_data['date'] = str(order_data['order_date'])
                else:
                    order_data['date'] = 'N/A'

                orders.append(order_data)

            # Sort orders by date (newest first) since we can't use order_by in query
            orders.sort(key=lambda x: x.get('order_date') or '', reverse=True)

        except Exception as e:
            print(f"Error fetching orders: {str(e)}")
            flash("Error loading orders. Please try again.", 'error')

    return render_template('view_orders.html', orders=orders)

@app.route('/view_bills')
@login_required
def view_bills():
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    bills = []

    if db:
        try:
            # Fetch all bills from orders collection
            bills_ref = db.collection('orders')
            bills_docs = bills_ref.stream()

            for bill_doc in bills_docs:
                bill_data = bill_doc.to_dict()
                bill_data['id'] = bill_doc.id

                # Format bill date
                if bill_data.get('order_date'):
                    if hasattr(bill_data['order_date'], 'strftime'):
                        bill_data['date'] = bill_data['order_date'].strftime('%Y-%m-%d %H:%M')
                    else:
                        bill_data['date'] = str(bill_data['order_date'])
                else:
                    bill_data['date'] = 'N/A'

                bills.append(bill_data)

            # Sort bills by date (newest first)
            bills.sort(key=lambda x: x.get('order_date') or '', reverse=True)

        except Exception as e:
            print(f"Error fetching bills: {str(e)}")
            flash("Error loading bills. Please try again.", 'error')

    return render_template('view_bills.html', bills=bills)

@app.route('/update_bill_status/<bill_id>', methods=['POST'])
@login_required
def update_bill_status(bill_id):
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    new_status = request.form.get('status')
    valid_statuses = ['pending', 'processed', 'waiting_for_payment', 'bill_generated', 'delivered', 'closed']

    if new_status not in valid_statuses:
        flash("Invalid status.", 'error')
        return redirect(url_for('view_bills'))

    if db:
        try:
            bill_ref = db.collection('orders').document(bill_id)
            bill_ref.update({
                'status': new_status,
                'updated_at': firestore.SERVER_TIMESTAMP
            })
            flash(f"Bill status updated to '{new_status.replace('_', ' ').title()}'.", 'success')
        except Exception as e:
            print(f"Error updating bill status: {str(e)}")
            flash("Error updating bill status. Please try again.", 'error')
    else:
        flash('Database not available.', 'error')

    return redirect(url_for('view_bills'))

@app.route('/create_bill', methods=['GET', 'POST'])
@login_required
def create_bill():
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    # Fetch available products for dropdown
    products = []
    if db:
        try:
            products_ref = db.collection('products')
            products_docs = products_ref.stream()
            for product_doc in products_docs:
                product_data = product_doc.to_dict()
                product_data['id'] = product_doc.id
                products.append(product_data)
        except Exception as e:
            print(f"Error fetching products: {str(e)}")

    if request.method == 'POST':
        # For now, just redirect to view_bills since bill creation is complex
        # In a real implementation, this would create custom bills
        flash("Bill creation feature coming soon.", 'info')
        return redirect(url_for('view_bills'))

    return render_template('create_bill.html', products=products)

@app.route('/print_bill/<bill_id>')
@login_required
def print_bill(bill_id):
    if not current_user.is_admin():
        flash("Access denied. Admin privileges required.", 'error')
        return redirect(url_for('home'))

    # Fetch bill data
    if db:
        try:
            bill_doc = db.collection('orders').document(bill_id).get()
            if bill_doc.exists:
                bill_data = bill_doc.to_dict()
                bill_data['id'] = bill_id

                # Format order date
                if bill_data.get('order_date'):
                    if hasattr(bill_data['order_date'], 'strftime'):
                        bill_data['date'] = bill_data['order_date'].strftime('%Y-%m-%d %H:%M')
                    else:
                        bill_data['date'] = str(bill_data['order_date'])
                else:
                    bill_data['date'] = 'N/A'

                return render_template('print_bill.html', bill=bill_data)
            else:
                flash("Bill not found.", 'error')
        except Exception as e:
            print(f"Error fetching bill: {str(e)}")
            flash("Error loading bill. Please try again.", 'error')
    else:
        flash('Database not available.', 'error')

    return redirect(url_for('view_bills'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)