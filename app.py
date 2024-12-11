from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, current_app, send_file
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_wtf.csrf import CSRFProtect
from db import db
from models import User, Role, AuditLog, user_roles, Item, BugReport, Feedback
from forms import ProductForm, UserForm, SignupForm, LoginForm, BugReportForm, FeedbackForm
from sqlalchemy import func
import csv
import io
from sqlalchemy.orm import joinedload
from datetime import datetime
from populate_inventory import initialize_inventory
from flask import abort

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'  # Update with your database URI
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = 'gyftydrfghuytftUYG'

    # Initialize SQLAlchemy with app
    db.init_app(app)

    # Initialize Flask-Login
    login_manager.init_app(app)

    # Initialize CSRF protection
    csrf = CSRFProtect(app)

    with app.app_context():
        db.create_all()  # Create tables for the models

    return app

app = create_app()

# Context processor to inject forms into all templates
@app.context_processor
def inject_forms():
    return {
        'bug_form': BugReportForm(),
        'feedback_form': FeedbackForm()
    }

@login_manager.user_loader
def load_user(user_id):
    with current_app.app_context():
        return db.session.query(User).options(joinedload(User.roles)).get(int(user_id))

# Decorator to require admin role
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.has_role('admin'):
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Example route to manage products
@app.route('/admin/products', methods=['GET', 'POST'])
@admin_required
def manage_products():
    form = ProductForm()
    page = request.args.get('page', 1, type=int)
    per_page = 5  # Number of items per page

    # Fetch items with pagination, ordered by ID in descending order
    items_paginated = Item.query.order_by(Item.id.desc()).paginate(page=page, per_page=per_page, error_out=False)

    if form.validate_on_submit():
        new_item = Item(
            model=form.model.data,
            color=form.color.data,
            memory=form.memory.data,
            serial_number=form.serial_number.data
        )
        db.session.add(new_item)
        db.session.commit()
        
        log_action(current_user.id, 'Add Product', f'Added product {new_item}')
        
        flash('Product added successfully!', 'success')
        return redirect(url_for('manage_products'))

    return render_template('admin/manage_products.html', items=items_paginated.items, form=form, pagination=items_paginated)

# Example route to manage users
@app.route('/admin/users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    form = UserForm()
    form.roles.choices = [(role.id, role.name) for role in Role.query.all()]
    page = request.args.get('page', 1, type=int)
    per_page = 5  # Number of users per page

    if form.validate_on_submit():
        user = User(email=form.email.data, password=generate_password_hash(form.password.data))
        user.roles = Role.query.filter(Role.id.in_(form.roles.data)).all()
        db.session.add(user)
        db.session.commit()
        flash('User added successfully!', 'success')
        return redirect(url_for('manage_users'))

    users_paginated = User.query.paginate(page=page, per_page=per_page, error_out=False)
    return render_template('admin/manage_users.html', form=form, users=users_paginated.items, pagination=users_paginated)

@app.route('/admin/users/edit/<int:user_id>', methods=['POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = UserForm(original_email=user.email)
    form.roles.choices = [(role.id, role.name) for role in Role.query.all()]

    if form.validate_on_submit():
        user.email = form.email.data
        if form.password.data:  # Only update password if a new one is provided
            user.password = generate_password_hash(form.password.data)
        user.roles = Role.query.filter(Role.id.in_(form.roles.data)).all()
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('manage_users'))
    else:
        # Flash form errors
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"Error in {getattr(form, field).label.text}: {error}", 'danger')
        return redirect(url_for('manage_users'))

@app.route('/admin/users/delete/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return '', 204

@app.route('/admin/products/edit/<int:item_id>', methods=['POST'])
@login_required
def edit_product(item_id):
    item = Item.query.get_or_404(item_id)
    form = ProductForm()
    
    if form.validate_on_submit():
        item.model = form.model.data
        item.color = form.color.data
        item.memory = form.memory.data
        item.serial_number = form.serial_number.data
        db.session.commit()
        log_action(current_user.id, 'Edit Product', f'Edited product {item}')
        flash('Product updated successfully!', 'success')
        return redirect(url_for('manage_products'))
    
    return render_template('edit_product.html', form=form, item=item)

@app.route('/admin/products/delete/<int:item_id>', methods=['POST'])
@admin_required
def delete_product(item_id):
    item = Item.query.get_or_404(item_id)
    data = request.get_json()
    comment = data.get('comment', '')
    reason = data.get('reason', '')

    db.session.delete(item)
    db.session.commit()

    log_action(
        current_user.id,
        'Delete Product',
        f'Deleted product {item}. Reason: {reason}. Comment: {comment}'
    )
    flash('Product deleted successfully!', 'success')
    return '', 204

def roles_required(*roles):
    """Decorator to restrict access to users with specific roles."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if not any(current_user.has_role(role) for role in roles):
                abort(403)  # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.errorhandler(403)
def forbidden(error):
    return render_template('403.html'), 403


# Define routes for user functionalities
@app.route('/inventory')
@login_required
@roles_required('admin', 'user')
def view_inventory():
    page = request.args.get('page', 1, type=int)
    items_paginated = Item.query.paginate(page=page, per_page=20)
    unique_models = Item.query.with_entities(Item.model).distinct().all()
    unique_models = [model[0] for model in unique_models]
    return render_template('inventory.html', items=items_paginated.items, pagination=items_paginated, unique_models=unique_models)

@app.route('/search', methods=['GET'])
@login_required
def search():
    query = request.args.get('query', '', type=str)
    page = request.args.get('page', 1, type=int)
    per_page = 5  # Number of search results per page

    if query:
        # Perform a case-insensitive search on relevant fields
        search_filter = (Item.model.ilike(f'%{query}%')) | \
                        (Item.color.ilike(f'%{query}%')) | \
                        (Item.memory.ilike(f'%{query}%')) | \
                        (Item.serial_number.ilike(f'%{query}%'))
        search_results_paginated = Item.query.filter(search_filter).order_by(Item.model.asc()).paginate(page=page, per_page=per_page, error_out=False)
    else:
        search_results_paginated = Item.query.order_by(Item.model.asc()).paginate(page=page, per_page=per_page, error_out=False)

    return render_template('search_results.html',
                           query=query,
                           search_results=search_results_paginated.items,
                           pagination=search_results_paginated)

@app.route('/recent_activities')
@login_required
def recent_activities():
    page = request.args.get('page', 1, type=int)
    per_page = 3  # Number of activities per page

    # Fetch the activities with pagination
    activities_paginated = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    recent_activities = []
    for activity in activities_paginated.items:
        item_details = None
        if 'product' in activity.details:
            serial_number = activity.details.split('-')[-1].strip('>')
            item = Item.query.filter_by(serial_number=serial_number).first()
            if item:
                item_details = {
                    'model': item.model,
                    'color': item.color,
                    'memory': item.memory,
                    'serial_number': item.serial_number
                }
        
        recent_activities.append({
            'action': activity.action,
            'timestamp': activity.timestamp,
            'details': activity.details,
            'item_details': item_details
        })
    
    return render_template('index.html', recent_activities=recent_activities, pagination=activities_paginated)

# Authentication Routes

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        
        user_role = Role.query.filter_by(name='user').first()
        if not user_role:
            flash('User role does not exist. Please contact the administrator.', 'danger')
            return redirect(url_for('signup'))
        
        new_user = User(email=form.email.data, password=hashed_password)
        new_user.roles.append(user_role)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/')
@login_required
def index():
    form = ProductForm()
    page = request.args.get('page', 1, type=int)
    per_page = 3  # Number of activities per page

    # Fetch the activities with pagination
    activities_paginated = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    recent_activities = []
    for activity in activities_paginated.items:
        item_details = None
        if 'product' in activity.details:
            # Extract the serial number from the details
            try:
                serial_number = activity.details.split('-')[-1].strip('> ')
                item = Item.query.filter_by(serial_number=serial_number).first()
                if item:
                    item_details = {
                        'model': item.model,
                        'color': item.color,
                        'memory': item.memory,
                        'serial_number': item.serial_number
                    }
            except IndexError:
                # Handle cases where the details format is unexpected
                serial_number = None

        recent_activities.append({
            'action': activity.action,
            'timestamp': activity.timestamp,
            'details': activity.details,
            'item_details': item_details
        })
    
    # Calculate total products
    total_products = Item.query.count()
    
    # Calculate alerts for invalid items
    alerts = Item.query.filter(
        (db.func.length(Item.serial_number) != 11) |
        (~Item.model.in_(Item.VALID_MODELS)) |
        (~Item.color.in_(Item.VALID_COLORS)) |
        (~Item.memory.in_(Item.VALID_MEMORIES))
    ).count()
    
    # Fetch items with invalid attributes
    alert_items = Item.query.filter(
        (db.func.length(Item.serial_number) != 11) |
        (~Item.model.in_(Item.VALID_MODELS)) |
        (~Item.color.in_(Item.VALID_COLORS)) |
        (~Item.memory.in_(Item.VALID_MEMORIES))
    ).all()
    
    return render_template(
        'index.html',
        recent_activities=recent_activities,
        total_products=total_products,
        alerts=alerts,  # Pass alerts to the template
        alert_items=alert_items,  # Pass items with invalid attributes
        pagination=activities_paginated,
        form=form  # Pass the form to the template
    )

def log_action(user_id, action, details=None):
    log_entry = AuditLog(user_id=user_id, action=action, details=details)
    db.session.add(log_entry)
    db.session.commit()

@app.route('/item/<serial_number>', methods=['GET', 'POST'])
@login_required
@roles_required('admin', 'user')
def item_detail(serial_number):
    item = Item.query.filter_by(serial_number=serial_number).first_or_404()
    # Assign image filename based on model and color
    model_number = item.model.replace('iPhone', '').replace(' ', '').lower()
    pro_suffix = 'pro' if 'pro' in item.model.lower() else ''
    color_clean = item.color.replace(' ', '').lower()
    image_filename = f'iphone{model_number}{pro_suffix}_{color_clean}.jpg'
    return render_template('item_detail.html', item=item, image_filename=image_filename)

@app.route('/reports')
@login_required
def generate_reports():
    # Total Products
    total_products = Item.query.count()

    # Breakdown by Model
    model_breakdown = db.session.query(Item.model, func.count(Item.id)).group_by(Item.model).all()

    # Breakdown by Color
    color_breakdown = db.session.query(Item.color, func.count(Item.id)).group_by(Item.color).all()

    # Breakdown by Memory
    memory_breakdown = db.session.query(Item.memory, func.count(Item.id)).group_by(Item.memory).all()

    # Alerts Summary
    alerts = db.session.query(Item).filter(
        (Item.model.notin_(Item.VALID_MODELS)) |
        (Item.color.notin_(Item.VALID_COLORS)) |
        (Item.memory.notin_(Item.VALID_MEMORIES)) |
        (func.length(Item.serial_number) != 11)
    ).count()

    # Recent Activities
    recent_activities = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(10).all()

    return render_template(
        'reports.html',
        total_products=total_products,
        model_breakdown=model_breakdown,
        color_breakdown=color_breakdown,
        memory_breakdown=memory_breakdown,
        alerts=alerts,
        recent_activities=recent_activities
    )

@app.route('/download_report')
@login_required
def download_report():
    # Ensure the user has the necessary permissions
    if not current_user.has_role('admin'):
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('index'))

    # Get the selected format from the request
    report_format = request.args.get('format', 'csv')

    # Fetch all items, users, and audit logs from the database
    items = Item.query.all()
    users = User.query.all()
    audit_logs = AuditLog.query.all()

    if report_format == 'html':
        # Render the report as an HTML string
        rendered_html = render_template('report.html', items=items, users=users, audit_logs=audit_logs)

        # Create a BytesIO object to hold the HTML content
        output = io.BytesIO()
        output.write(rendered_html.encode('utf-8'))
        output.seek(0)

        # Send the HTML file as a downloadable file
        return send_file(
            output,
            mimetype='text/html',
            as_attachment=True,
            download_name='warehouse_report.html'
        )
    else:
        # Create a CSV file in memory
        output = io.StringIO()
        writer = csv.writer(output)

        # Write CSV headers
        writer.writerow(['Model', 'Color', 'Memory', 'Serial Number'])

        # Write item data to CSV
        for item in items:
            writer.writerow([item.model, item.color, item.memory, item.serial_number])

        # Move the cursor to the beginning of the StringIO object
        output.seek(0)

        # Send the CSV file as a downloadable file
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name='warehouse_report.csv'
        )

@app.route('/report_bug', methods=['POST'])
def report_bug():
    form = BugReportForm()
    if form.validate_on_submit():
        bug = BugReport(
            user_id=current_user.id if current_user.is_authenticated else None,
            details=form.bug_details.data,
            timestamp=datetime.utcnow()
        )
        db.session.add(bug)
        db.session.commit()
        flash('Bug report submitted successfully!', 'success')
    else:
        flash('Please provide valid bug details.', 'danger')
    return redirect(url_for('index'))

@app.route('/feedback', methods=['POST'])
def feedback():
    form = FeedbackForm()
    if form.validate_on_submit():
        fb = Feedback(
            user_id=current_user.id if current_user.is_authenticated else None,
            details=form.feedback_details.data,
            timestamp=datetime.utcnow()
        )
        db.session.add(fb)
        db.session.commit()
        flash('Thank you for your feedback!', 'success')
    else:
        flash('Please provide valid feedback.', 'danger')
    return redirect(url_for('index'))

@app.route('/help')
def help():
    return render_template('help.html')

@app.route('/faq')
def faq():
    faqs = [
        {
            'question': 'How do I add a new item to the inventory?',
            'answer': 'Navigate to the "Manage Products" section in the Admin Panel and click on "Add New Product". Fill in the required details and submit the form.'
        },
        {
            'question': 'How can I generate reports?',
            'answer': 'Go to the "Reports" section in the header. Here you can generate various reports related to inventory, users, and activities.'
        },
        {
            'question': 'How do I reset my password?',
            'answer': 'Click on the "Login" link and then select "Forgot Password". Follow the instructions sent to your registered email to reset your password.'
        },
        {
            'question': 'Who can manage users?',
            'answer': 'Only users with the "admin" role have the permissions to manage other users. If you need access, please contact an existing administrator.'
        },
        # Add more FAQs as needed
    ]
    return render_template('faq.html', faqs=faqs)

@app.route('/user_guide')
def user_guide():
    return render_template('user_guide.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/terms_of_service')
def terms_of_service():
    return render_template('terms_of_service.html')

@app.route('/privacy_policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/item/<serial_number>/details', methods=['GET'])
@login_required
def item_details(serial_number):
    item = Item.query.filter_by(serial_number=serial_number).first_or_404()
    
    # Construct image filename based on your naming convention
    model_number = item.model.replace('iPhone', '').replace(' ', '').lower()
    pro_suffix = 'pro' if 'pro' not in model_number else ''
    color_clean = item.color.replace(' ', '').lower()
    image_filename = f'iphone{model_number}{pro_suffix}_{color_clean}.jpg'
    
    return render_template('item_detail_modal.html', item=item, image_filename=image_filename)

@app.route('/products/<int:item_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_product_route(item_id):
    item = Item.query.get_or_404(item_id)
    form = ProductForm(obj=item)  # Initialize the form with the item's current data

    if form.validate_on_submit():
        item.model = form.model.data
        item.color = form.color.data
        item.memory = form.memory.data
        item.serial_number = form.serial_number.data
        db.session.commit()
        log_action(current_user.id, 'Edit Product', f'Edited product {item}')
        flash('Product updated successfully!', 'success')
        return redirect(url_for('view_inventory'))

    return render_template('edit_product_form.html', form=form, item=item, image_filename=f'iphone{item.model.lower().replace(" ", "")}_{item.color.lower()}.jpg')

@app.route('/delete_product/<int:item_id>', methods=['POST'])
@login_required
@admin_required
def delete_product_route(item_id):
    item = Item.query.get_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    log_action(current_user.id, 'Delete Product', f'Deleted product {item}')
    return '', 204  # No Content

if __name__ == '__main__':
    initialize_inventory(app, db, Item)  # Pass the app, db, and Item to the function
    app.run(debug=True)
