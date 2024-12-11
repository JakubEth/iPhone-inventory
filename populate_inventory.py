from faker import Faker
import random
from models import Role  # Import the Role model

def clear_inventory(app, db, Item):
    with app.app_context():
        db.session.query(Item).delete()
        db.session.commit()
        print("Successfully cleared the inventory.")

def populate_inventory(app, db, Item, num_items=50):
    fake = Faker()
    models = ['iPhone 12', 'iPhone 12 Pro', 'iPhone 13', 'iPhone 13 Pro', 'iPhone 14', 'iPhone 14 Pro']
    colors = ['Black', 'White', 'Red']
    memories = ['64GB', '128GB', '256GB', '512GB']

    with app.app_context():
        for _ in range(num_items):
            model = random.choice(models)
            color = random.choice(colors)
            memory = random.choice(memories)
            serial_number = fake.unique.bothify(text='??#####????')  # Example: AB12345XYZ

            item = Item(
                model=model,
                color=color,
                memory=memory,
                serial_number=serial_number
            )
            db.session.add(item)
        
        db.session.commit()
        print(f"Successfully added {num_items} items to the inventory.")

def initialize_roles(app, db):
    with app.app_context():
        # Define default roles
        default_roles = ['admin', 'user']
        
        # Check and add roles if they don't exist
        for role_name in default_roles:
            if not Role.query.filter_by(name=role_name).first():
                new_role = Role(name=role_name)
                db.session.add(new_role)
        
        db.session.commit()
        print("Roles initialized successfully.")

def initialize_inventory(app, db, Item):
    with app.app_context():
        # Initialize roles
        initialize_roles(app, db)
        
        # Check if inventory is empty and populate if necessary
        if Item.query.count() == 0:
            print("Inventory is empty. Populating with sample data...")
            populate_inventory(app, db, Item)
        else:
            print("Inventory already populated. Skipping population.")

if __name__ == '__main__':
    clear_inventory()
    populate_inventory()