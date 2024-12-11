# IPhone Inventory Management System

This is a Flask-based web application for managing an inventory of iPhones. It includes features for adding, editing, and deleting products, as well as generating reports and managing users.

## Features

- User authentication and role-based access control
- Inventory management with product details
- Report generation in CSV and HTML formats
- Bug reporting and feedback submission
- Responsive design using Tailwind CSS

## Installation

### Prerequisites

- Python 3.7 or higher
- Virtualenv (optional but recommended)
- PostgreSQL or any other SQL database supported by SQLAlchemy

### Setup

1. **Clone the repository:**

   ```bash
   git clone https://github.com/JakubEth/iPhone-inventory.git
   cd iPhone-inventory
   ```

2. **Create a virtual environment:**

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows use `venv\Scripts\activate`
   ```

3. **Install the dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

4. **Set up the database:**

   - Ensure your database server is running.
   - Create a new database for the application.
   - Update the `SQLALCHEMY_DATABASE_URI` in `config.py` with your database connection string.

5. **Initialize the database:**

   ```bash
   flask db init
   flask db migrate
   flask db upgrade
   ```

6. **Populate the database with sample data:**

   The database will be automatically populated with sample data when you start the application if it's empty.

## Running the Application

1. **Start the Flask development server:**

   ```bash
   python3 app.py
   ```

   The application will be available at `http://127.0.0.1:5000`.

2. **Access the application:**

   - Open your web browser and go to `http://127.0.0.1:5000`.
   - Log in with the default admin credentials (if any) or create a new account.

## Usage

- **Manage Products:** Add, edit, or delete products in the inventory.
- **Generate Reports:** Download reports in CSV or HTML format.
- **User Management:** Admin users can manage other users and assign roles.
- **Submit Feedback:** Users can report bugs or provide feedback.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
