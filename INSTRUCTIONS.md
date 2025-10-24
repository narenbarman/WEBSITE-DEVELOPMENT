# Barman Store - Setup and Usage Instructions

## Prerequisites

- Python 3.8 or higher
- Firebase project with Firestore and Authentication enabled
- Firebase Admin SDK key file

## Installation

1. **Clone or download the project**:
   ```
   git clone <repository-url>
   cd "Barman Store"
   ```

2. **Create a virtual environment** (recommended):
   ```
   python -m venv venv
   venv\Scripts\activate  # On Windows
   ```

3. **Install dependencies**:
   ```
   pip install -r requirements.txt
   ```

4. **Set up Firebase**:
   - Create a Firebase project at https://console.firebase.google.com/
   - Enable Firestore Database
   - Enable Authentication (Email/Password)
   - Generate a private key for your service account:
     - Go to Project Settings > Service Accounts
     - Click "Generate new private key"
     - Save the JSON file as `firebase_config.py` or update the path in the code

5. **Configure environment variables**:
   - Copy `.env.example` to `.env` (if exists) or create a `.env` file
   - Add your Firebase configuration:
     ```
     FIREBASE_PROJECT_ID=your-project-id
     FIREBASE_PRIVATE_KEY_ID=your-private-key-id
     FIREBASE_PRIVATE_KEY=your-private-key
     FIREBASE_CLIENT_EMAIL=your-client-email
     FIREBASE_CLIENT_ID=your-client-id
     FIREBASE_AUTH_URI=https://accounts.google.com/o/oauth2/auth
     FIREBASE_TOKEN_URI=https://oauth2.googleapis.com/token
     FIREBASE_AUTH_PROVIDER_CERT_URL=https://www.googleapis.com/oauth2/v1/certs
     FIREBASE_CLIENT_CERT_URL=your-client-cert-url
     ```

## Running the Application

### Option 1: Using the batch script (Windows)
Double-click `run_app.bat` or run it from command prompt:
```
run_app.bat
```

### Option 2: Manual execution
1. Activate virtual environment (if used):
   ```
   venv\Scripts\activate
   ```

2. Run the Flask app:
   ```
   python app.py
   ```

The application will start on `http://localhost:5000`

## Usage

### User Registration and Login
1. Navigate to the home page
2. Click "Register" to create a new account
3. Use your email and password to log in

### Browsing Products
- Visit the "Catalog" page to view available products
- Use the search and filter options

### Shopping Cart
- Add products to your cart from the catalog
- View and manage items in your cart
- Proceed to checkout

### Admin Features
- Log in with admin credentials
- Access the admin panel to:
  - Manage products (add, edit, delete)
  - Manage users
  - View purchase records

## Project Structure

```
Barman Store/
├── app.py                 # Main application file
├── firebase_config.py     # Firebase configuration
├── requirements.txt       # Python dependencies
├── .env                   # Environment variables
├── run_app.bat           # Windows batch script
├── static/               # Static files
│   ├── css/
│   ├── js/
│   └── assets/
└── templates/            # HTML templates
    ├── home.html
    ├── login.html
    ├── register.html
    └── ...
```

## Troubleshooting

### Common Issues

1. **Firebase connection errors**:
   - Verify your Firebase credentials in `.env`
   - Ensure the service account key file is in the correct location
   - Check Firebase project settings

2. **Port already in use**:
   - Change the port in `app.py` or kill the process using port 5000

3. **Import errors**:
   - Ensure all dependencies are installed: `pip install -r requirements.txt`
   - Activate virtual environment if used

4. **Template not found errors**:
   - Ensure all template files are in the `templates/` directory
   - Check file paths in the code

### Development Mode

To run in debug mode, modify `app.py`:
```python
if __name__ == '__main__':
    app.run(debug=True)
```

## Contributing

1. Follow the existing code style
2. Test your changes thoroughly
3. Update documentation as needed
4. Submit a pull request

## Support

For issues or questions, please check the project documentation or create an issue in the repository.