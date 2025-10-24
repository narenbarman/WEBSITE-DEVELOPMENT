# Barman Store

A Flask-based web application for managing a barman store, including user authentication, product management, purchases, and admin functionalities.

## Features

- User registration and login with Firebase authentication
- Product catalog and management
- Shopping cart functionality
- Purchase registration and tracking
- Admin panel for managing users and products
- Responsive web interface with Bootstrap

## Technologies Used

- **Backend**: Python Flask
- **Database**: Firebase Firestore
- **Authentication**: Firebase Auth
- **Frontend**: HTML, CSS, JavaScript, Bootstrap
- **Deployment**: Local development with batch script

## Project Structure

```
Barman Store/
├── app.py                 # Main Flask application
├── firebase_config.py     # Firebase configuration
├── requirements.txt       # Python dependencies
├── run_app.bat           # Batch script to run the app
├── .env                  # Environment variables
├── users.json            # User data (if used)
├── static/               # Static files (CSS, JS, assets)
│   ├── css/
│   ├── js/
│   └── assets/
├── templates/            # HTML templates
│   ├── home.html
│   ├── login.html
│   ├── register.html
│   ├── catalog.html
│   ├── cart.html
│   ├── account.html
│   ├── admin.html
│   └── ... (other templates)
└── .gitignore            # Git ignore file
```

## Getting Started

See [INSTRUCTIONS.md](INSTRUCTIONS.md) for detailed setup and usage instructions.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License.