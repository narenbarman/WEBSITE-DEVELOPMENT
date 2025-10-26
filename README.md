# Barman Store

A comprehensive departmental store management system built with Flask, featuring user authentication, product management, inventory tracking, billing, and customer support.

## Features

### User Management
- **Email/Password Authentication**: Traditional login system
- **Social Login**: Facebook and Google OAuth integration (requires API credentials)
- **User Registration**: Account creation with email/phone verification
- **Role-based Access**: Customer and Administrator roles

### Product Management
- **Product Catalog**: Browse and search products
- **Inventory Management**: Stock tracking and updates
- **Product CRUD**: Add, edit, delete products (Admin only)
- **Category Organization**: Products organized by categories

### Shopping Features
- **Shopping Cart**: Add/remove items, quantity management
- **Checkout Process**: Complete order placement
- **Order History**: View past orders and status
- **Bill Generation**: Automatic bill creation and printing

### Administrative Tools
- **User Management**: View and manage all users
- **Purchase Register**: Track supplier purchases
- **Billing System**: Generate and manage bills
- **Support Tickets**: Handle customer support requests

### Customer Support
- **Support Ticket System**: Submit and track support requests
- **Admin Response System**: Administrators can respond to tickets
- **Status Tracking**: Monitor ticket progress
- **Help Center**: Comprehensive FAQ and guides

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd barman-store
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment variables**
   Create a `.env` file with the following variables:
   ```env
   # Flask Configuration
   SECRET_KEY=your-secret-key-here

   # Firebase Configuration (required)
   FIREBASE_PROJECT_ID=your-project-id
   FIREBASE_PRIVATE_KEY_ID=your-private-key-id
   FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"
   FIREBASE_CLIENT_EMAIL=your-client-email
   FIREBASE_CLIENT_ID=your-client-id
   FIREBASE_CLIENT_X509_CERT_URL=your-cert-url
   FIREBASE_API_KEY=your-api-key

   # OAuth Configuration (optional - for social login)
   FACEBOOK_APP_ID=your-facebook-app-id
   FACEBOOK_APP_SECRET=your-facebook-app-secret
   GOOGLE_CLIENT_ID=your-google-client-id
   GOOGLE_CLIENT_SECRET=your-google-client-secret
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

   Or use the batch file:
   ```bash
   run_app.bat
   ```

5. **Access the application**
   Open your browser and navigate to `http://localhost:5000`

## OAuth Setup (Optional)

### Facebook Login
1. Go to [Facebook Developers](https://developers.facebook.com/)
2. Create a new app
3. Add Facebook Login product
4. Configure OAuth redirect URIs: `http://localhost:5000/login/facebook/authorized`
5. Copy App ID and App Secret to `.env`

### Google Login
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable Google+ API
4. Create OAuth 2.0 credentials
5. Configure authorized redirect URIs: `http://localhost:5000/login/google/authorized`
6. Copy Client ID and Client Secret to `.env`

## Usage

### For Customers
1. **Register/Login**: Create account or login with email/social accounts
2. **Browse Products**: View catalog and add items to cart
3. **Checkout**: Complete purchase and track orders
4. **Support**: Submit tickets for assistance

### For Administrators
1. **Login**: Use admin credentials
2. **Manage Products**: Add/edit/delete products
3. **User Management**: View and manage users
4. **Handle Orders**: Process orders and generate bills
5. **Support**: Respond to customer tickets

## API Endpoints

### Authentication
- `GET /` - Home page
- `GET/POST /account` - Login/Register page
- `POST /logout` - Logout
- `GET /login/facebook` - Facebook OAuth
- `GET /login/google` - Google OAuth

### Products & Shopping
- `GET /catalog` - Product catalog
- `POST /add_to_cart/<product_id>` - Add to cart
- `GET /cart` - Shopping cart
- `POST /checkout` - Process order
- `GET /view_orders` - Order history

### Administration
- `GET /admin` - Admin dashboard
- `GET /products` - Product management
- `POST /add_product` - Add product
- `GET/POST /edit_product/<id>` - Edit product
- `POST /delete_product/<id>` - Delete product

### Support
- `GET/POST /support` - Customer support
- `GET /admin/support` - Admin support dashboard
- `GET/POST /admin/support/<id>` - Handle support ticket

## Database Schema

The application uses Firebase Firestore with the following collections:

- **users**: User accounts and profiles
- **products**: Product catalog
- **carts**: Shopping cart data
- **orders**: Customer orders
- **purchase_bills**: Supplier purchase records
- **support_tickets**: Customer support requests

## Security Features

- **Password hashing** for secure storage
- **Session management** with secure cookies
- **Role-based access control**
- **Email/Phone verification** for account security
- **OTP verification** for sensitive operations
- **Input validation** and sanitization

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please use the in-app support ticket system or contact the development team.

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