# Privilege Escalation Scanner

A web-based educational tool for learning about privilege escalation vulnerabilities and security best practices.

## 🎯 Overview

This application simulates privilege escalation vulnerability scanning in a safe, educational environment. It's designed to help students and researchers understand common security vulnerabilities without the risks associated with real penetration testing.

## ⚠️ Important Notice

**This tool is for educational purposes only!** It simulates vulnerability checks and should never be used for actual penetration testing or malicious purposes.

## 🚀 Features

### User Features
- **User Registration & Authentication** - Secure login system with role-based access
- **Interactive Scanning** - Run simulated privilege escalation scans
- **Detailed Results** - View comprehensive scan results with risk assessments
- **Scan History** - Track and manage your scan history
- **Responsive UI** - Modern, mobile-friendly interface

### Admin Features
- **User Management** - View and manage all registered users
- **Scan Monitoring** - Monitor all scan activities across the platform
- **Data Management** - Delete users and scan results as needed

### Security Checks
The scanner simulates checks for:
- Sudo configuration vulnerabilities
- SUID file exploits
- World-writable file permissions
- Cron job vulnerabilities
- Environment variable issues
- Network service misconfigurations
- File permission problems
- User group memberships
- Recent login activity
- Vulnerable package installations

## 🛠️ Tech Stack

- **Backend**: Python Flask
- **Database**: SQLite (development) / PostgreSQL (production)
- **Frontend**: HTML5, CSS3, Bootstrap 5, JavaScript
- **Authentication**: Flask-SQLAlchemy with Werkzeug security

## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)

### Setup Instructions

1. **Clone or download the project**
   ```bash
   git clone <repository-url>
   cd privilege-escalation-web
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Access the application**
   - Open your browser and go to `http://localhost:5000`
   - Default admin credentials: `admin` / `admin123`

## 🗂️ Project Structure

```
privilege-escalation-web/
│
├── app.py                    # Main Flask application
├── requirements.txt          # Python dependencies
├── README.md                # This file
│
├── auth/                    # Authentication module
│   ├── __init__.py
│   ├── models.py            # User and database models
│   └── routes.py            # Login/register routes
│
├── scanner/                 # Scanner module
│   ├── __init__.py
│   └── scanner.py           # Privilege escalation logic
│
├── templates/               # HTML templates
│   ├── base.html            # Base template
│   ├── index.html           # Homepage
│   ├── login.html           # Login page
│   ├── register.html        # Registration page
│   ├── dashboard.html       # User dashboard
│   ├── scan.html            # Scan interface
│   ├── results.html         # Scan results
│   └── admin.html           # Admin dashboard
│
└── static/                  # Static assets
    ├── style.css            # Custom CSS
    └── script.js            # JavaScript functionality
```

## 🔧 Configuration

### Environment Variables
You can configure the application using environment variables:

- `FLASK_ENV` - Set to `development` or `production`
- `SECRET_KEY` - Flask secret key for sessions
- `DATABASE_URL` - Database connection string

### Database
The application uses SQLite by default for development. For production, consider using PostgreSQL:

```python
# In app.py, change the database URI
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://user:password@localhost/dbname'
```

## 🚀 Deployment

### Heroku
1. Create a `Procfile`:
   ```
   web: gunicorn app:app
   ```

2. Add PostgreSQL addon:
   ```bash
   heroku addons:create heroku-postgresql:hobby-dev
   ```

3. Deploy:
   ```bash
   git push heroku main
   ```

### Render
1. Connect your GitHub repository
2. Set build command: `pip install -r requirements.txt`
3. Set start command: `gunicorn app:app`
4. Add environment variables as needed

## 📚 Usage Guide

### For Students/Researchers

1. **Register an Account**
   - Click "Register" and create your account
   - Use a valid email address

2. **Run a Scan**
   - Go to "Run Scan" from the dashboard
   - Click "Start Scan" to begin the simulation
   - Wait for results (usually takes a few seconds)

3. **View Results**
   - Results are displayed with color-coded risk levels
   - High risk = Red, Medium risk = Yellow, Low risk = Green
   - Click on individual checks for detailed information

4. **Track History**
   - View all your scans in the dashboard
   - Access previous results anytime

### For Administrators

1. **Login with Admin Account**
   - Use the default admin credentials or create an admin user

2. **Monitor Users**
   - View all registered users
   - Delete users if necessary

3. **Manage Scans**
   - View all scan results across the platform
   - Delete individual scan results

## 🔒 Security Features

- **Password Hashing** - All passwords are securely hashed using Werkzeug
- **Session Management** - Secure session handling with Flask
- **Input Validation** - All user inputs are validated
- **SQL Injection Protection** - Using SQLAlchemy ORM
- **XSS Protection** - Jinja2 auto-escaping enabled

## 🐛 Troubleshooting

### Common Issues

1. **Database Errors**
   - Delete `database.db` and restart the application
   - Check database permissions

2. **Import Errors**
   - Ensure virtual environment is activated
   - Run `pip install -r requirements.txt`

3. **Port Already in Use**
   - Change the port in `app.py`: `app.run(port=5001)`

### Debug Mode
To enable debug mode, set the environment variable:
```bash
export FLASK_ENV=development
```

## 🤝 Contributing

This is an educational project. If you'd like to contribute:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is for educational purposes only. Please use responsibly and in accordance with your institution's policies.

## ⚠️ Disclaimer

This tool is designed for educational purposes only. The authors are not responsible for any misuse of this software. Users are responsible for ensuring they have proper authorization before testing any systems.

## 📞 Support

For questions or issues:
- Check the troubleshooting section above
- Review the code comments for implementation details
- Ensure you're using the correct Python version

---

**Remember: This tool is for learning purposes only. Always follow ethical guidelines and obtain proper authorization before testing any systems.**





