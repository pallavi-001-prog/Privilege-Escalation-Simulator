#!/usr/bin/env python3
"""
Startup script for the Privilege Escalation Scanner application.
"""

import os
import sys
from app import app, db
from auth.models import User, ScanResult
from werkzeug.security import generate_password_hash

def setup_database():
    """Initialize the database and create admin user if needed."""
    with app.app_context():
        # Create all tables
        db.create_all()
        print("✓ Database tables created/verified")
        
        # Check if admin user exists
        admin_user = User.query.filter_by(username='admin').first()
        if not admin_user:
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin123'),
                role='admin'
            )
            db.session.add(admin)
            db.session.commit()
            print("✓ Admin user created: username='admin', password='admin123'")
        else:
            print("✓ Admin user already exists")

def main():
    """Main startup function."""
    print("Privilege Escalation Scanner")
    print("=" * 40)
    print("Starting application...")
    
    try:
        # Setup database
        setup_database()
        
        # Get configuration
        host = os.getenv('HOST', '0.0.0.0')
        port = int(os.getenv('PORT', 5000))
        debug = os.getenv('FLASK_ENV') == 'development'
        
        print(f"✓ Server starting on {host}:{port}")
        print(f"✓ Debug mode: {'ON' if debug else 'OFF'}")
        print("=" * 40)
        print("Access the application at:")
        print(f"  http://localhost:{port}")
        print("\nDefault admin credentials:")
        print("  Username: admin")
        print("  Password: admin123")
        print("=" * 40)
        
        # Start the application
        app.run(host=host, port=port, debug=debug)
        
    except KeyboardInterrupt:
        print("\n\nApplication stopped by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Error starting application: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()


