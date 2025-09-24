#!/usr/bin/env python3
"""
Simple test script to verify the privilege escalation scanner application works.
"""

import sys
import os

def test_imports():
    """Test that all modules can be imported without errors."""
    print("Testing imports...")
    
    try:
        from app import app, db
        print("✓ Main app imports successfully")
    except Exception as e:
        print(f"✗ Failed to import main app: {e}")
        return False
    
    try:
        from auth.models import User, ScanResult
        print("✓ Auth models import successfully")
    except Exception as e:
        print(f"✗ Failed to import auth models: {e}")
        return False
    
    try:
        from scanner.scanner import PrivilegeEscalationScanner
        print("✓ Scanner module imports successfully")
    except Exception as e:
        print(f"✗ Failed to import scanner: {e}")
        return False
    
    return True

def test_scanner():
    """Test the privilege escalation scanner."""
    print("\nTesting scanner...")
    
    try:
        from scanner.scanner import PrivilegeEscalationScanner
        
        scanner = PrivilegeEscalationScanner()
        results = scanner.run_scan()
        
        # Check if results have expected structure
        required_keys = ['scan_info', 'checks', 'risk_score', 'risk_level', 'summary']
        for key in required_keys:
            if key not in results:
                print(f"✗ Missing key in results: {key}")
                return False
        
        print(f"✓ Scanner completed successfully")
        print(f"  - Risk Score: {results['risk_score']}%")
        print(f"  - Risk Level: {results['risk_level']}")
        print(f"  - Total Checks: {len(results['checks'])}")
        
        return True
        
    except Exception as e:
        print(f"✗ Scanner test failed: {e}")
        return False

def test_database():
    """Test database operations."""
    print("\nTesting database...")
    
    try:
        from app import app, db
        from auth.models import User, ScanResult
        
        with app.app_context():
            # Create tables
            db.create_all()
            print("✓ Database tables created successfully")
            
            # Test user creation
            test_user = User(
                username='test_user',
                email='test@example.com',
                password_hash='test_hash',
                role='user'
            )
            db.session.add(test_user)
            db.session.commit()
            print("✓ User creation test passed")
            
            # Test scan result creation
            test_scan = ScanResult(
                user_id=test_user.id,
                scan_type='test_scan',
                results='{"test": "data"}',
                status='completed'
            )
            db.session.add(test_scan)
            db.session.commit()
            print("✓ Scan result creation test passed")
            
            # Clean up
            db.session.delete(test_scan)
            db.session.delete(test_user)
            db.session.commit()
            print("✓ Database cleanup completed")
            
        return True
        
    except Exception as e:
        print(f"✗ Database test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("Privilege Escalation Scanner - Test Suite")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_scanner,
        test_database
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("✓ All tests passed! The application should work correctly.")
        return 0
    else:
        print("✗ Some tests failed. Please check the errors above.")
        return 1

if __name__ == '__main__':
    sys.exit(main())





