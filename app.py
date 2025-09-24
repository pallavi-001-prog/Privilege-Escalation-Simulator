from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import sys
from scanner.scanner import PrivilegeEscalationScanner
from scanner.realtime_scanner import RealtimeVulnerabilityScanner
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Import models after db initialization
from auth.models import User, ScanResult, db

# Initialize the models database with the app
db.init_app(app)

# Import routes
from auth.routes import auth_bp

# Register blueprints
app.register_blueprint(auth_bp, url_prefix='/auth')

@app.route('/')
def index():
    """Home page with overview about privilege escalation"""
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """User dashboard to view scan history"""
    if 'user_id' not in session:
        flash('Please log in to access the dashboard.', 'error')
        return redirect(url_for('auth.login'))
    
    user = User.query.get(session['user_id'])
    scan_results = ScanResult.query.filter_by(user_id=user.id).order_by(ScanResult.created_at.desc(), ScanResult.id.desc()).all()
    
    return render_template('dashboard.html', user=user, scan_results=scan_results)

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    """Run privilege escalation scan"""
    if 'user_id' not in session:
        flash('Please log in to run scans.', 'error')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        try:
            # Initialize scanner
            scanner = PrivilegeEscalationScanner()
            
            # Run the scan
            results = scanner.run_scan()
            
            # Save results to database
            scan_result = ScanResult(
                user_id=session['user_id'],
                scan_type='privilege_escalation',
                status='completed',
                completed_at=datetime.utcnow()
            )
            # Persist results as JSON string
            scan_result.set_results(results)
            db.session.add(scan_result)
            db.session.commit()
            
            return render_template('results.html', results=results, scan_id=scan_result.id)
            
        except Exception as e:
            flash(f'Error running scan: {str(e)}', 'error')
            return redirect(url_for('dashboard'))
    
    return render_template('scan.html')

@app.route('/realtime-scan', methods=['GET', 'POST'])
def realtime_scan():
    """Run real-time vulnerability scan"""
    if 'user_id' not in session:
        flash('Please log in to run scans.', 'error')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        try:
            scan_type = request.form.get('scan_type', 'basic')
            
            # Initialize real-time scanner
            scanner = RealtimeVulnerabilityScanner()
            
            # Run the real-time scan
            results = scanner.run_realtime_scan(scan_type)
            
            # Save results to database
            scan_result = ScanResult(
                user_id=session['user_id'],
                scan_type=f'realtime_{scan_type}',
                status='completed',
                completed_at=datetime.utcnow()
            )
            # Persist results as JSON string
            scan_result.set_results(results)
            db.session.add(scan_result)
            db.session.commit()
            
            return render_template('realtime_results.html', results=results, scan_id=scan_result.id, scan_type=scan_type)
            
        except Exception as e:
            flash(f'Error running real-time scan: {str(e)}', 'error')
            return redirect(url_for('dashboard'))
    
    return render_template('realtime_scan.html')

@app.route('/results/<int:scan_id>')
def view_results(scan_id):
    """View specific scan results"""
    if 'user_id' not in session:
        flash('Please log in to view results.', 'error')
        return redirect(url_for('auth.login'))
    
    scan_result = ScanResult.query.get_or_404(scan_id)
    
    # Check if user owns this scan result
    if scan_result.user_id != session['user_id'] and not session.get('is_admin', False):
        flash('You do not have permission to view this scan result.', 'error')
        return redirect(url_for('dashboard'))
    
    # Normalize results to ensure risk and summary exist
    normalized_results = scan_result.get_results()
    return render_template('results.html', results=normalized_results, scan_id=scan_id)

def _recalculate_risk(results_dict):
    total_checks = len(results_dict.get('checks', []))
    if total_checks == 0:
        results_dict['risk_score'] = 0
        results_dict['risk_level'] = 'unknown'
        results_dict['summary'] = {'total_checks': 0, 'vulnerable': 0, 'warnings': 0, 'safe': 0}
        return results_dict
    vulnerable_count = sum(1 for c in results_dict['checks'] if c.get('status') == 'vulnerable')
    warning_count = sum(1 for c in results_dict['checks'] if c.get('status') == 'warning')
    safe_count = sum(1 for c in results_dict['checks'] if c.get('status') == 'safe')
    risk_score = int((vulnerable_count * 40 + warning_count * 20) / total_checks * 100)
    risk_score = min(100, max(0, risk_score))
    if risk_score >= 70:
        risk_level = 'high'
    elif risk_score >= 40:
        risk_level = 'medium'
    elif risk_score >= 10:
        risk_level = 'low'
    else:
        risk_level = 'minimal'
    results_dict['risk_score'] = risk_score
    results_dict['risk_level'] = risk_level
    results_dict['summary'] = {
        'total_checks': total_checks,
        'vulnerable': vulnerable_count,
        'warnings': warning_count,
        'safe': safe_count
    }
    return results_dict

@app.route('/remediate/<int:scan_id>/network-services', methods=['GET', 'POST'])
def remediate_network_services(scan_id):
    if 'user_id' not in session:
        flash('Please log in to remediate findings.', 'error')
        return redirect(url_for('auth.login'))
    scan_result = ScanResult.query.get_or_404(scan_id)
    if scan_result.user_id != session['user_id'] and not session.get('is_admin', False):
        flash('You do not have permission to modify this scan result.', 'error')
        return redirect(url_for('dashboard'))
    results = scan_result.get_results()
    # Locate the Network Services check
    network_check = None
    for check in results.get('checks', []):
        if check.get('name') == 'Network Services':
            network_check = check
            break
    if request.method == 'POST':
        # Apply a simulated fix: demote root services to non-root and mark as safe
        if network_check:
            network_check['status'] = 'safe'
            network_check['risk_level'] = 'low'
            network_check['description'] = 'Services configured to run with least privilege'
            network_check['details'] = ['Adjusted service users from root to dedicated users (simulated)']
            results = _recalculate_risk(results)
            scan_result.set_results(results)
            db.session.commit()
            flash('Applied simulated remediation for Network Services.', 'success')
            return redirect(url_for('view_results', scan_id=scan_id))
    return render_template('remediation_network.html', scan_id=scan_id, results=results, network_check=network_check)

@app.route('/admin')
def admin_dashboard():
    """Admin dashboard to view all scan histories"""
    if not session.get('is_admin', False):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
    
    # Get all scan results with user information
    scan_results = db.session.query(ScanResult, User).join(User).order_by(ScanResult.created_at.desc(), ScanResult.id.desc()).all()
    users = User.query.all()
    
    return render_template('admin.html', scan_results=scan_results, users=users)

@app.route('/admin/delete_scan/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    """Delete a scan result (admin only)"""
    if not session.get('is_admin', False):
        return jsonify({'success': False, 'message': 'Access denied'})
    
    scan_result = ScanResult.query.get_or_404(scan_id)
    db.session.delete(scan_result)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Scan result deleted successfully'})

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    """Delete a user and their scan results (admin only)"""
    if not session.get('is_admin', False):
        return jsonify({'success': False, 'message': 'Access denied'})
    
    user = User.query.get_or_404(user_id)
    
    # Delete user's scan results first
    ScanResult.query.filter_by(user_id=user_id).delete()
    
    # Delete the user
    db.session.delete(user)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'User and associated data deleted successfully'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        # Create admin user if it doesn't exist
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
            print("Admin user created: username='admin', password='admin123'")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
