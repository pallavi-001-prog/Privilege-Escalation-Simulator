from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import json

db = SQLAlchemy()

class User(db.Model):
    """User model for authentication and authorization"""
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to scan results
    scan_results = db.relationship('ScanResult', backref='user', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'

class ScanResult(db.Model):
    """Model to store privilege escalation scan results"""
    __tablename__ = 'scan_results'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='pending')
    results_json = db.Column(db.Text)  # Store results as JSON string
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    
    def set_results(self, results):
        """Store scan results as JSON string"""
        self.results_json = json.dumps(results)
    
    def get_results(self):
        """Retrieve and parse scan results from JSON string"""
        if not self.results_json:
            return {}
        data = json.loads(self.results_json)
        # Ensure summary and risk fields exist to avoid template errors
        checks = data.get('checks', [])
        if 'summary' not in data or 'risk_level' not in data or 'risk_score' not in data:
            total_checks = len(checks)
            vulnerable = sum(1 for c in checks if c.get('status') == 'vulnerable')
            warnings = sum(1 for c in checks if c.get('status') == 'warning')
            safe = sum(1 for c in checks if c.get('status') == 'safe')
            if total_checks == 0:
                data['risk_score'] = 0
                data['risk_level'] = 'unknown'
                data['summary'] = {
                    'total_checks': 0,
                    'vulnerable': 0,
                    'warnings': 0,
                    'safe': 0
                }
            else:
                vulnerable_ratio = vulnerable / total_checks
                warning_ratio = warnings / total_checks
                risk_score = int(min(100, max(0, (vulnerable_ratio * 65 + warning_ratio * 20) * 100)))
                vulnerable_count = vulnerable
                if vulnerable_count >= 3 or (vulnerable_count >= 2 and vulnerable_ratio >= 0.5):
                    level = 'high'
                elif vulnerable_count == 1 or (0.2 <= vulnerable_ratio < 0.5):
                    level = 'medium'
                elif vulnerable_count == 0 and warnings > 0:
                    level = 'low'
                else:
                    level = 'minimal'
                data['risk_score'] = risk_score
                data['risk_level'] = level
                data['summary'] = {
                    'total_checks': total_checks,
                    'vulnerable': vulnerable,
                    'warnings': warnings,
                    'safe': safe
                }
            # Persist the repair silently
            try:
                self.set_results(data)
                db.session.commit()
            except Exception:
                db.session.rollback()
        return data
    
    def __repr__(self):
        return f'<ScanResult {self.id}: {self.scan_type}>'


