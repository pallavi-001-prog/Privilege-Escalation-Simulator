import os
import subprocess
import platform
import json
from datetime import datetime

class PrivilegeEscalationScanner:
    """
    Educational privilege escalation vulnerability scanner.
    This is for demonstration purposes only and simulates common checks.
    """
    
    def __init__(self):
        self.results = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'platform': platform.system(),
                'hostname': platform.node(),
                'user': os.getenv('USER', os.getenv('USERNAME', 'unknown'))
            },
            'checks': []
        }
    
    def run_scan(self):
        """Run all privilege escalation checks"""
        print("Starting privilege escalation vulnerability scan...")
        
        # Run various privilege escalation checkswhy
        self._check_sudo_configuration()
        self._check_suid_files()
        self._check_world_writable_files()
        self._check_cron_jobs()
        self._check_environment_variables()
        self._check_network_services()
        self._check_file_permissions()
        self._check_user_groups()
        self._check_recent_logins()
        self._check_installed_packages()
        
        # Calculate overall risk score
        self._calculate_risk_score()
        
        print("Scan completed!")
        return self.results
    
    def _add_check_result(self, check_name, status, description, details=None, risk_level='medium'):
        """Add a check result to the scan results"""
        self.results['checks'].append({
            'name': check_name,
            'status': status,  # 'safe', 'vulnerable', 'warning', 'info'
            'description': description,
            'details': details or [],
            'risk_level': risk_level,
            'timestamp': datetime.now().isoformat()
        })
    
    def _check_sudo_configuration(self):
        """Check for sudo misconfigurations"""
        try:
            # Simulate checking sudo configuration
            sudo_configs = [
                "NOPASSWD: ALL",
                "ALL=(ALL) NOPASSWD: ALL",
                "ALL=(ALL) ALL"
            ]
            
            # Simulate finding a vulnerable sudo configuration
            vulnerable_config = "NOPASSWD: ALL"
            
            if vulnerable_config in sudo_configs:
                self._add_check_result(
                    "Sudo Configuration",
                    "vulnerable",
                    "Found sudo configuration that allows passwordless access",
                    ["User can run sudo without password", "Configuration: NOPASSWD: ALL"],
                    "high"
                )
            else:
                self._add_check_result(
                    "Sudo Configuration",
                    "safe",
                    "Sudo configuration appears secure",
                    ["No passwordless sudo configurations found"],
                    "low"
                )
        except Exception as e:
            self._add_check_result(
                "Sudo Configuration",
                "warning",
                "Could not check sudo configuration",
                [f"Error: {str(e)}"],
                "medium"
            )
    
    def _check_suid_files(self):
        """Check for SUID files that might be exploitable"""
        try:
            # Simulate finding SUID files
            suid_files = [
                "/usr/bin/passwd",
                "/usr/bin/sudo",
                "/bin/su",
                "/usr/bin/find",  # This could be exploitable
                "/usr/bin/nmap"   # This could be exploitable
            ]
            
            exploitable_suid = ["/usr/bin/find", "/usr/bin/nmap"]
            
            if exploitable_suid:
                self._add_check_result(
                    "SUID Files",
                    "vulnerable",
                    "Found potentially exploitable SUID files",
                    [f"Potentially exploitable: {', '.join(exploitable_suid)}"],
                    "high"
                )
            else:
                self._add_check_result(
                    "SUID Files",
                    "safe",
                    "No exploitable SUID files found",
                    ["All SUID files appear to be standard system files"],
                    "low"
                )
        except Exception as e:
            self._add_check_result(
                "SUID Files",
                "warning",
                "Could not check SUID files",
                [f"Error: {str(e)}"],
                "medium"
            )
    
    def _check_world_writable_files(self):
        """Check for world-writable files in sensitive locations"""
        try:
            # Simulate finding world-writable files
            world_writable = [
                "/tmp/test_file",
                "/var/tmp/backup",
                "/home/user/.bashrc"  # This would be concerning
            ]
            
            sensitive_writable = ["/home/user/.bashrc"]
            
            if sensitive_writable:
                self._add_check_result(
                    "World-Writable Files",
                    "vulnerable",
                    "Found world-writable files in sensitive locations",
                    [f"Sensitive files: {', '.join(sensitive_writable)}"],
                    "high"
                )
            else:
                self._add_check_result(
                    "World-Writable Files",
                    "safe",
                    "No sensitive world-writable files found",
                    ["Only temporary files are world-writable"],
                    "low"
                )
        except Exception as e:
            self._add_check_result(
                "World-Writable Files",
                "warning",
                "Could not check world-writable files",
                [f"Error: {str(e)}"],
                "medium"
            )
    
    def _check_cron_jobs(self):
        """Check for exploitable cron jobs"""
        try:
            # Simulate checking cron jobs
            cron_jobs = [
                "*/5 * * * * /usr/bin/backup.sh",
                "0 2 * * * /home/user/cleanup.sh",
                "* * * * * /tmp/script.sh"  # This would be concerning
            ]
            
            suspicious_cron = ["* * * * * /tmp/script.sh"]
            
            if suspicious_cron:
                self._add_check_result(
                    "Cron Jobs",
                    "vulnerable",
                    "Found suspicious cron jobs",
                    [f"Suspicious jobs: {', '.join(suspicious_cron)}"],
                    "high"
                )
            else:
                self._add_check_result(
                    "Cron Jobs",
                    "safe",
                    "Cron jobs appear normal",
                    ["No suspicious cron jobs found"],
                    "low"
                )
        except Exception as e:
            self._add_check_result(
                "Cron Jobs",
                "warning",
                "Could not check cron jobs",
                [f"Error: {str(e)}"],
                "medium"
            )
    
    def _check_environment_variables(self):
        """Check for dangerous environment variables"""
        try:
            # Simulate checking environment variables
            dangerous_vars = {
                "PATH": "/tmp:/usr/local/bin:/usr/bin:/bin",
                "LD_PRELOAD": "/tmp/malicious.so",
                "LD_LIBRARY_PATH": "/tmp"
            }
            
            found_dangerous = []
            for var, value in dangerous_vars.items():
                if "/tmp" in value:
                    found_dangerous.append(f"{var}={value}")
            
            if found_dangerous:
                self._add_check_result(
                    "Environment Variables",
                    "vulnerable",
                    "Found dangerous environment variables",
                    found_dangerous,
                    "high"
                )
            else:
                self._add_check_result(
                    "Environment Variables",
                    "safe",
                    "Environment variables appear secure",
                    ["No dangerous environment variables found"],
                    "low"
                )
        except Exception as e:
            self._add_check_result(
                "Environment Variables",
                "warning",
                "Could not check environment variables",
                [f"Error: {str(e)}"],
                "medium"
            )
    
    def _check_network_services(self):
        """Check for network services running with elevated privileges"""
        try:
            # Simulate checking network services
            services = [
                {"name": "ssh", "port": 22, "user": "root"},
                {"name": "apache2", "port": 80, "user": "www-data"},
                {"name": "mysql", "port": 3306, "user": "mysql"},
                {"name": "custom_service", "port": 8080, "user": "root"}  # Concerning
            ]
            
            root_services = [s for s in services if s["user"] == "root"]
            
            if len(root_services) > 2:  # More than just SSH and one other
                self._add_check_result(
                    "Network Services",
                    "warning",
                    "Multiple services running as root",
                    [f"{s['name']} running as {s['user']}" for s in root_services],
                    "medium"
                )
            else:
                self._add_check_result(
                    "Network Services",
                    "safe",
                    "Network services running with appropriate privileges",
                    [f"{s['name']} running as {s['user']}" for s in services],
                    "low"
                )
        except Exception as e:
            self._add_check_result(
                "Network Services",
                "warning",
                "Could not check network services",
                [f"Error: {str(e)}"],
                "medium"
            )
    
    def _check_file_permissions(self):
        """Check for files with incorrect permissions"""
        try:
            # Simulate checking file permissions
            sensitive_files = [
                "/etc/passwd",
                "/etc/shadow",
                "/etc/sudoers",
                "/etc/ssh/sshd_config"
            ]
            
            # Simulate finding a file with incorrect permissions
            incorrect_perms = ["/etc/shadow (644 instead of 640)"]
            
            if incorrect_perms:
                self._add_check_result(
                    "File Permissions",
                    "vulnerable",
                    "Found files with incorrect permissions",
                    incorrect_perms,
                    "high"
                )
            else:
                self._add_check_result(
                    "File Permissions",
                    "safe",
                    "Sensitive files have correct permissions",
                    ["All checked files have appropriate permissions"],
                    "low"
                )
        except Exception as e:
            self._add_check_result(
                "File Permissions",
                "warning",
                "Could not check file permissions",
                [f"Error: {str(e)}"],
                "medium"
            )
    
    def _check_user_groups(self):
        """Check user group memberships for privilege escalation opportunities"""
        try:
            # Simulate checking user groups
            user_groups = ["users", "sudo", "docker", "admin"]
            
            privileged_groups = [g for g in user_groups if g in ["sudo", "docker", "admin"]]
            
            if privileged_groups:
                self._add_check_result(
                    "User Groups",
                    "info",
                    "User is member of privileged groups",
                    [f"Member of: {', '.join(privileged_groups)}"],
                    "medium"
                )
            else:
                self._add_check_result(
                    "User Groups",
                    "safe",
                    "User has minimal group memberships",
                    ["No privileged group memberships found"],
                    "low"
                )
        except Exception as e:
            self._add_check_result(
                "User Groups",
                "warning",
                "Could not check user groups",
                [f"Error: {str(e)}"],
                "medium"
            )
    
    def _check_recent_logins(self):
        """Check for recent login activity"""
        try:
            # Simulate checking recent logins
            recent_logins = [
                {"user": "root", "time": "2024-01-15 10:30:00", "ip": "192.168.1.100"},
                {"user": "admin", "time": "2024-01-15 09:15:00", "ip": "192.168.1.101"},
                {"user": "user", "time": "2024-01-15 08:45:00", "ip": "192.168.1.102"}
            ]
            
            root_logins = [login for login in recent_logins if login["user"] == "root"]
            
            if root_logins:
                self._add_check_result(
                    "Recent Logins",
                    "info",
                    "Recent root login activity detected",
                    [f"Root login at {login['time']} from {login['ip']}" for login in root_logins],
                    "medium"
                )
            else:
                self._add_check_result(
                    "Recent Logins",
                    "safe",
                    "No recent root login activity",
                    ["No root logins in recent history"],
                    "low"
                )
        except Exception as e:
            self._add_check_result(
                "Recent Logins",
                "warning",
                "Could not check recent logins",
                [f"Error: {str(e)}"],
                "medium"
            )
    
    def _check_installed_packages(self):
        """Check for potentially vulnerable installed packages"""
        try:
            # Simulate checking installed packages
            packages = [
                {"name": "openssh-server", "version": "8.2p1", "vulnerable": False},
                {"name": "apache2", "version": "2.4.41", "vulnerable": False},
                {"name": "mysql-server", "version": "8.0.25", "vulnerable": True},
                {"name": "python3", "version": "3.8.10", "vulnerable": False}
            ]
            
            vulnerable_packages = [pkg for pkg in packages if pkg["vulnerable"]]
            
            if vulnerable_packages:
                self._add_check_result(
                    "Installed Packages",
                    "vulnerable",
                    "Found potentially vulnerable packages",
                    [f"{pkg['name']} {pkg['version']} - Known vulnerabilities" for pkg in vulnerable_packages],
                    "high"
                )
            else:
                self._add_check_result(
                    "Installed Packages",
                    "safe",
                    "No known vulnerable packages found",
                    ["All checked packages appear to be up to date"],
                    "low"
                )
        except Exception as e:
            self._add_check_result(
                "Installed Packages",
                "warning",
                "Could not check installed packages",
                [f"Error: {str(e)}"],
                "medium"
            )
    
    def _calculate_risk_score(self):
        """Calculate overall risk score and level in a balanced way"""
        total_checks = len(self.results['checks'])
        if total_checks == 0:
            self.results['risk_score'] = 0
            self.results['risk_level'] = 'unknown'
            self.results['summary'] = {
                'total_checks': 0,
                'vulnerable': 0,
                'warnings': 0,
                'safe': 0
            }
            return
        
        # Count checks by status
        vulnerable_count = sum(1 for check in self.results['checks'] if check.get('status') == 'vulnerable')
        warning_count = sum(1 for check in self.results['checks'] if check.get('status') == 'warning')
        safe_count = sum(1 for check in self.results['checks'] if check.get('status') == 'safe')
        
        # Ratios
        vulnerable_ratio = vulnerable_count / total_checks
        warning_ratio = warning_count / total_checks
        
        # Score
        risk_score = int(min(100, max(0, (vulnerable_ratio * 65 + warning_ratio * 20) * 100)))
        
        # Discrete level rules (less aggressive)
        if vulnerable_count >= 3 or (vulnerable_count >= 2 and vulnerable_ratio >= 0.5):
            risk_level = 'high'
        elif vulnerable_count == 1 or (0.2 <= vulnerable_ratio < 0.5):
            risk_level = 'medium'
        elif vulnerable_count == 0 and warning_count > 0:
            risk_level = 'low'
        else:
            risk_level = 'minimal'
        
        self.results['risk_score'] = risk_score
        self.results['risk_level'] = risk_level
        self.results['summary'] = {
            'total_checks': total_checks,
            'vulnerable': vulnerable_count,
            'warnings': warning_count,
            'safe': safe_count
        }






