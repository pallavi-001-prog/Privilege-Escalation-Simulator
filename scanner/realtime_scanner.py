import os
import subprocess
import platform
import json
import time
from datetime import datetime

class RealtimeVulnerabilityScanner:
    """
    Real-time vulnerability scanner for actual system checks.
    Simplified for normal users with clear explanations.
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
    
    def run_realtime_scan(self, scan_type="basic"):
        """Run real-time vulnerability scan"""
        print(f"Starting real-time {scan_type} vulnerability scan...")
        
        if scan_type == "basic":
            self._check_file_permissions()
            self._check_running_processes()
            self._check_sudo_configuration()
            self._check_suid_files()
        elif scan_type == "network":
            self._check_open_ports()
            self._check_network_services()
            self._check_cron_jobs()
            self._check_environment_variables()
        elif scan_type == "system":
            self._check_system_info()
            self._check_installed_software()
            self._check_user_groups()
            self._check_world_writable_files()
        elif scan_type == "privilege_escalation":
            # Comprehensive privilege escalation scan
            self._check_sudo_configuration()
            self._check_suid_files()
            self._check_world_writable_files()
            self._check_cron_jobs()
            self._check_environment_variables()
            self._check_file_permissions()
            self._check_user_groups()
            self._check_network_services()
        
        # Calculate risk score
        self._calculate_risk_score()
        
        print("Real-time scan completed!")
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
    
    def _check_file_permissions(self):
        """Check file permissions on Windows/Linux"""
        try:
            if platform.system() == "Windows":
                # Check Windows file permissions
                sensitive_files = [
                    "C:\\Windows\\System32\\config\\SAM",
                    "C:\\Windows\\System32\\config\\SYSTEM",
                    "C:\\Windows\\System32\\drivers\\etc\\hosts"
                ]
                
                vulnerable_files = []
                for file_path in sensitive_files:
                    if os.path.exists(file_path):
                        try:
                            # Try to read the file
                            with open(file_path, 'r') as f:
                                f.read(1)
                            vulnerable_files.append(f"{file_path} - Readable by current user")
                        except PermissionError:
                            pass  # Good - file is protected
                        except Exception:
                            pass
                
                if vulnerable_files:
                    self._add_check_result(
                        "File Permissions",
                        "vulnerable",
                        "Found sensitive system files that are readable by current user",
                        vulnerable_files,
                        "high"
                    )
                else:
                    self._add_check_result(
                        "File Permissions",
                        "safe",
                        "Sensitive system files are properly protected",
                        ["All checked system files require elevated privileges"],
                        "low"
                    )
            else:
                # Check Linux file permissions
                sensitive_files = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]
                vulnerable_files = []
                
                for file_path in sensitive_files:
                    if os.path.exists(file_path):
                        try:
                            stat_info = os.stat(file_path)
                            mode = stat_info.st_mode
                            # Check if file is world-readable
                            if mode & 0o004:
                                vulnerable_files.append(f"{file_path} - World readable")
                        except Exception:
                            pass
                
                if vulnerable_files:
                    self._add_check_result(
                        "File Permissions",
                        "vulnerable",
                        "Found files with overly permissive permissions",
                        vulnerable_files,
                        "high"
                    )
                else:
                    self._add_check_result(
                        "File Permissions",
                        "safe",
                        "File permissions appear secure",
                        ["No overly permissive file permissions found"],
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
    
    def _check_running_processes(self):
        """Check for suspicious running processes"""
        try:
            if platform.system() == "Windows":
                # Get running processes on Windows
                result = subprocess.run(['tasklist', '/fo', 'csv'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    processes = result.stdout.split('\n')[1:]  # Skip header
                    suspicious_processes = []
                    
                    # Look for potentially suspicious processes
                    suspicious_names = ['nc.exe', 'netcat', 'ncat', 'powershell', 'cmd.exe']
                    for process in processes:
                        if process.strip():
                            parts = process.split(',')
                            if len(parts) > 0:
                                process_name = parts[0].strip('"').lower()
                                for suspicious in suspicious_names:
                                    if suspicious in process_name:
                                        suspicious_processes.append(process_name)
                    
                    if suspicious_processes:
                        self._add_check_result(
                            "Running Processes",
                            "warning",
                            "Found potentially suspicious processes",
                            suspicious_processes,
                            "medium"
                        )
                    else:
                        self._add_check_result(
                            "Running Processes",
                            "safe",
                            "No suspicious processes detected",
                            ["All running processes appear normal"],
                            "low"
                        )
                else:
                    self._add_check_result(
                        "Running Processes",
                        "warning",
                        "Could not enumerate running processes",
                        ["Access denied or system error"],
                        "medium"
                    )
            else:
                # Linux process check
                result = subprocess.run(['ps', 'aux'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    processes = result.stdout.split('\n')[1:]  # Skip header
                    root_processes = []
                    
                    for process in processes:
                        if process.strip():
                            parts = process.split()
                            if len(parts) > 10 and parts[0] == 'root':
                                root_processes.append(parts[10:])  # Command part
                    
                    if len(root_processes) > 5:  # More than 5 root processes
                        self._add_check_result(
                            "Running Processes",
                            "info",
                            f"Found {len(root_processes)} processes running as root",
                            [f"Total root processes: {len(root_processes)}"],
                            "medium"
                        )
                    else:
                        self._add_check_result(
                            "Running Processes",
                            "safe",
                            "Normal number of root processes running",
                            [f"Root processes: {len(root_processes)}"],
                            "low"
                        )
                        
        except Exception as e:
            self._add_check_result(
                "Running Processes",
                "warning",
                "Could not check running processes",
                [f"Error: {str(e)}"],
                "medium"
            )
    
    def _check_open_ports(self):
        """Check for open network ports"""
        try:
            if platform.system() == "Windows":
                # Use netstat on Windows
                result = subprocess.run(['netstat', '-an'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    listening_ports = []
                    
                    for line in lines:
                        if 'LISTENING' in line:
                            parts = line.split()
                            if len(parts) > 1:
                                port_info = parts[1]
                                listening_ports.append(port_info)
                    
                    # Check for common vulnerable ports
                    vulnerable_ports = []
                    dangerous_ports = ['21', '23', '135', '139', '445', '1433', '3389']
                    
                    for port_info in listening_ports:
                        for port in dangerous_ports:
                            if f':{port}' in port_info:
                                vulnerable_ports.append(f"Port {port} is open")
                    
                    if vulnerable_ports:
                        self._add_check_result(
                            "Open Ports",
                            "vulnerable",
                            "Found potentially dangerous open ports",
                            vulnerable_ports,
                            "high"
                        )
                    else:
                        self._add_check_result(
                            "Open Ports",
                            "safe",
                            "No dangerous ports found open",
                            [f"Total listening ports: {len(listening_ports)}"],
                            "low"
                        )
                else:
                    self._add_check_result(
                        "Open Ports",
                        "warning",
                        "Could not check open ports",
                        ["Access denied or system error"],
                        "medium"
                    )
            else:
                # Linux port check
                result = subprocess.run(['ss', '-tuln'], 
                                      capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    lines = result.stdout.split('\n')[1:]  # Skip header
                    listening_ports = []
                    
                    for line in lines:
                        if line.strip():
                            parts = line.split()
                            if len(parts) > 3:
                                port_info = parts[3]
                                listening_ports.append(port_info)
                    
                    # Check for dangerous ports
                    vulnerable_ports = []
                    dangerous_ports = ['21', '23', '135', '139', '445', '1433', '3389']
                    
                    for port_info in listening_ports:
                        for port in dangerous_ports:
                            if f':{port}' in port_info:
                                vulnerable_ports.append(f"Port {port} is open")
                    
                    if vulnerable_ports:
                        self._add_check_result(
                            "Open Ports",
                            "vulnerable",
                            "Found potentially dangerous open ports",
                            vulnerable_ports,
                            "high"
                        )
                    else:
                        self._add_check_result(
                            "Open Ports",
                            "safe",
                            "No dangerous ports found open",
                            [f"Total listening ports: {len(listening_ports)}"],
                            "low"
                        )
                        
        except Exception as e:
            self._add_check_result(
                "Open Ports",
                "warning",
                "Could not check open ports",
                [f"Error: {str(e)}"],
                "medium"
            )
    
    def _check_network_services(self):
        """Check network services"""
        try:
            if platform.system() == "Windows":
                # Check Windows services
                result = subprocess.run(['sc', 'query', 'state=', 'all'], 
                                      capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    services = result.stdout.split('\n')
                    running_services = []
                    
                    for i, line in enumerate(services):
                        if 'SERVICE_NAME:' in line and i + 1 < len(services):
                            service_name = line.split('SERVICE_NAME:')[1].strip()
                            next_line = services[i + 1]
                            if 'RUNNING' in next_line:
                                running_services.append(service_name)
                    
                    # Check for potentially vulnerable services
                    vulnerable_services = []
                    dangerous_services = ['telnet', 'ftp', 'snmp', 'rpc', 'netbios']
                    
                    for service in running_services:
                        for dangerous in dangerous_services:
                            if dangerous.lower() in service.lower():
                                vulnerable_services.append(service)
                    
                    if vulnerable_services:
                        self._add_check_result(
                            "Network Services",
                            "warning",
                            "Found potentially vulnerable network services",
                            vulnerable_services,
                            "medium"
                        )
                    else:
                        self._add_check_result(
                            "Network Services",
                            "safe",
                            "No obviously vulnerable services detected",
                            [f"Total running services: {len(running_services)}"],
                            "low"
                        )
                else:
                    self._add_check_result(
                        "Network Services",
                        "warning",
                        "Could not enumerate network services",
                        ["Access denied or system error"],
                        "medium"
                    )
            else:
                # Linux service check
                result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running'], 
                                      capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    services = result.stdout.split('\n')[1:]  # Skip header
                    running_services = []
                    
                    for line in services:
                        if line.strip() and '.service' in line:
                            service_name = line.split()[0]
                            running_services.append(service_name)
                    
                    # Check for vulnerable services
                    vulnerable_services = []
                    dangerous_services = ['telnet', 'ftp', 'snmp', 'rpc', 'netbios']
                    
                    for service in running_services:
                        for dangerous in dangerous_services:
                            if dangerous.lower() in service.lower():
                                vulnerable_services.append(service)
                    
                    if vulnerable_services:
                        self._add_check_result(
                            "Network Services",
                            "warning",
                            "Found potentially vulnerable network services",
                            vulnerable_services,
                            "medium"
                        )
                    else:
                        self._add_check_result(
                            "Network Services",
                            "safe",
                            "No obviously vulnerable services detected",
                            [f"Total running services: {len(running_services)}"],
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
    
    def _check_system_info(self):
        """Check basic system information"""
        try:
            system_info = {
                'os': platform.system(),
                'version': platform.version(),
                'architecture': platform.architecture()[0],
                'processor': platform.processor(),
                'python_version': platform.python_version()
            }
            
            # Check if running as administrator/root
            is_admin = False
            if platform.system() == "Windows":
                try:
                    import ctypes
                    is_admin = ctypes.windll.shell32.IsUserAnAdmin()
                except:
                    pass
            else:
                is_admin = os.geteuid() == 0
            
            if is_admin:
                self._add_check_result(
                    "System Information",
                    "warning",
                    "Application is running with elevated privileges",
                    [f"Running as: {'Administrator' if platform.system() == 'Windows' else 'Root'}"],
                    "medium"
                )
            else:
                self._add_check_result(
                    "System Information",
                    "safe",
                    "Application is running with normal user privileges",
                    [f"OS: {system_info['os']} {system_info['version']}"],
                    "low"
                )
                
        except Exception as e:
            self._add_check_result(
                "System Information",
                "warning",
                "Could not gather system information",
                [f"Error: {str(e)}"],
                "medium"
            )
    
    def _check_installed_software(self):
        """Check for potentially vulnerable software"""
        try:
            if platform.system() == "Windows":
                # Check Windows installed programs
                result = subprocess.run(['wmic', 'product', 'get', 'name,version'], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    programs = result.stdout.split('\n')
                    vulnerable_software = []
                    
                    # Look for potentially vulnerable software
                    dangerous_software = ['java', 'flash', 'adobe', 'microsoft office']
                    
                    for program in programs:
                        if program.strip():
                            program_lower = program.lower()
                            for dangerous in dangerous_software:
                                if dangerous in program_lower:
                                    vulnerable_software.append(program.strip())
                    
                    if vulnerable_software:
                        self._add_check_result(
                            "Installed Software",
                            "warning",
                            "Found potentially vulnerable software",
                            vulnerable_software[:5],  # Limit to first 5
                            "medium"
                        )
                    else:
                        self._add_check_result(
                            "Installed Software",
                            "safe",
                            "No obviously vulnerable software detected",
                            [f"Total programs checked: {len(programs)}"],
                            "low"
                        )
                else:
                    self._add_check_result(
                        "Installed Software",
                        "warning",
                        "Could not enumerate installed software",
                        ["Access denied or system error"],
                        "medium"
                    )
            else:
                # Linux package check
                result = subprocess.run(['dpkg', '-l'], 
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    packages = result.stdout.split('\n')[5:]  # Skip headers
                    vulnerable_packages = []
                    
                    # Look for potentially vulnerable packages
                    dangerous_packages = ['apache', 'nginx', 'mysql', 'postgresql', 'php']
                    
                    for package in packages:
                        if package.strip():
                            package_lower = package.lower()
                            for dangerous in dangerous_packages:
                                if dangerous in package_lower and 'ii' in package:
                                    vulnerable_packages.append(package.split()[1])
                    
                    if vulnerable_packages:
                        self._add_check_result(
                            "Installed Software",
                            "info",
                            "Found network services and databases",
                            vulnerable_packages[:5],  # Limit to first 5
                            "medium"
                        )
                    else:
                        self._add_check_result(
                            "Installed Software",
                            "safe",
                            "No obviously vulnerable packages detected",
                            [f"Total packages checked: {len(packages)}"],
                            "low"
                        )
                        
        except Exception as e:
            self._add_check_result(
                "Installed Software",
                "warning",
                "Could not check installed software",
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
        
        # Score (kept for display)
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
    
    def _check_sudo_configuration(self):
        """Check for actual sudo misconfigurations"""
        try:
            if platform.system() == "Windows":
                # Windows doesn't have sudo, skip this check
                self._add_check_result(
                    "Sudo Configuration",
                    "info",
                    "Sudo not applicable on Windows systems",
                    ["Windows uses UAC instead of sudo"],
                    "low"
                )
                return
            
            # Check if sudo is installed
            result = subprocess.run(['which', 'sudo'], capture_output=True, text=True, timeout=5)
            if result.returncode != 0:
                self._add_check_result(
                    "Sudo Configuration",
                    "info",
                    "Sudo not installed on this system",
                    ["Sudo package not found"],
                    "low"
                )
                return
            
            # Check sudo configuration
            try:
                # Try to read sudoers file
                result = subprocess.run(['sudo', '-l'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    sudo_output = result.stdout.lower()
                    
                    # Check for dangerous configurations
                    dangerous_patterns = [
                        'nopasswd: all',
                        'all=(all) nopasswd: all',
                        'all=(all) all',
                        'nopasswd: /bin/su',
                        'nopasswd: /usr/bin/passwd'
                    ]
                    
                    found_vulnerabilities = []
                    for pattern in dangerous_patterns:
                        if pattern in sudo_output:
                            found_vulnerabilities.append(f"Found: {pattern}")
                    
                    if found_vulnerabilities:
                        self._add_check_result(
                            "Sudo Configuration",
                            "vulnerable",
                            "Found dangerous sudo configurations",
                            found_vulnerabilities,
                            "high"
                        )
                    else:
                        self._add_check_result(
                            "Sudo Configuration",
                            "safe",
                            "Sudo configuration appears secure",
                            ["No dangerous sudo rules found"],
                            "low"
                        )
                else:
                    self._add_check_result(
                        "Sudo Configuration",
                        "warning",
                        "Could not check sudo configuration",
                        ["Access denied or sudo not configured"],
                        "medium"
                    )
            except subprocess.TimeoutExpired:
                self._add_check_result(
                    "Sudo Configuration",
                    "warning",
                    "Sudo check timed out",
                    ["Command execution timeout"],
                    "medium"
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
        """Check for actual SUID files that might be exploitable"""
        try:
            if platform.system() == "Windows":
                # Windows doesn't have SUID, skip this check
                self._add_check_result(
                    "SUID Files",
                    "info",
                    "SUID not applicable on Windows systems",
                    ["Windows uses different permission model"],
                    "low"
                )
                return
            
            # Find SUID files
            result = subprocess.run(['find', '/usr', '/bin', '/sbin', '-type', 'f', '-perm', '-4000', '2>/dev/null'], 
                                  shell=True, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0 and result.stdout.strip():
                suid_files = result.stdout.strip().split('\n')
                
                # Known potentially exploitable SUID files
                dangerous_suid = [
                    '/usr/bin/find',
                    '/usr/bin/nmap',
                    '/usr/bin/nmap',
                    '/usr/bin/vim',
                    '/usr/bin/less',
                    '/usr/bin/more',
                    '/usr/bin/nano',
                    '/usr/bin/awk',
                    '/usr/bin/sed',
                    '/usr/bin/man',
                    '/usr/bin/at',
                    '/usr/bin/crontab',
                    '/usr/bin/zip',
                    '/usr/bin/unzip',
                    '/usr/bin/tar',
                    '/usr/bin/gzip',
                    '/usr/bin/gunzip'
                ]
                
                found_dangerous = []
                for suid_file in suid_files:
                    if suid_file in dangerous_suid:
                        found_dangerous.append(suid_file)
                
                if found_dangerous:
                    self._add_check_result(
                        "SUID Files",
                        "vulnerable",
                        "Found potentially exploitable SUID files",
                        found_dangerous,
                        "high"
                    )
                else:
                    self._add_check_result(
                        "SUID Files",
                        "safe",
                        "No obviously exploitable SUID files found",
                        [f"Found {len(suid_files)} SUID files, all appear safe"],
                        "low"
                    )
            else:
                self._add_check_result(
                    "SUID Files",
                    "warning",
                    "Could not enumerate SUID files",
                    ["Access denied or find command failed"],
                    "medium"
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
        """Check for actual world-writable files in sensitive locations"""
        try:
            if platform.system() == "Windows":
                # Check Windows for world-writable files
                sensitive_paths = [
                    "C:\\Windows\\System32",
                    "C:\\Program Files",
                    "C:\\Program Files (x86)",
                    "C:\\Users"
                ]
                
                vulnerable_files = []
                for path in sensitive_paths:
                    if os.path.exists(path):
                        try:
                            # Use icacls to check permissions
                            result = subprocess.run(['icacls', path], capture_output=True, text=True, timeout=10)
                            if result.returncode == 0:
                                # Look for "Everyone" with "F" (Full Control) or "M" (Modify)
                                if "Everyone:(F)" in result.stdout or "Everyone:(M)" in result.stdout:
                                    vulnerable_files.append(f"{path} - World writable")
                        except:
                            pass
                
                if vulnerable_files:
                    self._add_check_result(
                        "World-Writable Files",
                        "vulnerable",
                        "Found world-writable files in sensitive locations",
                        vulnerable_files,
                        "high"
                    )
                else:
                    self._add_check_result(
                        "World-Writable Files",
                        "safe",
                        "No world-writable files in sensitive locations",
                        ["Sensitive directories have proper permissions"],
                        "low"
                    )
            else:
                # Linux/Unix world-writable check
                sensitive_paths = ["/etc", "/home", "/root", "/var/log", "/usr/bin", "/usr/sbin"]
                vulnerable_files = []
                
                for path in sensitive_paths:
                    if os.path.exists(path):
                        try:
                            result = subprocess.run(['find', path, '-type', 'f', '-perm', '-002', '2>/dev/null'], 
                                                  shell=True, capture_output=True, text=True, timeout=15)
                            if result.returncode == 0 and result.stdout.strip():
                                files = result.stdout.strip().split('\n')
                                for file in files:
                                    if file.strip():
                                        vulnerable_files.append(file)
                        except:
                            pass
                
                if vulnerable_files:
                    self._add_check_result(
                        "World-Writable Files",
                        "vulnerable",
                        "Found world-writable files in sensitive locations",
                        vulnerable_files[:10],  # Limit to first 10
                        "high"
                    )
                else:
                    self._add_check_result(
                        "World-Writable Files",
                        "safe",
                        "No world-writable files in sensitive locations",
                        ["All checked directories have proper permissions"],
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
        """Check for actual exploitable cron jobs"""
        try:
            if platform.system() == "Windows":
                # Check Windows Task Scheduler
                result = subprocess.run(['schtasks', '/query', '/fo', 'csv'], 
                                      capture_output=True, text=True, timeout=15)
                if result.returncode == 0:
                    tasks = result.stdout.split('\n')[1:]  # Skip header
                    suspicious_tasks = []
                    
                    for task in tasks:
                        if task.strip():
                            parts = task.split(',')
                            if len(parts) > 2:
                                task_name = parts[0].strip('"')
                                task_path = parts[2].strip('"') if len(parts) > 2 else ""
                                
                                # Check for suspicious task paths
                                if any(suspicious in task_path.lower() for suspicious in ['/tmp/', 'c:\\temp\\', 'c:\\users\\public\\']):
                                    suspicious_tasks.append(f"{task_name}: {task_path}")
                    
                    if suspicious_tasks:
                        self._add_check_result(
                            "Cron Jobs / Scheduled Tasks",
                            "vulnerable",
                            "Found suspicious scheduled tasks",
                            suspicious_tasks,
                            "high"
                        )
                    else:
                        self._add_check_result(
                            "Cron Jobs / Scheduled Tasks",
                            "safe",
                            "No suspicious scheduled tasks found",
                            [f"Checked {len(tasks)} scheduled tasks"],
                            "low"
                        )
                else:
                    self._add_check_result(
                        "Cron Jobs / Scheduled Tasks",
                        "warning",
                        "Could not check scheduled tasks",
                        ["Access denied or system error"],
                        "medium"
                    )
            else:
                # Linux cron check
                cron_files = ['/etc/crontab', '/etc/cron.d/', '/var/spool/cron/crontabs/']
                suspicious_jobs = []
                
                for cron_file in cron_files:
                    if os.path.exists(cron_file):
                        try:
                            if os.path.isfile(cron_file):
                                with open(cron_file, 'r') as f:
                                    content = f.read()
                                    # Look for jobs in /tmp or other suspicious locations
                                    lines = content.split('\n')
                                    for line in lines:
                                        if any(suspicious in line for suspicious in ['/tmp/', '/var/tmp/', 'wget', 'curl']):
                                            suspicious_jobs.append(f"{cron_file}: {line.strip()}")
                            elif os.path.isdir(cron_file):
                                # Check files in cron directory
                                for file in os.listdir(cron_file):
                                    file_path = os.path.join(cron_file, file)
                                    if os.path.isfile(file_path):
                                        with open(file_path, 'r') as f:
                                            content = f.read()
                                            for line in content.split('\n'):
                                                if any(suspicious in line for suspicious in ['/tmp/', '/var/tmp/', 'wget', 'curl']):
                                                    suspicious_jobs.append(f"{file_path}: {line.strip()}")
                        except:
                            pass
                
                if suspicious_jobs:
                    self._add_check_result(
                        "Cron Jobs",
                        "vulnerable",
                        "Found suspicious cron jobs",
                        suspicious_jobs[:10],  # Limit to first 10
                        "high"
                    )
                else:
                    self._add_check_result(
                        "Cron Jobs",
                        "safe",
                        "No suspicious cron jobs found",
                        ["All cron jobs appear normal"],
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
        """Check for actual dangerous environment variables"""
        try:
            dangerous_vars = ['PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH', 'PYTHONPATH']
            found_dangerous = []
            
            for var in dangerous_vars:
                value = os.environ.get(var, '')
                if value:
                    # Check for suspicious paths
                    suspicious_paths = ['/tmp', '/var/tmp', '/dev/shm', 'c:\\temp', 'c:\\users\\public']
                    for suspicious in suspicious_paths:
                        if suspicious in value:
                            found_dangerous.append(f"{var}={value}")
                            break
            
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
    
    def _check_user_groups(self):
        """Check actual user group memberships for privilege escalation opportunities"""
        try:
            if platform.system() == "Windows":
                # Check Windows groups
                result = subprocess.run(['whoami', '/groups'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    groups = result.stdout.lower()
                    privileged_groups = []
                    
                    # Look for privileged groups
                    admin_groups = ['administrators', 'domain admins', 'enterprise admins', 'schema admins']
                    for group in admin_groups:
                        if group in groups:
                            privileged_groups.append(group)
                    
                    if privileged_groups:
                        self._add_check_result(
                            "User Groups",
                            "warning",
                            "User is member of privileged groups",
                            privileged_groups,
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
                else:
                    self._add_check_result(
                        "User Groups",
                        "warning",
                        "Could not check user groups",
                        ["Access denied or system error"],
                        "medium"
                    )
            else:
                # Linux groups
                result = subprocess.run(['groups'], capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    groups = result.stdout.strip().split()
                    privileged_groups = []
                    
                    # Look for privileged groups
                    admin_groups = ['sudo', 'docker', 'admin', 'wheel', 'root']
                    for group in groups:
                        if group in admin_groups:
                            privileged_groups.append(group)
                    
                    if privileged_groups:
                        self._add_check_result(
                            "User Groups",
                            "warning",
                            "User is member of privileged groups",
                            privileged_groups,
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
                else:
                    self._add_check_result(
                        "User Groups",
                        "warning",
                        "Could not check user groups",
                        ["Access denied or system error"],
                        "medium"
                    )
                    
        except Exception as e:
            self._add_check_result(
                "User Groups",
                "warning",
                "Could not check user groups",
                [f"Error: {str(e)}"],
                "medium"
            )

