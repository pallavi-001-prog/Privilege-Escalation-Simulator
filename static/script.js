// Custom JavaScript for Privilege Escalation Scanner

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });

    // Auto-hide alerts after 5 seconds
    setTimeout(function() {
        var alerts = document.querySelectorAll('.alert');
        alerts.forEach(function(alert) {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);

    // Add fade-in animation to cards
    var cards = document.querySelectorAll('.card');
    cards.forEach(function(card, index) {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        
        setTimeout(function() {
            card.style.transition = 'all 0.5s ease';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, index * 100);
    });

    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(function(anchor) {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            var target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Form validation
    var forms = document.querySelectorAll('.needs-validation');
    forms.forEach(function(form) {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });

    // Password confirmation validation
    var password = document.getElementById('password');
    var confirmPassword = document.getElementById('confirm_password');
    
    if (password && confirmPassword) {
        function validatePassword() {
            if (password.value !== confirmPassword.value) {
                confirmPassword.setCustomValidity("Passwords don't match");
            } else {
                confirmPassword.setCustomValidity('');
            }
        }
        
        password.addEventListener('change', validatePassword);
        confirmPassword.addEventListener('keyup', validatePassword);
    }

    // Scan progress simulation
    var scanForm = document.getElementById('scanForm');
    if (scanForm) {
        scanForm.addEventListener('submit', function() {
            var progressCard = document.getElementById('progressCard');
            var progressBar = document.querySelector('.progress-bar');
            var scanButton = document.getElementById('scanButton');
            
            if (progressCard && progressBar && scanButton) {
                progressCard.style.display = 'block';
                scanButton.disabled = true;
                scanButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Scanning...';
                
                // Simulate progress
                var progress = 0;
                var interval = setInterval(function() {
                    progress += Math.random() * 15;
                    if (progress > 90) progress = 90;
                    progressBar.style.width = progress + '%';
                }, 500);
                
                // Clear interval after form submission
                setTimeout(function() {
                    clearInterval(interval);
                }, 100);
            }
        });
    }

    // Risk level color coding
    var riskElements = document.querySelectorAll('[data-risk-level]');
    riskElements.forEach(function(element) {
        var riskLevel = element.getAttribute('data-risk-level');
        element.classList.add('risk-' + riskLevel);
    });

    // Status color coding
    var statusElements = document.querySelectorAll('[data-status]');
    statusElements.forEach(function(element) {
        var status = element.getAttribute('data-status');
        element.classList.add('status-' + status);
    });

    // Table row click handlers
    var tableRows = document.querySelectorAll('tbody tr[data-href]');
    tableRows.forEach(function(row) {
        row.style.cursor = 'pointer';
        row.addEventListener('click', function() {
            window.location.href = this.getAttribute('data-href');
        });
    });

    // Confirmation dialogs
    var deleteButtons = document.querySelectorAll('[data-confirm]');
    deleteButtons.forEach(function(button) {
        button.addEventListener('click', function(e) {
            var message = this.getAttribute('data-confirm');
            if (!confirm(message)) {
                e.preventDefault();
            }
        });
    });

    // Auto-refresh for running scans
    var runningScans = document.querySelectorAll('.badge:contains("Running")');
    if (runningScans.length > 0) {
        setInterval(function() {
            location.reload();
        }, 30000); // Refresh every 30 seconds
    }

    // Copy to clipboard functionality
    var copyButtons = document.querySelectorAll('[data-copy]');
    copyButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            var text = this.getAttribute('data-copy');
            navigator.clipboard.writeText(text).then(function() {
                // Show success message
                var toast = document.createElement('div');
                toast.className = 'toast position-fixed top-0 end-0 m-3';
                toast.innerHTML = `
                    <div class="toast-header">
                        <i class="fas fa-check-circle text-success me-2"></i>
                        <strong class="me-auto">Success</strong>
                        <button type="button" class="btn-close" data-bs-dismiss="toast"></button>
                    </div>
                    <div class="toast-body">
                        Copied to clipboard!
                    </div>
                `;
                document.body.appendChild(toast);
                var bsToast = new bootstrap.Toast(toast);
                bsToast.show();
                
                // Remove toast after it's hidden
                toast.addEventListener('hidden.bs.toast', function() {
                    document.body.removeChild(toast);
                });
            });
        });
    });

    // Search functionality for tables
    var searchInputs = document.querySelectorAll('[data-search]');
    searchInputs.forEach(function(input) {
        var targetTable = document.querySelector(input.getAttribute('data-search'));
        if (targetTable) {
            input.addEventListener('keyup', function() {
                var filter = this.value.toLowerCase();
                var rows = targetTable.querySelectorAll('tbody tr');
                
                rows.forEach(function(row) {
                    var text = row.textContent.toLowerCase();
                    if (text.indexOf(filter) > -1) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                });
            });
        }
    });

    // Export functionality
    var exportButtons = document.querySelectorAll('[data-export]');
    exportButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            var format = this.getAttribute('data-export');
            var table = document.querySelector(this.getAttribute('data-target'));
            
            if (format === 'csv' && table) {
                exportTableToCSV(table, 'scan-results.csv');
            } else if (format === 'json') {
                // Export scan results as JSON
                var scanData = JSON.parse(this.getAttribute('data-scan-results'));
                downloadJSON(scanData, 'scan-results.json');
            }
        });
    });

    // Risk score animation
    var riskScoreElements = document.querySelectorAll('.risk-score');
    riskScoreElements.forEach(function(element) {
        var finalScore = parseInt(element.textContent);
        var currentScore = 0;
        var increment = finalScore / 50;
        
        var timer = setInterval(function() {
            currentScore += increment;
            if (currentScore >= finalScore) {
                currentScore = finalScore;
                clearInterval(timer);
            }
            element.textContent = Math.round(currentScore) + '%';
        }, 20);
    });
});

// Utility functions
function exportTableToCSV(table, filename) {
    var csv = [];
    var rows = table.querySelectorAll('tr');
    
    for (var i = 0; i < rows.length; i++) {
        var row = [], cols = rows[i].querySelectorAll('td, th');
        
        for (var j = 0; j < cols.length; j++) {
            var data = cols[j].textContent.replace(/"/g, '""');
            row.push('"' + data + '"');
        }
        
        csv.push(row.join(','));
    }
    
    var csvContent = csv.join('\n');
    downloadCSV(csvContent, filename);
}

function downloadCSV(csvContent, filename) {
    var blob = new Blob([csvContent], { type: 'text/csv' });
    var url = window.URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    window.URL.revokeObjectURL(url);
}

function downloadJSON(data, filename) {
    var jsonContent = JSON.stringify(data, null, 2);
    var blob = new Blob([jsonContent], { type: 'application/json' });
    var url = window.URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    window.URL.revokeObjectURL(url);
}

// AJAX helper functions
function makeRequest(url, method, data) {
    return fetch(url, {
        method: method,
        headers: {
            'Content-Type': 'application/json',
        },
        body: data ? JSON.stringify(data) : undefined
    });
}

function showNotification(message, type = 'info') {
    var alertClass = 'alert-' + type;
    var iconClass = type === 'success' ? 'fa-check-circle' : 
                   type === 'error' ? 'fa-exclamation-triangle' : 
                   type === 'warning' ? 'fa-exclamation-circle' : 'fa-info-circle';
    
    var notification = document.createElement('div');
    notification.className = 'alert ' + alertClass + ' alert-dismissible fade show position-fixed top-0 end-0 m-3';
    notification.style.zIndex = '9999';
    notification.innerHTML = `
        <i class="fas ${iconClass} me-2"></i>
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(function() {
        if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
        }
    }, 5000);
}

// Chart.js integration for future use
function createRiskChart(canvasId, data) {
    var ctx = document.getElementById(canvasId);
    if (ctx && typeof Chart !== 'undefined') {
        new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Vulnerable', 'Warnings', 'Safe'],
                datasets: [{
                    data: [data.vulnerable, data.warnings, data.safe],
                    backgroundColor: [
                        '#dc3545',
                        '#ffc107',
                        '#28a745'
                    ],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }
}





