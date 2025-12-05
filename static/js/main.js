document.addEventListener('DOMContentLoaded', function() {
    const alerts = document.querySelectorAll('.alert:not(.alert-light)');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        }, 5000);
    });

    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    const forms = document.querySelectorAll('form');
    forms.forEach(function(form) {
        form.addEventListener('submit', function(e) {
            const submitBtn = form.querySelector('button[type="submit"]');
            if (submitBtn && !submitBtn.disabled) {
                submitBtn.disabled = true;
                const originalText = submitBtn.innerHTML;
                submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>';
                
                setTimeout(function() {
                    submitBtn.disabled = false;
                    submitBtn.innerHTML = originalText;
                }, 10000);
            }
        });
    });

    const photoInput = document.getElementById('photo');
    if (photoInput) {
        photoInput.addEventListener('change', function(e) {
            const file = e.target.files[0];
            if (file) {
                if (file.size > 5 * 1024 * 1024) {
                    alert('File size must be less than 5MB');
                    e.target.value = '';
                    return;
                }
                
                const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
                if (!allowedTypes.includes(file.type)) {
                    alert('Only JPG, PNG, and GIF files are allowed');
                    e.target.value = '';
                    return;
                }
            }
        });
    }

    const searchInputs = document.querySelectorAll('input[name="keyword"]');
    searchInputs.forEach(function(input) {
        let timeout;
        input.addEventListener('input', function() {
            clearTimeout(timeout);
            timeout = setTimeout(function() {
            }, 500);
        });
    });
});

function formatDate(dateString) {
    const options = { year: 'numeric', month: 'short', day: 'numeric' };
    return new Date(dateString).toLocaleDateString('en-US', options);
}

function getStatusBadgeClass(status) {
    switch(status) {
        case 'Pending':
            return 'bg-warning text-dark';
        case 'In Progress':
            return 'bg-info';
        case 'Resolved':
            return 'bg-success';
        default:
            return 'bg-secondary';
    }
}

function getPriorityBadgeClass(priority) {
    switch(priority) {
        case 'High':
            return 'bg-danger';
        case 'Medium':
            return 'bg-warning text-dark';
        case 'Low':
            return 'bg-info';
        default:
            return 'bg-secondary';
    }
}

function markNotificationsRead() {
    const csrfToken = document.querySelector('input[name="csrf_token"]')?.value || 
                      document.head.querySelector('meta[name="csrf-token"]')?.content || '';
    
    fetch('/notifications/mark-read', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken
        },
        body: JSON.stringify({})
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // Reload page to update badge count from server
            setTimeout(() => {
                location.reload();
            }, 500);
        }
    })
    .catch(error => console.error('Error marking notifications as read:', error));
}
