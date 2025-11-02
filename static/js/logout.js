// Automatic logout on network disconnection
(function() {
    let isOnline = navigator.onLine;
    let logoutTimer;

    function logout() {
        console.log('Network disconnected, logging out...');
        // Redirect to logout URL
        window.location.href = '/logout';
    }

    function startLogoutTimer() {
        // Wait 30 seconds after disconnection before logging out
        logoutTimer = setTimeout(logout, 30000);
    }

    function cancelLogoutTimer() {
        if (logoutTimer) {
            clearTimeout(logoutTimer);
            logoutTimer = null;
        }
    }

    function handleOnline() {
        console.log('Network reconnected');
        cancelLogoutTimer();
        isOnline = true;
    }

    function handleOffline() {
        console.log('Network disconnected');
        isOnline = false;
        startLogoutTimer();
    }

    // Listen for online/offline events
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);

    // Check initial state
    if (!isOnline) {
        startLogoutTimer();
    }

    // Periodic check every 10 seconds as backup
    setInterval(function() {
        if (!navigator.onLine && isOnline) {
            handleOffline();
        } else if (navigator.onLine && !isOnline) {
            handleOnline();
        }
    }, 10000);

    console.log('Automatic logout on disconnection initialized');
})();

// Function to close flash messages
function closeFlashMessage(button) {
    const flashMessage = button.closest('.flash-message');
    flashMessage.style.animation = 'fadeOut 0.3s ease-out';
    setTimeout(() => {
        flashMessage.remove();
        // Force page reactivation by triggering a minimal DOM change
        document.body.style.display = 'block';
        // Small delay to ensure DOM update
        setTimeout(() => {
            document.body.offsetHeight; // Trigger reflow
        }, 10);
    }, 300);
}

// Auto-hide flash messages after 5 seconds
document.addEventListener('DOMContentLoaded', function() {
    const flashMessages = document.querySelectorAll('.flash-message');
    flashMessages.forEach(message => {
        // Add close button to each flash message
        const closeBtn = document.createElement('button');
        closeBtn.className = 'close-btn';
        closeBtn.innerHTML = '×';
        closeBtn.onclick = function() { closeFlashMessage(this); };
        message.appendChild(closeBtn);

        // Auto-hide after 5 seconds
        setTimeout(() => {
            if (message.parentNode) { // Check if still in DOM
                closeFlashMessage(closeBtn);
            }
        }, 5000);

        // Add click event to reactivate page when message is clicked
        message.addEventListener('click', () => {
            document.body.offsetHeight; // Force reflow to reactivate page
        });
    });

    // Add periodic page activity check
    let activityTimer = setInterval(() => {
        // Trigger minimal DOM activity to keep page responsive
        const body = document.body;
        const currentDisplay = body.style.display;
        body.style.display = currentDisplay || 'block';

        // Force a minimal reflow to ensure page stays active
        body.offsetHeight;
    }, 30000); // Every 30 seconds

    // Clear timer on page unload
    window.addEventListener('beforeunload', () => {
        if (activityTimer) {
            clearInterval(activityTimer);
        }
    });
});