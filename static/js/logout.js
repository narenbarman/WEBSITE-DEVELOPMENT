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