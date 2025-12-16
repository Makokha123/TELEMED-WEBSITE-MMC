/**
 * Local Time Utility - Converts server timestamps to device's local time
 * This script handles timezone conversion for timestamps throughout the application
 */

// Get device's local timezone offset
function getDeviceTimezone() {
    const now = new Date();
    const offset = -now.getTimezoneOffset(); // Get offset in minutes
    const offsetHours = Math.floor(Math.abs(offset) / 60);
    const offsetMinutes = Math.abs(offset) % 60;
    const sign = offset >= 0 ? '+' : '-';
    return {
        offset: offset,
        offsetHours: offsetHours,
        offsetMinutes: offsetMinutes,
        sign: sign,
        tzString: `UTC${sign}${String(offsetHours).padStart(2, '0')}:${String(offsetMinutes).padStart(2, '0')}`
    };
}

// Store device timezone in session storage for server-side use if needed
function storeDeviceTimezone() {
    const tz = getDeviceTimezone();
    sessionStorage.setItem('deviceTimezone', JSON.stringify({
        offset: tz.offset,
        tzString: tz.tzString,
        timestamp: new Date().getTime()
    }));
}

// Format date to local time with various formats
function formatToLocalTime(utcDate, format = 'datetime') {
    if (!utcDate) return 'N/A';
    
    // Handle string dates (ISO format or other formats)
    let date = utcDate instanceof Date ? utcDate : new Date(utcDate);
    
    // Check if date is valid
    if (isNaN(date.getTime())) {
        return 'Invalid date';
    }
    
    const options = {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true
    };
    
    const localeOptions = {
        dateonly: {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        },
        timeonly: {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: true
        },
        datetime: options,
        short: {
            year: '2-digit',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit'
        }
    };
    
    return date.toLocaleString('en-US', localeOptions[format] || options);
}

// Convert time to "time ago" format with local timezone awareness
function formatTimeAgo(utcDate) {
    if (!utcDate) return 'N/A';
    
    let date = utcDate instanceof Date ? utcDate : new Date(utcDate);
    
    if (isNaN(date.getTime())) {
        return 'Invalid date';
    }
    
    const now = new Date();
    const seconds = Math.floor((now - date) / 1000);
    
    if (seconds < 60) return 'just now';
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    const hours = Math.floor(seconds / 3600);
    if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    const days = Math.floor(seconds / 86400);
    if (days < 7) return `${days} day${days > 1 ? 's' : ''} ago`;
    
    // For older dates, show full date
    return formatToLocalTime(date, 'short');
}

// Update all timestamps on page load
function updateAllTimestamps() {
    const timestampElements = document.querySelectorAll('[data-timestamp]');
    timestampElements.forEach(element => {
        const timestamp = element.getAttribute('data-timestamp');
        const format = element.getAttribute('data-timestamp-format') || 'datetime';
        const useTimeAgo = element.getAttribute('data-timestamp-timeago') === 'true';
        
        if (timestamp) {
            const localTime = useTimeAgo ? formatTimeAgo(timestamp) : formatToLocalTime(timestamp, format);
            element.textContent = localTime;
            element.title = formatToLocalTime(timestamp, 'datetime'); // Show full datetime in tooltip
        }
    });
}

// Watch for new timestamps added dynamically
function observeNewTimestamps() {
    const observer = new MutationObserver((mutations) => {
        mutations.forEach((mutation) => {
            if (mutation.addedNodes.length) {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === 1) { // Element node
                        // Check if the added node itself has timestamps
                        if (node.hasAttribute && node.hasAttribute('data-timestamp')) {
                            const timestamp = node.getAttribute('data-timestamp');
                            const format = node.getAttribute('data-timestamp-format') || 'datetime';
                            const useTimeAgo = node.getAttribute('data-timestamp-timeago') === 'true';
                            const localTime = useTimeAgo ? formatTimeAgo(timestamp) : formatToLocalTime(timestamp, format);
                            node.textContent = localTime;
                            node.title = formatToLocalTime(timestamp, 'datetime');
                        }
                        // Check descendants
                        node.querySelectorAll('[data-timestamp]')?.forEach(element => {
                            const timestamp = element.getAttribute('data-timestamp');
                            const format = element.getAttribute('data-timestamp-format') || 'datetime';
                            const useTimeAgo = element.getAttribute('data-timestamp-timeago') === 'true';
                            const localTime = useTimeAgo ? formatTimeAgo(timestamp) : formatToLocalTime(timestamp, format);
                            element.textContent = localTime;
                            element.title = formatToLocalTime(timestamp, 'datetime');
                        });
                    }
                });
            }
        });
    });
    
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
}

// Initialize on document ready
document.addEventListener('DOMContentLoaded', function() {
    storeDeviceTimezone();
    updateAllTimestamps();
    observeNewTimestamps();
});

// Re-update timestamps every minute (for "time ago" format)
setInterval(updateAllTimestamps, 60000);

// Expose functions globally for manual use
window.LocalTime = {
    formatToLocalTime: formatToLocalTime,
    formatTimeAgo: formatTimeAgo,
    getDeviceTimezone: getDeviceTimezone,
    updateAllTimestamps: updateAllTimestamps
};
