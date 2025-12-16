/**
 * Local Time Utility - Converts server timestamps to user's selected timezone (fallback to EAT)
 * This script handles timezone conversion for timestamps throughout the application.
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

// Resolve preferred timezone: window.USER_TZ if set, else EAT (Africa/Nairobi), else device tz
function resolvePreferredTimeZone() {
    try {
        if (window && window.USER_TZ && typeof window.USER_TZ === 'string' && window.USER_TZ.trim()) {
            return window.USER_TZ.trim();
        }
    } catch (e) {}
    return 'Africa/Nairobi';
}

// Format date to local time with various formats using preferred timezone
function formatToLocalTime(utcDate, format = 'datetime') {
    if (!utcDate) return 'N/A';
    let date = utcDate instanceof Date ? utcDate : new Date(utcDate);
    if (isNaN(date.getTime())) return 'Invalid date';

    const tz = resolvePreferredTimeZone();

    const options = { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true, timeZone: tz };
    const localeOptions = {
        dateonly: { year: 'numeric', month: 'short', day: 'numeric', timeZone: tz },
        timeonly: { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: true, timeZone: tz },
        datetime: options,
        short: { year: '2-digit', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', timeZone: tz }
    };
    try {
        return new Intl.DateTimeFormat('en-US', localeOptions[format] || options).format(date);
    } catch (e) {
        // Fallback to default toLocaleString if Intl fails
        return date.toLocaleString('en-US');
    }
}

// Convert time to "time ago" format with local timezone awareness
function formatTimeAgo(utcDate) {
    if (!utcDate) return 'N/A';
    const date = utcDate instanceof Date ? utcDate : new Date(utcDate);
    if (isNaN(date.getTime())) return 'Invalid date';

    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const seconds = Math.floor(diffMs / 1000);

    if (seconds < 60) return 'just now';
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    const hours = Math.floor(seconds / 3600);
    if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    const days = Math.floor(seconds / 86400);
    if (days < 7) return `${days} day${days > 1 ? 's' : ''} ago`;

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
