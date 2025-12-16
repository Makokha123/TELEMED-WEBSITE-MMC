// call-logs.js - fetches call logs and shows browser notifications for missed calls/messages
(function(){
  async function fetchCallLogs(filter='all'){
    try{
      const url = filter && filter !== 'all' ? `/api/call_logs?filter=${filter}` : '/api/call_logs';
      const resp = await fetch(url);
      if(!resp.ok) throw new Error('Network error');
      return await resp.json();
    }catch(e){
      console.error('Failed to fetch call logs', e);
      return { call_logs: [] };
    }
  }

  // show browser notification
  function notify(title, body, tag){
    if (!('Notification' in window)) return;
    if (Notification.permission === 'granted') {
      new Notification(title, { body, tag });
    } else if (Notification.permission !== 'denied') {
      Notification.requestPermission().then(p => { if (p === 'granted') new Notification(title, { body, tag }); });
    }
  }

  // Poll for missed calls/messages and notify
  async function pollNotifications(){
    const data = await fetchCallLogs('missed');
    const items = data.call_logs || [];
    items.forEach(i => {
      const tag = `calllog-${i.id}`;
      // show only once per id using sessionStorage
      if (!sessionStorage.getItem(tag)) {
        notify('Missed call', `${i.remote_user_name || 'Unknown'} (${i.type})`, tag);
        sessionStorage.setItem(tag, 'notified');
      }
    });
  }

  // Expose some functions globally for embedding pages
  window.CallLogs = { fetchCallLogs, pollNotifications };

  // Start polling in background
  setInterval(pollNotifications, 30000);
  // One immediate run
  pollNotifications();
})();
