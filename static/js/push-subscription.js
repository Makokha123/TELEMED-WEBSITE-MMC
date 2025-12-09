// push-subscription.js
// Handles Service Worker registration and PushManager subscription flow
(async function(){
  if (typeof window === 'undefined') return;
  window.PushManagerHelper = {
    isSupported: function(){ return ('serviceWorker' in navigator) && ('PushManager' in window) && ('Notification' in window); },
    getVapidKey: async function(){
      try{ const r = await fetch('/api/push/vapid_public_key'); if(!r.ok) throw new Error('no key'); const j = await r.json(); return j.vapid_public_key; }catch(e){ console.warn('Failed to fetch VAPID key', e); return null; }
    },
    registerServiceWorker: async function(){
      try{
        const reg = await navigator.serviceWorker.register('/static/js/sw.js');
        await navigator.serviceWorker.ready;
        return reg;
      }catch(e){ console.warn('SW register failed', e); return null; }
    },
    subscribeForPush: async function(user_id){
      if (!this.isSupported()) return { success: false, error: 'not_supported' };
      const permission = await Notification.requestPermission();
      if (permission !== 'granted') return { success: false, error: 'permission_denied' };
      const reg = await this.registerServiceWorker();
      if (!reg) return { success: false, error: 'sw_failed' };
      const vapidKey = await this.getVapidKey();
      if (!vapidKey) return { success: false, error: 'no_vapid' };
      // convert base64 url to Uint8Array
      function urlBase64ToUint8Array(base64String) {
        const padding = '='.repeat((4 - base64String.length % 4) % 4);
        const base64 = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
        const rawData = window.atob(base64);
        const outputArray = new Uint8Array(rawData.length);
        for (let i = 0; i < rawData.length; ++i) {
          outputArray[i] = rawData.charCodeAt(i);
        }
        return outputArray;
      }
      try{
        const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlBase64ToUint8Array(vapidKey) });
        // persist to server
        const body = { subscription: sub.toJSON() };
        if (user_id) body.user_id = user_id;
        const r = await fetch('/api/push/subscribe', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
        if (!r.ok) throw new Error('subscribe failed');
        return { success: true, subscription: sub };
      }catch(e){ console.warn('Subscription failed', e); return { success: false, error: e && e.message ? e.message : 'sub_error' }; }
    },
    unsubscribeForPush: async function(user_id){
      try{
        const reg = await navigator.serviceWorker.ready;
        const sub = await reg.pushManager.getSubscription();
        if (!sub) return { success: true };
        const body = { subscription: sub.toJSON() };
        if (user_id) body.user_id = user_id;
        const r = await fetch('/api/push/unsubscribe', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
        try{ await sub.unsubscribe(); }catch(e){}
        return { success: r.ok };
      }catch(e){ console.warn('Unsubscribe failed', e); return { success: false }; }
    }
  };
})();
