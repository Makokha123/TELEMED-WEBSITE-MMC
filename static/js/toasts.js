// toasts.js
// Minimal in-page toast helper to show temporary notifications
(function(){
  function ensureContainer(){
    let c = document.getElementById('inpage-toasts-container');
    if (!c) {
      c = document.createElement('div');
      c.id = 'inpage-toasts-container';
      c.style.position = 'fixed';
      c.style.right = '16px';
      c.style.bottom = '16px';
      c.style.zIndex = 99999;
      document.body.appendChild(c);
    }
    return c;
  }

  function showToast(title, body, options){
    options = options || {};
    const c = ensureContainer();
    const el = document.createElement('div');
    el.className = 'inpage-toast';
    el.style.background = options.background || '#222';
    el.style.color = options.color || '#fff';
    el.style.padding = '10px 14px';
    el.style.marginTop = '8px';
    el.style.borderRadius = '8px';
    el.style.boxShadow = '0 6px 20px rgba(0,0,0,0.15)';
    el.style.cursor = 'pointer';
    el.innerHTML = `<div style="font-weight:700;margin-bottom:2px;">${title}</div><div style="font-size:13px;opacity:0.95;">${body || ''}</div>`;
    if (options.onclick) el.addEventListener('click', options.onclick);
    c.appendChild(el);
    setTimeout(()=>{ el.style.transition = 'opacity 0.35s'; el.style.opacity = '0'; setTimeout(()=>el.remove(), 400); }, options.duration || 7000);
    return el;
  }

  window.InpageToasts = { show: showToast };
})();
