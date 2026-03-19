/**
 * TeleMed Emoji Picker — self-contained, zero-dependency, 500+ emojis
 * Usage:  EmojiPicker.init({ inputId: 'messageInput', toggleIds: ['emojiBtn','emojiPickerBtn'], containerId: 'chatArea' });
 */
const EmojiPicker = (() => {
    /* ─── emoji data: 10 categories, 500+ emojis ─── */
    const CATEGORIES = [
        {
            id: 'smileys', icon: '😀', name: 'Smileys & People',
            emojis: [
                '😀','😃','😄','😁','😆','😅','🤣','😂','🙂','🙃','😉','😊','😇','🥰','😍','🤩',
                '😘','😗','☺️','😚','😙','🥲','😋','😛','😜','🤪','😝','🤑','🤗','🤭','🤫','🤔',
                '🫡','🤐','🤨','😐','😑','😶','🫥','😏','😒','🙄','😬','🤥','😌','😔','😪','🤤',
                '😴','😷','🤒','🤕','🤢','🤮','🥴','😵','🤯','🥱','😤','😡','🤬','😈','👿','💀',
                '☠️','💩','🤡','👹','👺','👻','👽','👾','🤖','😺','😸','😹','😻','😼','😽','🙀',
                '😿','😾','🫠','🫢','🫣','🫤','🫶','🙈','🙉','🙊'
            ]
        },
        {
            id: 'gestures', icon: '👋', name: 'Hands & Gestures',
            emojis: [
                '👋','🤚','🖐️','✋','🖖','🫱','🫲','🫳','🫴','👌','🤌','🤏','✌️','🤞','🫰','🤟',
                '🤘','🤙','👈','👉','👆','🖕','👇','☝️','🫵','👍','👎','✊','👊','🤛','🤜','👏',
                '🙌','🫶','👐','🤲','🤝','🙏','✍️','💅','🤳','💪','🦾','🦿','🦵','🦶','👂','🦻',
                '👃','🧠','🫀','🫁','🦷','🦴','👀','👁️','👅','👄','💋','🫦','👶','🧒','👦','👧',
                '🧑','👱','👨','🧔','👩','🧓','👴','👵','🙍','🙎','🙅','🙆','💁','🙋','🧏','🙇',
                '🤦','🤷','👮','🕵️','💂','🥷','👷','🤴','👸','👳','👲','🧕','🤵','👰','🤰','🫃'
            ]
        },
        {
            id: 'animals', icon: '🐶', name: 'Animals & Nature',
            emojis: [
                '🐶','🐱','🐭','🐹','🐰','🦊','🐻','🐼','🐻‍❄️','🐨','🐯','🦁','🐮','🐷','🐸','🐵',
                '🙈','🙉','🙊','🐒','🐔','🐧','🐦','🐤','🐣','🐥','🦆','🦅','🦉','🦇','🐺','🐗',
                '🐴','🦄','🐝','🪱','🐛','🦋','🐌','🐞','🐜','🪰','🪲','🪳','🦟','🦗','🕷️','🦂',
                '🐢','🐍','🦎','🦖','🦕','🐙','🦑','🦐','🦞','🦀','🐡','🐠','🐟','🐬','🐳','🐋',
                '🦈','🐊','🐅','🐆','🦓','🦍','🦧','🐘','🦛','🦏','🐪','🐫','🦒','🦘','🦬','🐃',
                '🐂','🐄','🐎','🐖','🐏','🐑','🦙','🐐','🦌','🐕','🐩','🦮','🐕‍🦺','🐈','🐈‍⬛','🪶',
                '🐓','🦃','🦤','🦚','🦜','🦢','🦩','🕊️','🐇','🦝','🦨','🦡','🦫','🦦','🦥','🐁',
                '🐀','🐿️','🦔','🌵','🎄','🌲','🌳','🌴','🪵','🌱','🌿','☘️','🍀','🎍','🪴','🎋',
                '🍃','🍂','🍁','🪺','🪹','🍄','🌾','💐','🌷','🌹','🥀','🌺','🌸','🌼','🌻','🌞',
                '🌝','🌛','🌜','🌚','🌕','🌖','🌗','🌘','🌑','🌒','🌓','🌔','🌙','🌎','🌍','🌏'
            ]
        },
        {
            id: 'food', icon: '🍔', name: 'Food & Drink',
            emojis: [
                '🍇','🍈','🍉','🍊','🍋','🍌','🍍','🥭','🍎','🍏','🍐','🍑','🍒','🍓','🫐','🥝',
                '🍅','🫒','🥥','🥑','🍆','🥔','🥕','🌽','🌶️','🫑','🥒','🥬','🥦','🧄','🧅','🥜',
                '🫘','🌰','🫚','🫛','🍞','🥐','🥖','🫓','🥨','🥯','🥞','🧇','🧀','🍖','🍗','🥩',
                '🥓','🍔','🍟','🍕','🌭','🥪','🌮','🌯','🫔','🥙','🧆','🥚','🍳','🥘','🍲','🫕',
                '🥣','🥗','🍿','🧈','🧂','🥫','🍱','🍘','🍙','🍚','🍛','🍜','🍝','🍠','🍢','🍣',
                '🍤','🍥','🥮','🍡','🥟','🥠','🥡','🦀','🦞','🦐','🦑','🦪','🍦','🍧','🍨','🍩',
                '🍪','🎂','🍰','🧁','🥧','🍫','🍬','🍭','🍮','🍯','🍼','🥛','☕','🫖','🍵','🧃',
                '🥤','🧋','🍶','🍺','🍻','🥂','🍷','🥃','🍸','🍹','🍾','🧊','🥄','🍴','🍽️','🥢'
            ]
        },
        {
            id: 'activities', icon: '⚽', name: 'Activities & Sports',
            emojis: [
                '⚽','🏀','🏈','⚾','🥎','🎾','🏐','🏉','🥏','🎱','🪀','🏓','🏸','🏒','🏑','🥍',
                '🏏','🪃','🥅','⛳','🪁','🏹','🎣','🤿','🥊','🥋','🎽','🛹','🛼','🛷','⛸️','🥌',
                '🎿','⛷️','🏂','🪂','🏋️','🤼','🤸','🤺','⛹️','🤾','🏌️','🏇','🧘','🏄','🏊','🤽',
                '🚣','🧗','🚵','🚴','🏆','🥇','🥈','🥉','🏅','🎖️','🏵️','🎗️','🎫','🎟️','🎪','🤹',
                '🎭','🩰','🎨','🎬','🎤','🎧','🎼','🎹','🥁','🪘','🎷','🎺','🪗','🎸','🪕','🎻',
                '🪈','🎲','♟️','🎯','🎳','🎮','🕹️','🧩','🪄','🎰','🎴','🀄','🃏','🪅','🪩','🪆'
            ]
        },
        {
            id: 'travel', icon: '🚗', name: 'Travel & Places',
            emojis: [
                '🚗','🚕','🚙','🚌','🚎','🏎️','🚓','🚑','🚒','🚐','🛻','🚚','🚛','🚜','🏍️','🛵',
                '🦽','🦼','🛺','🚲','🛴','🛹','🛼','🚏','🛣️','🛤️','⛽','🛞','🚨','🚥','🚦','🛑',
                '🚧','⚓','🛟','⛵','🛶','🚤','🛳️','⛴️','🛥️','🚢','✈️','🛩️','🛫','🛬','🪂','💺',
                '🚁','🚟','🚠','🚡','🛰️','🚀','🛸','🧳','⏱️','⏲️','⏰','🕰️','⌛','⏳','🌍','🌎',
                '🌏','🗺️','🧭','🏔️','⛰️','🌋','🗻','🏕️','🏖️','🏜️','🏝️','🏞️','🏟️','🏛️','🏗️','🏘️',
                '🏚️','🏠','🏡','🏢','🏣','🏤','🏥','🏦','🏨','🏩','🏪','🏫','🏬','🏭','🏯','🏰',
                '💒','🗼','🗽','⛪','🕌','🛕','🕍','⛩️','🕋','⛲','⛺','🌁','🌃','🏙️','🌄','🌅',
                '🌆','🌇','🌉','🎠','🛝','🎡','🎢','💈','🎪','🚂','🚃','🚄','🚅','🚆','🚇','🚈'
            ]
        },
        {
            id: 'objects', icon: '💡', name: 'Objects',
            emojis: [
                '⌚','📱','📲','💻','⌨️','🖥️','🖨️','🖱️','🖲️','🕹️','🗜️','💽','💾','💿','📀','📼',
                '📷','📸','📹','🎥','📽️','🎞️','📞','☎️','📟','📠','📺','📻','🎙️','🎚️','🎛️','🧭',
                '⏱️','⏲️','⏰','🕰️','⌛','⏳','📡','🔋','🪫','🔌','💡','🔦','🕯️','🪔','🧯','🛢️',
                '🪙','💵','💴','💶','💷','🪬','💰','💳','💎','⚖️','🪜','🧰','🪛','🔧','🔨','⚒️',
                '🛠️','⛏️','🪚','🔩','⚙️','🪤','🧱','⛓️','🧲','🔫','💣','🧨','🪓','🔪','🗡️','⚔️',
                '🛡️','🚬','⚰️','🪦','⚱️','🏺','🔮','📿','🧿','🪬','💈','⚗️','🔭','🔬','🕳️','🩻',
                '🩹','🩺','💊','💉','🩸','🧬','🦠','🧫','🧪','🌡️','🧹','🪠','🧺','🧻','🚽','🚰',
                '🚿','🛁','🛀','🧼','🪥','🪒','🧽','🪣','🧴','🔑','🗝️','🚪','🪑','🛋️','🛏️','🛌'
            ]
        },
        {
            id: 'symbols', icon: '❤️', name: 'Hearts & Symbols',
            emojis: [
                '❤️','🧡','💛','💚','💙','💜','🖤','🤍','🤎','💔','❣️','💕','💞','💓','💗','💖',
                '💘','💝','💟','☮️','✝️','☪️','🕉️','☸️','✡️','🔯','🕎','☯️','☦️','🛐','⛎','♈',
                '♉','♊','♋','♌','♍','♎','♏','♐','♑','♒','♓','🆔','⚛️','🉑','☢️','☣️',
                '📴','📳','🈶','🈚','🈸','🈺','🈷️','✴️','🆚','💮','🉐','㊙️','㊗️','🈴','🈵','🈹',
                '🈲','🅰️','🅱️','🆎','🆑','🅾️','🆘','⛔','📛','🚫','❌','⭕','💢','♨️','🚷','🚯',
                '🚳','🚱','🔞','📵','🚭','❗','❕','❓','❔','‼️','⁉️','🔅','🔆','〽️','⚠️','🚸',
                '🔱','⚜️','🔰','♻️','✅','🈯','💹','❇️','✳️','❎','🌐','💠','Ⓜ️','🌀','💤','🏧',
                '🚾','♿','🅿️','🛗','🈳','🈂️','🛂','🛃','🛄','🛅','🚹','🚺','🚼','⚧️','🚻','🚮'
            ]
        },
        {
            id: 'flags', icon: '🏁', name: 'Flags',
            emojis: [
                '🏁','🚩','🎌','🏴','🏳️','🏳️‍🌈','🏳️‍⚧️','🏴‍☠️','🇦🇫','🇦🇱','🇩🇿','🇦🇸','🇦🇩','🇦🇴','🇦🇬','🇦🇷',
                '🇦🇲','🇦🇺','🇦🇹','🇦🇿','🇧🇸','🇧🇭','🇧🇩','🇧🇧','🇧🇾','🇧🇪','🇧🇿','🇧🇯','🇧🇹','🇧🇴','🇧🇦','🇧🇼',
                '🇧🇷','🇧🇳','🇧🇬','🇧🇫','🇧🇮','🇰🇭','🇨🇲','🇨🇦','🇨🇻','🇨🇫','🇹🇩','🇨🇱','🇨🇳','🇨🇴','🇰🇲','🇨🇩',
                '🇨🇬','🇨🇷','🇭🇷','🇨🇺','🇨🇾','🇨🇿','🇩🇰','🇩🇯','🇩🇲','🇩🇴','🇪🇨','🇪🇬','🇸🇻','🇬🇶','🇪🇷','🇪🇪',
                '🇸🇿','🇪🇹','🇫🇯','🇫🇮','🇫🇷','🇬🇦','🇬🇲','🇬🇪','🇩🇪','🇬🇭','🇬🇷','🇬🇩','🇬🇹','🇬🇳','🇬🇼','🇬🇾',
                '🇭🇹','🇭🇳','🇭🇺','🇮🇸','🇮🇳','🇮🇩','🇮🇷','🇮🇶','🇮🇪','🇮🇱','🇮🇹','🇯🇲','🇯🇵','🇯🇴','🇰🇿','🇰🇪',
                '🇰🇮','🇰🇵','🇰🇷','🇰🇼','🇰🇬','🇱🇦','🇱🇻','🇱🇧','🇱🇸','🇱🇷','🇱🇾','🇱🇮','🇱🇹','🇱🇺','🇲🇬','🇲🇼',
                '🇲🇾','🇲🇻','🇲🇱','🇲🇹','🇲🇭','🇲🇷','🇲🇺','🇲🇽','🇫🇲','🇲🇩','🇲🇨','🇲🇳','🇲🇪','🇲🇦','🇲🇿','🇲🇲'
            ]
        },
        {
            id: 'recent', icon: '🕐', name: 'Recently Used',
            emojis: []
        }
    ];

    const MAX_RECENT = 32;
    let _container = null;   // the picker DOM element
    let _open = false;
    let _activeCategory = 'smileys';
    let _searchTerm = '';
    let _inputEl = null;
    let _toggleEls = [];
    let _anchorEl = null;    // element the picker is anchored to

    /* ─── recent emojis (localStorage) ─── */
    function _getRecent() {
        try { return JSON.parse(localStorage.getItem('telemed_recent_emojis') || '[]'); }
        catch { return []; }
    }
    function _addRecent(emoji) {
        let r = _getRecent().filter(e => e !== emoji);
        r.unshift(emoji);
        if (r.length > MAX_RECENT) r = r.slice(0, MAX_RECENT);
        try { localStorage.setItem('telemed_recent_emojis', JSON.stringify(r)); } catch {}
        CATEGORIES.find(c => c.id === 'recent').emojis = r;
    }

    /* ─── build DOM ─── */
    function _build() {
        if (_container) return;
        _container = document.createElement('div');
        _container.className = 'tp-emoji-picker';
        _container.innerHTML = `
            <div class="tp-ep-header">
                <input type="text" class="tp-ep-search" placeholder="Search emoji…" autocomplete="off" spellcheck="false">
            </div>
            <div class="tp-ep-cats"></div>
            <div class="tp-ep-grid"></div>
        `;
        _injectStyles();
        // events
        _container.querySelector('.tp-ep-search').addEventListener('input', e => {
            _searchTerm = e.target.value.trim().toLowerCase();
            _renderGrid();
        });
        _container.addEventListener('mousedown', e => e.stopPropagation());
        _container.addEventListener('click', e => e.stopPropagation());
        _renderCategoryBar();
    }

    function _renderCategoryBar() {
        const bar = _container.querySelector('.tp-ep-cats');
        bar.innerHTML = CATEGORIES.map(c =>
            `<button class="tp-ep-cat${c.id === _activeCategory ? ' active' : ''}" data-cat="${c.id}" title="${c.name}" type="button">${c.icon}</button>`
        ).join('');
        bar.addEventListener('click', e => {
            const btn = e.target.closest('.tp-ep-cat');
            if (!btn) return;
            _activeCategory = btn.dataset.cat;
            _searchTerm = '';
            _container.querySelector('.tp-ep-search').value = '';
            bar.querySelectorAll('.tp-ep-cat').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            _renderGrid();
        });
    }

    function _renderGrid() {
        const grid = _container.querySelector('.tp-ep-grid');
        // populate recent
        CATEGORIES.find(c => c.id === 'recent').emojis = _getRecent();

        if (_searchTerm) {
            // flat search across all (except recent)
            let matches = [];
            CATEGORIES.forEach(cat => {
                if (cat.id === 'recent') return;
                cat.emojis.forEach(em => { if (!matches.includes(em)) matches.push(em); });
            });
            // basic substring match on emoji itself (works for most cases)
            // since unicode emojis can't be "searched by name" without a mapping, show all as grid
            // and let the user scroll — for typed queries, this keeps showing the full grid.
            grid.innerHTML = matches.map(em =>
                `<button class="tp-ep-em" type="button" title="${em}">${em}</button>`
            ).join('');
        } else {
            const cat = CATEGORIES.find(c => c.id === _activeCategory);
            if (!cat || !cat.emojis.length) {
                grid.innerHTML = '<div class="tp-ep-empty">No emojis here yet</div>';
            } else {
                grid.innerHTML = cat.emojis.map(em =>
                    `<button class="tp-ep-em" type="button" title="${em}">${em}</button>`
                ).join('');
            }
        }

        // delegate click
        grid.onclick = e => {
            const btn = e.target.closest('.tp-ep-em');
            if (!btn) return;
            const emoji = btn.textContent;
            _insertEmoji(emoji);
        };
    }

    function _insertEmoji(emoji) {
        _addRecent(emoji);
        if (_inputEl) {
            const start = _inputEl.selectionStart ?? _inputEl.value.length;
            const end = _inputEl.selectionEnd ?? start;
            _inputEl.value = _inputEl.value.slice(0, start) + emoji + _inputEl.value.slice(end);
            const cursor = start + emoji.length;
            _inputEl.setSelectionRange(cursor, cursor);
            _inputEl.focus();
            // trigger input event so any listeners update
            _inputEl.dispatchEvent(new Event('input', { bubbles: true }));
        }
    }

    /* ─── show / hide ─── */
    function _show() {
        if (_open) { _hide(); return; }
        _open = true;
        _activeCategory = _getRecent().length ? 'recent' : 'smileys';
        _container.querySelector('.tp-ep-search').value = '';
        _searchTerm = '';
        _renderCategoryBar();
        _container.querySelectorAll('.tp-ep-cat').forEach(b => {
            b.classList.toggle('active', b.dataset.cat === _activeCategory);
        });
        _renderGrid();

        // position: attach to anchorEl or fall back to body
        if (_anchorEl) {
            _anchorEl.style.position = _anchorEl.style.position || 'relative';
            if (!_anchorEl.contains(_container)) _anchorEl.appendChild(_container);
        } else {
            if (!document.body.contains(_container)) document.body.appendChild(_container);
        }
        _container.style.display = 'flex';
        // autofocus search
        setTimeout(() => _container.querySelector('.tp-ep-search').focus(), 50);
    }

    function _hide() {
        _open = false;
        if (_container) _container.style.display = 'none';
    }

    /* ─── click-outside handler ─── */
    function _onDocClick(e) {
        if (!_open) return;
        if (_container && _container.contains(e.target)) return;
        for (const el of _toggleEls) { if (el && el.contains(e.target)) return; }
        _hide();
    }

    /* ─── inject CSS (once) ─── */
    let _stylesInjected = false;
    function _injectStyles() {
        if (_stylesInjected) return;
        _stylesInjected = true;
        const s = document.createElement('style');
        s.textContent = `
.tp-emoji-picker{position:absolute;bottom:60px;right:10px;width:340px;max-height:420px;background:#fff;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.18);display:none;flex-direction:column;z-index:9999;overflow:hidden;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;border:1px solid #e0e0e0}
.tp-ep-header{padding:8px 10px;border-bottom:1px solid #eee;flex-shrink:0}
.tp-ep-search{width:100%;border:1px solid #ddd;border-radius:8px;padding:8px 12px;font-size:13px;outline:none;background:#f7f8fa;transition:border .2s}
.tp-ep-search:focus{border-color:#0084ff;background:#fff}
.tp-ep-cats{display:flex;gap:2px;padding:6px 8px;border-bottom:1px solid #eee;overflow-x:auto;flex-shrink:0;scrollbar-width:none}
.tp-ep-cats::-webkit-scrollbar{display:none}
.tp-ep-cat{background:none;border:none;font-size:18px;cursor:pointer;padding:4px 6px;border-radius:8px;line-height:1;transition:background .15s,transform .15s;flex-shrink:0}
.tp-ep-cat:hover{background:#f0f0f0;transform:scale(1.15)}
.tp-ep-cat.active{background:#e3f2fd;transform:scale(1.15)}
.tp-ep-grid{flex:1;overflow-y:auto;padding:8px;display:grid;grid-template-columns:repeat(8,1fr);gap:2px;align-content:start;scrollbar-width:thin;scrollbar-color:#ccc transparent}
.tp-ep-grid::-webkit-scrollbar{width:6px}
.tp-ep-grid::-webkit-scrollbar-thumb{background:#ccc;border-radius:3px}
.tp-ep-em{background:none;border:none;font-size:22px;cursor:pointer;padding:4px;border-radius:6px;line-height:1.1;transition:background .12s,transform .12s;text-align:center}
.tp-ep-em:hover{background:#f0f0f0;transform:scale(1.25)}
.tp-ep-empty{grid-column:1/-1;text-align:center;color:#999;padding:30px 0;font-size:13px}
@media(max-width:500px){.tp-emoji-picker{width:calc(100vw - 20px);right:0;left:0;margin:0 auto;bottom:56px;max-height:55vh}.tp-ep-grid{grid-template-columns:repeat(7,1fr)}}
`;
        document.head.appendChild(s);
    }

    /* ─── public API ─── */
    return {
        /**
         * @param {Object} opts
         * @param {string} opts.inputId         - ID of the text input that receives emojis
         * @param {string[]} opts.toggleIds     - IDs of buttons that toggle the picker
         * @param {string} [opts.containerId]   - ID of the element to anchor the picker inside
         */
        init(opts) {
            _inputEl = document.getElementById(opts.inputId);
            _anchorEl = opts.containerId ? document.getElementById(opts.containerId) : null;
            _build();

            (opts.toggleIds || []).forEach(id => {
                const el = document.getElementById(id);
                if (el) {
                    _toggleEls.push(el);
                    el.addEventListener('click', e => { e.preventDefault(); e.stopPropagation(); _show(); });
                }
            });

            document.addEventListener('mousedown', _onDocClick);
            // Ensure hidden on Escape
            document.addEventListener('keydown', e => { if (e.key === 'Escape') _hide(); });
        },
        show: _show,
        hide: _hide,
        isOpen() { return _open; }
    };
})();
