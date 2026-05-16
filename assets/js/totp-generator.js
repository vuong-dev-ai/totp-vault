/**
 * TOTP Vault v5 — Quản lý nhiều 2FA, note thêm sau qua nút "+"
 */
(function () {
    'use strict';

    // ==========================================================
    // CRYPTO: Base32 + SHA-1 + HMAC + TOTP
    // ==========================================================
    const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    function base32Decode(input) {
        const cleaned = String(input).toUpperCase().replace(/\s+/g, '').replace(/=+$/, '');
        if (!cleaned.length) throw new Error('Secret rỗng.');
        if (!/^[A-Z2-7]+$/.test(cleaned)) throw new Error('Secret chỉ dùng A–Z và 2–7.');
        let bits = '';
        for (const ch of cleaned) bits += BASE32.indexOf(ch).toString(2).padStart(5, '0');
        const bytes = new Uint8Array(Math.floor(bits.length / 8));
        for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(bits.slice(i*8, i*8+8), 2);
        if (!bytes.length) throw new Error('Secret quá ngắn.');
        return bytes;
    }

    function sha1(bytes) {
        const msgLen = bytes.length, bitLen = msgLen * 8;
        const totalLen = (((msgLen + 8) >> 6) + 1) << 6;
        const p = new Uint8Array(totalLen);
        p.set(bytes); p[msgLen] = 0x80;
        const hi = Math.floor(bitLen / 0x100000000), lo = bitLen >>> 0;
        p[totalLen-8]=(hi>>>24)&0xff; p[totalLen-7]=(hi>>>16)&0xff;
        p[totalLen-6]=(hi>>>8)&0xff;  p[totalLen-5]=hi&0xff;
        p[totalLen-4]=(lo>>>24)&0xff; p[totalLen-3]=(lo>>>16)&0xff;
        p[totalLen-2]=(lo>>>8)&0xff;  p[totalLen-1]=lo&0xff;
        let h0=0x67452301,h1=0xefcdab89,h2=0x98badcfe,h3=0x10325476,h4=0xc3d2e1f0;
        const w = new Uint32Array(80);
        const rol = (n,s) => ((n<<s)|(n>>>(32-s)))>>>0;
        for (let b=0; b<totalLen; b+=64) {
            for (let i=0; i<16; i++) { const j=b+i*4; w[i] = ((p[j]<<24)|(p[j+1]<<16)|(p[j+2]<<8)|p[j+3])>>>0; }
            for (let i=16; i<80; i++) w[i] = rol((w[i-3]^w[i-8]^w[i-14]^w[i-16])>>>0, 1);
            let a=h0,bb=h1,c=h2,d=h3,e=h4;
            for (let i=0; i<80; i++) {
                let f,k;
                if (i<20)      { f=(bb&c)|((~bb)&d);        k=0x5a827999; }
                else if (i<40) { f=bb^c^d;                   k=0x6ed9eba1; }
                else if (i<60) { f=(bb&c)|(bb&d)|(c&d);      k=0x8f1bbcdc; }
                else           { f=bb^c^d;                   k=0xca62c1d6; }
                f=f>>>0;
                const t = (rol(a,5)+f+e+k+w[i])>>>0;
                e=d; d=c; c=rol(bb,30); bb=a; a=t;
            }
            h0=(h0+a)>>>0; h1=(h1+bb)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0; h4=(h4+e)>>>0;
        }
        const out = new Uint8Array(20);
        [h0,h1,h2,h3,h4].forEach((h,i) => {
            out[i*4]=(h>>>24)&0xff; out[i*4+1]=(h>>>16)&0xff;
            out[i*4+2]=(h>>>8)&0xff; out[i*4+3]=h&0xff;
        });
        return out;
    }

    function hmacSha1Js(key, data) {
        const B=64; let k=key;
        if (k.length>B) k=sha1(k);
        if (k.length<B) { const t=new Uint8Array(B); t.set(k); k=t; }
        const o=new Uint8Array(B), i=new Uint8Array(B);
        for (let x=0; x<B; x++) { o[x]=k[x]^0x5c; i[x]=k[x]^0x36; }
        const inner=new Uint8Array(B+data.length); inner.set(i); inner.set(data,B);
        const ih=sha1(inner);
        const outer=new Uint8Array(B+ih.length); outer.set(o); outer.set(ih,B);
        return sha1(outer);
    }

    function counterBytes(c) {
        const b = new Uint8Array(8);
        const hi = Math.floor(c/0x100000000), lo = c>>>0;
        b[0]=(hi>>>24)&0xff; b[1]=(hi>>>16)&0xff; b[2]=(hi>>>8)&0xff; b[3]=hi&0xff;
        b[4]=(lo>>>24)&0xff; b[5]=(lo>>>16)&0xff; b[6]=(lo>>>8)&0xff; b[7]=lo&0xff;
        return b;
    }

    const canUseSubtle = !!(window.crypto && window.crypto.subtle && window.isSecureContext);

    async function hmac(key, data) {
        if (canUseSubtle) {
            try {
                const k = await crypto.subtle.importKey('raw', key, {name:'HMAC',hash:'SHA-1'}, false, ['sign']);
                return new Uint8Array(await crypto.subtle.sign('HMAC', k, data));
            } catch (_) { return hmacSha1Js(key, data); }
        }
        return hmacSha1Js(key, data);
    }

    async function hotp(key, counter, digits) {
        const h = await hmac(key, counterBytes(counter));
        const off = h[h.length-1] & 0x0f;
        const bin = ((h[off]&0x7f)<<24) | ((h[off+1]&0xff)<<16) | ((h[off+2]&0xff)<<8) | (h[off+3]&0xff);
        return String(bin % Math.pow(10,digits)).padStart(digits,'0');
    }

    async function totp(secret, period, digits) {
        const key = base32Decode(secret);
        const counter = Math.floor(Date.now() / 1000 / period);
        return hotp(key, counter, digits);
    }

    function formatCode(c) {
        if (c.length === 6) return c.slice(0,3) + ' ' + c.slice(3);
        if (c.length === 8) return c.slice(0,4) + ' ' + c.slice(4);
        return c;
    }

    // ==========================================================
    // TYPES (svg dùng cho icon trong list item)
    // ==========================================================
    const TYPES = {
        google:  { label: 'Google',   svg: 'G' },
        github:  { label: 'GitHub',   svg: '<svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M12 .3a12 12 0 0 0-3.8 23.4c.6.1.8-.3.8-.6v-2.1c-3.3.7-4-1.6-4-1.6-.6-1.4-1.4-1.8-1.4-1.8-1.1-.7.1-.7.1-.7 1.2.1 1.9 1.3 1.9 1.3 1.1 1.9 2.9 1.4 3.6 1 .1-.8.4-1.4.8-1.7-2.7-.3-5.5-1.3-5.5-6 0-1.3.5-2.4 1.3-3.2 0-.4-.6-1.6.1-3.4 0 0 1-.3 3.3 1.2a11.5 11.5 0 0 1 6 0c2.3-1.5 3.3-1.2 3.3-1.2.7 1.8.2 3 .1 3.4.8.8 1.3 1.9 1.3 3.2 0 4.6-2.8 5.7-5.5 6 .4.4.8 1.1.8 2.2v3.3c0 .3.2.7.8.6A12 12 0 0 0 12 .3"/></svg>' },
        chatgpt: { label: 'ChatGPT',  svg: 'AI' },
        discord: { label: 'Discord',  svg: '<svg viewBox="0 0 24 24" width="16" height="16" fill="currentColor"><path d="M20.3 4.4A19.8 19.8 0 0 0 15.4 3l-.3.5a18 18 0 0 0-6.2 0L8.6 3a19.8 19.8 0 0 0-5 1.5C0 9.4-.6 14.3.2 19.1a20 20 0 0 0 6 3l1.2-1.7-2.4-1.1.5-.4a14 14 0 0 0 12 0l.5.4-2.4 1.1 1.2 1.7a20 20 0 0 0 6-3c1-5.5.2-10.3-2.5-14.7M8.5 16c-1.2 0-2.2-1.1-2.2-2.5S7.3 11 8.5 11s2.2 1.1 2.2 2.5S9.7 16 8.5 16m6.9 0c-1.2 0-2.2-1.1-2.2-2.5S14.3 11 15.4 11s2.2 1.1 2.2 2.5S16.6 16 15.4 16"/></svg>' },
        other:   { label: 'Khác',     svg: '?' },
    };

    // ==========================================================
    // STORAGE
    // ==========================================================
    const STORAGE_KEY = 'totp-vault-items-v5';
    const PERIOD = 30;
    const DIGITS = 6;

    let items = []; // {id, type, secret, note}
    let selectedType = 'google';

    function loadItems() {
        try {
            const raw = localStorage.getItem(STORAGE_KEY);
            items = raw ? JSON.parse(raw) : [];
            if (!Array.isArray(items)) items = [];
            // migrate: old 'label' -> 'note'
            items = items.map(it => ({
                id: it.id, type: it.type, secret: it.secret,
                note: it.note ?? it.label ?? ''
            }));
        } catch { items = []; }
    }

    function saveItems() {
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(items)); }
        catch (e) { console.warn('Lưu thất bại:', e); }
    }

    function genId() {
        return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
    }

    // ==========================================================
    // CLIPBOARD
    // ==========================================================
    async function copyToClipboard(text) {
        try {
            if (navigator.clipboard && navigator.clipboard.writeText && window.isSecureContext) {
                await navigator.clipboard.writeText(text);
                return true;
            }
        } catch (_) {}
        try {
            const ta = document.createElement('textarea');
            ta.value = text;
            ta.setAttribute('readonly', '');
            ta.style.position = 'fixed';
            ta.style.opacity = '0';
            document.body.appendChild(ta);
            ta.select();
            ta.setSelectionRange(0, text.length);
            const ok = document.execCommand('copy');
            document.body.removeChild(ta);
            return ok;
        } catch (_) { return false; }
    }

    // ==========================================================
    // TOAST
    // ==========================================================
    let toastTimer = null;
    function showToast(msg, kind = 'success') {
        const toast = document.getElementById('toast');
        if (!toast) return;
        toast.className = 'totp-toast is-' + kind;
        const icon = kind === 'error'
            ? '<svg class="totp-toast__icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>'
            : '<svg class="totp-toast__icon" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
        toast.innerHTML = icon + '<span>' + esc(msg) + '</span>';
        toast.hidden = false;
        clearTimeout(toastTimer);
        toastTimer = setTimeout(() => { toast.hidden = true; }, 2400);
    }

    // ==========================================================
    // ESCAPE
    // ==========================================================
    function esc(s) {
        return String(s ?? '')
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    // ==========================================================
    // SMART PARSE: tự tách secret + note từ chuỗi paste
    // Hỗ trợ nhiều format:
    //   - Dính liền:  SECRETemail@gmail.compass@
    //   - Dấu |:      email|pass|secret
    //   - Cách nhiều khoảng trắng, xuống dòng, tab
    //   - Bao bởi dấu nháy
    // Chiến lược: tìm SECRET trước (Base32 chuẩn), rồi mới
    // extract email từ phần còn lại. Tránh case email greedy
    // ăn cả secret khi không có separator.
    // ==========================================================
    function parseSmartInput(raw) {
        let text = String(raw).trim();
        text = text.replace(/^["'`]+|["'`]+$/g, '').trim();
        if (!text) return null;

        let secret = null;
        let workText = text;

        // 1a. Formatted: 4+ nhóm Base32 4 ký tự cách bởi space/tab
        //     (kiểu "abcd efgh ijkl ..." Google Authenticator display)
        let m = workText.match(/[A-Za-z2-7]{4}(?:[ \t]+[A-Za-z2-7]{4}){3,}/);
        if (m) {
            secret = m[0];
        } else {
            // 1b. Uppercase Base32 ≥16 ký tự liền (Google/GitHub raw style)
            m = workText.match(/[A-Z2-7]{16,}/);
            if (m) {
                secret = m[0];
            } else {
                // 1c. Fallback: bất kỳ Base32 ≥16 ký tự (lấy dài nhất)
                const all = [...workText.matchAll(/[A-Za-z2-7]{16,}/g)];
                if (all.length > 0) {
                    all.sort((a, b) => b[0].length - a[0].length);
                    secret = all[0][0];
                }
            }
        }

        if (secret) workText = workText.replace(secret, '\n');

        // 2. Extract email từ phần còn lại
        //    [a-z]{2,} cho TLD để tránh ăn nhầm chữ in hoa liền sau
        const emailRegex = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[a-z]{2,}/g;
        const emails = workText.match(emailRegex) || [];
        workText = workText.replace(emailRegex, '\n');

        // 3. Phần còn lại tách theo separator hoặc nhiều space liên tiếp
        const otherParts = workText
            .split(/[|\n\t;]+|[ ]{2,}/)
            .map(s => s.trim())
            .filter(Boolean);

        return {
            secret: secret || '',
            note: [...emails, ...otherParts].join(' · ')
        };
    }

    function detectType(text) {
        const lower = String(text).toLowerCase();
        if (/@gmail\.com|@googlemail|\bgoogle\b/.test(lower))  return 'google';
        if (/github/.test(lower))                                return 'github';
        if (/discord/.test(lower))                               return 'discord';
        if (/chatgpt|openai/.test(lower))                        return 'chatgpt';
        return null;
    }

    // ==========================================================
    // RENDER
    // ==========================================================
    const listEl   = document.getElementById('list');
    const emptyEl  = document.getElementById('emptyState');
    const countEl  = document.getElementById('countBadge');

    // Search state (set by init's input handler)
    let searchQuery = '';

    function applySearch() {
        const q = searchQuery.toLowerCase().trim();
        let visibleCount = 0;

        const allItemEls = listEl.querySelectorAll('.totp-item');
        allItemEls.forEach(itemEl => {
            const id = itemEl.dataset.id;
            const item = items.find(it => it.id === id);
            if (!item) return;

            let matches = !q;
            if (q) {
                const haystack = [
                    item.note || '',
                    TYPES[item.type]?.label || '',
                    item.type || ''
                ].join(' ').toLowerCase();
                matches = haystack.includes(q);
            }

            itemEl.hidden = !matches;
            if (matches) visibleCount++;
        });

        const searchBox    = document.getElementById('searchBox');
        const noResults    = document.getElementById('noResultsState');
        const noResultsQ   = document.getElementById('noResultsQuery');

        if (searchBox) searchBox.hidden = items.length === 0;

        if (noResults) {
            const showNoResults = items.length > 0 && q && visibleCount === 0;
            noResults.hidden = !showNoResults;
            if (showNoResults && noResultsQ) noResultsQ.textContent = `"${searchQuery}"`;
        }
    }

    function itemHtml(it) {
        const t = TYPES[it.type] || TYPES.other;
        const hasNote = !!it.note;
        return `
            <div class="totp-item" data-id="${esc(it.id)}">
                <div class="totp-item__head">
                    <div class="totp-item__icon totp-item__icon--${esc(it.type)}">${t.svg}</div>
                    <div class="totp-item__title">
                        <span class="totp-item__name">${esc(t.label)}</span>
                    </div>
                    <button type="button" class="totp-item-btn totp-item-btn--delete" data-role="delete" aria-label="Xóa">
                        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"></path><path d="M10 11v6"></path><path d="M14 11v6"></path></svg>
                    </button>
                </div>

                <div class="totp-item__secret">${esc(it.secret)}</div>

                <div class="totp-item__code-row">
                    <span class="totp-item__code" data-role="code">— — —   — — —</span>
                    <div class="totp-item__actions">
                        <button type="button" class="totp-item-btn totp-item-btn--copy" data-role="copy" aria-label="Copy mã">
                            <svg class="icon-copy" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                            <svg class="icon-check" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
                        </button>
                        <button type="button" class="totp-item-btn totp-item-btn--note" data-role="note-toggle" aria-label="Thêm/sửa note">
                            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>
                        </button>
                    </div>
                </div>

                <div class="totp-item__note-display" data-role="note-display"${hasNote ? '' : ' hidden'}>
                    <svg class="totp-item__note-icon" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                        <polyline points="14 2 14 8 20 8"></polyline>
                    </svg>
                    <span class="totp-item__note-text" data-role="note-text">${esc(it.note)}</span>
                    <button type="button" class="totp-item-btn totp-item-btn--copy-note" data-role="copy-note" aria-label="Copy note">
                        <svg class="icon-copy" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                        <svg class="icon-check" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>
                    </button>
                </div>

                <form class="totp-item__note-form" hidden data-role="note-form">
                    <input type="text" class="totp-item__note-input" placeholder="Nhập note (bỏ trống để xóa)" value="${esc(it.note)}" maxlength="200" />
                    <button type="submit" class="totp-item__note-save">Lưu</button>
                </form>

                <div class="totp-item__progress"><div class="totp-item__progress-fill" data-role="prog"></div></div>
            </div>
        `;
    }

    function renderList() {
        if (!items.length) {
            listEl.innerHTML = '';
            emptyEl.hidden = false;
            countEl.textContent = '0';
            applySearch();
            return;
        }
        emptyEl.hidden = true;
        countEl.textContent = String(items.length);
        listEl.innerHTML = items.map(itemHtml).join('');
        updateAllCodes(true);
        applySearch();
    }

    // Partial: update note display in-place
    function refreshItemNote(id) {
        const item = items.find(it => it.id === id);
        if (!item) return;
        const root = listEl.querySelector(`.totp-item[data-id="${CSS.escape(id)}"]`);
        if (!root) return;

        const display = root.querySelector('[data-role="note-display"]');
        const textEl  = root.querySelector('[data-role="note-text"]');
        const input   = root.querySelector('.totp-item__note-input');

        if (item.note) {
            textEl.textContent = item.note;
            display.hidden = false;
        } else {
            textEl.textContent = '';
            display.hidden = true;
        }
        if (input) input.value = item.note || '';
    }

    // ==========================================================
    // TICKER
    // ==========================================================
    let masterTicker = null;
    const lastCounters = new Map();

    async function updateAllCodes(forceAll = false) {
        const nowSec = Date.now() / 1000;
        const counter = Math.floor(nowSec / PERIOD);
        const rem = PERIOD - (nowSec % PERIOD);

        for (const item of items) {
            const root = listEl.querySelector(`.totp-item[data-id="${CSS.escape(item.id)}"]`);
            if (!root) continue;

            const codeEl = root.querySelector('[data-role="code"]');
            const progEl = root.querySelector('[data-role="prog"]');

            const lastC = lastCounters.get(item.id);
            if (forceAll || lastC !== counter) {
                try {
                    const code = await totp(item.secret, PERIOD, DIGITS);
                    codeEl.textContent = formatCode(code);
                    codeEl.dataset.raw = code;
                    lastCounters.set(item.id, counter);
                    if (!forceAll) {
                        codeEl.classList.remove('is-pulse');
                        void codeEl.offsetWidth;
                        codeEl.classList.add('is-pulse');
                    }
                } catch (_) {
                    codeEl.textContent = '— lỗi —';
                }
            }

            progEl.style.width = (rem / PERIOD * 100) + '%';
            const warn = rem <= 5;
            progEl.classList.toggle('is-warning', warn);
            codeEl.classList.toggle('is-warning', warn);
        }
    }

    function startTicker() {
        stopTicker();
        masterTicker = setInterval(() => updateAllCodes(false), 500);
    }
    function stopTicker() {
        if (masterTicker) { clearInterval(masterTicker); masterTicker = null; }
    }

    // ==========================================================
    // ACTIONS
    // ==========================================================
    function deleteItem(id) {
        items = items.filter(it => it.id !== id);
        lastCounters.delete(id);
        saveItems();
        renderList();
        showToast('Đã xóa 2FA', 'success');
    }

    async function copyItemCode(id) {
        const root = listEl.querySelector(`.totp-item[data-id="${CSS.escape(id)}"]`);
        if (!root) return;
        const codeEl = root.querySelector('[data-role="code"]');
        const raw = codeEl?.dataset.raw;
        if (!raw) return;

        const ok = await copyToClipboard(raw);
        const btn = root.querySelector('[data-role="copy"]');
        if (btn) {
            btn.classList.add('is-copied');
            setTimeout(() => btn.classList.remove('is-copied'), 1300);
        }
        showToast(ok ? `Đã copy: ${raw}` : 'Copy thất bại', ok ? 'success' : 'error');
    }

    async function copyItemNote(id) {
        const item = items.find(it => it.id === id);
        if (!item || !item.note) return;

        const ok = await copyToClipboard(item.note);
        const root = listEl.querySelector(`.totp-item[data-id="${CSS.escape(id)}"]`);
        if (root) {
            const btn = root.querySelector('[data-role="copy-note"]');
            if (btn) {
                btn.classList.add('is-copied');
                setTimeout(() => btn.classList.remove('is-copied'), 1300);
            }
        }
        showToast(ok ? 'Đã copy note' : 'Copy thất bại', ok ? 'success' : 'error');
    }

    function toggleNoteForm(root) {
        const form = root.querySelector('[data-role="note-form"]');
        const btn  = root.querySelector('[data-role="note-toggle"]');
        const willOpen = form.hidden;
        form.hidden = !willOpen;
        btn.classList.toggle('is-open', willOpen);
        if (willOpen) {
            const inp = form.querySelector('.totp-item__note-input');
            inp.focus();
            inp.select();
        }
    }

    function saveNote(root, value) {
        const id = root.dataset.id;
        const item = items.find(it => it.id === id);
        if (!item) return;

        const trimmed = value.trim();
        item.note = trimmed;
        saveItems();
        refreshItemNote(id);
        applySearch();

        // close form
        const form = root.querySelector('[data-role="note-form"]');
        const btn  = root.querySelector('[data-role="note-toggle"]');
        form.hidden = true;
        btn.classList.remove('is-open');

        showToast(trimmed ? 'Đã lưu note' : 'Đã xóa note', 'success');
    }

    // ==========================================================
    // INIT
    // ==========================================================
    function init() {
        const form        = document.getElementById('addForm');
        const secretInput = document.getElementById('secretInput');
        const pasteBtn    = document.getElementById('pasteBtn');
        const errorBox    = document.getElementById('errorBox');
        const typePicker  = document.getElementById('typePicker');
        const notePreview     = document.getElementById('notePreview');
        const notePreviewText = document.getElementById('notePreviewText');
        const clearNoteBtn    = document.getElementById('clearNoteBtn');
        const searchInput     = document.getElementById('searchInput');
        const searchClearBtn  = document.getElementById('searchClearBtn');

        let pendingNote = '';

        function showError(m) { errorBox.textContent = m; errorBox.hidden = false; }
        function clearError() { errorBox.hidden = true; errorBox.textContent = ''; }

        function setPendingNote(note) {
            pendingNote = note || '';
            if (pendingNote) {
                notePreviewText.textContent = pendingNote;
                notePreview.hidden = false;
            } else {
                notePreview.hidden = true;
            }
        }

        function selectType(type) {
            if (!TYPES[type]) return;
            selectedType = type;
            typePicker.querySelectorAll('.totp-type').forEach(b => {
                b.classList.toggle('is-active', b.dataset.type === type);
            });
        }

        function resetSearch() {
            searchInput.value = '';
            searchQuery = '';
            searchClearBtn.hidden = true;
            applySearch();
        }

        // Search input
        searchInput.addEventListener('input', () => {
            searchQuery = searchInput.value;
            searchClearBtn.hidden = !searchQuery;
            applySearch();
        });

        searchClearBtn.addEventListener('click', () => {
            resetSearch();
            searchInput.focus();
        });

        // ESC trong search input để clear nhanh
        searchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && searchInput.value) {
                e.preventDefault();
                resetSearch();
            }
        });

        // Khi giá trị input có dấu phân cách, email, hoặc nhiều space → tự parse
        function maybeAutoParse() {
            const val = secretInput.value;
            // Trigger nếu có: |, \n, \t, ;, @ (email), hoặc 2+ space liên tiếp
            if (!/[|\n\t;@]|[ ]{2,}/.test(val)) return;
            const parsed = parseSmartInput(val);
            if (!parsed || !parsed.secret) return;
            // Chỉ apply nếu parse ra secret hợp lệ
            secretInput.value = parsed.secret;
            setPendingNote(parsed.note);
            const detected = detectType(parsed.note + ' ' + parsed.secret);
            if (detected) selectType(detected);
        }

        // Type picker
        typePicker.addEventListener('click', (e) => {
            const btn = e.target.closest('[data-type]');
            if (!btn) return;
            selectType(btn.dataset.type);
        });

        // Paste vào input → parse sau khi browser đã chèn text
        secretInput.addEventListener('paste', () => setTimeout(maybeAutoParse, 0));

        // Input event để bắt cả gõ tay có delimiter / email / nhiều space
        secretInput.addEventListener('input', () => {
            if (/[|\n\t;@]|[ ]{2,}/.test(secretInput.value)) maybeAutoParse();
        });

        // Nút × trên note preview → bỏ note
        clearNoteBtn.addEventListener('click', () => setPendingNote(''));

        // Nút Dán (lấy từ clipboard)
        pasteBtn.addEventListener('click', async () => {
            try {
                if (navigator.clipboard && navigator.clipboard.readText && window.isSecureContext) {
                    const text = await navigator.clipboard.readText();
                    secretInput.value = text.trim();
                    maybeAutoParse();
                    secretInput.focus();
                    return;
                }
            } catch (_) {}
            secretInput.focus();
        });

        // Submit
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            clearError();

            // last-chance parse phòng khi user paste mà event chưa fire
            maybeAutoParse();

            const secret = secretInput.value.trim();
            if (!secret) { showError('Hãy nhập secret 2FA.'); return; }

            let code;
            try {
                base32Decode(secret);
                code = await totp(secret, PERIOD, DIGITS);
            } catch (err) {
                showError(err.message || 'Secret không hợp lệ.');
                return;
            }

            const item = { id: genId(), type: selectedType, secret, note: pendingNote };
            items.push(item);
            saveItems();
            renderList();

            // auto-copy mã hiện tại 1 lần
            const ok = await copyToClipboard(code);
            showToast(
                ok ? `Đã thêm + copy mã: ${code}` : `Đã thêm (copy thất bại): ${code}`,
                ok ? 'success' : 'error'
            );

            const newRoot = listEl.querySelector(`.totp-item[data-id="${CSS.escape(item.id)}"]`);
            if (newRoot) {
                const btn = newRoot.querySelector('[data-role="copy"]');
                if (btn) {
                    btn.classList.add('is-copied');
                    setTimeout(() => btn.classList.remove('is-copied'), 1300);
                }
            }

            // reset form
            secretInput.value = '';
            setPendingNote('');
            resetSearch();
            secretInput.focus();
        });

        // List click delegation
        listEl.addEventListener('click', (e) => {
            const root = e.target.closest('.totp-item');
            if (!root) return;
            const id = root.dataset.id;

            if (e.target.closest('[data-role="copy-note"]'))         copyItemNote(id);
            else if (e.target.closest('[data-role="copy"]'))         copyItemCode(id);
            else if (e.target.closest('[data-role="delete"]'))       { if (confirm('Xóa 2FA này?')) deleteItem(id); }
            else if (e.target.closest('[data-role="note-toggle"]')) toggleNoteForm(root);
        });

        // List submit delegation (note form)
        listEl.addEventListener('submit', (e) => {
            const noteForm = e.target.closest('[data-role="note-form"]');
            if (!noteForm) return;
            e.preventDefault();
            const root = noteForm.closest('.totp-item');
            const input = noteForm.querySelector('.totp-item__note-input');
            saveNote(root, input.value);
        });

        // Boot
        loadItems();
        renderList();
        startTicker();
        window.addEventListener('beforeunload', stopTicker);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
