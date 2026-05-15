/**
 * TOTP Vault — TOTP generator (v3 minimal)
 * RFC 6238 (HMAC-SHA1). Fallback SHA-1 thuần JS khi site không phải secure context.
 * Không lưu trữ. Không tracking. Không gửi secret về server.
 */
(function () {
    'use strict';

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

    // ==========================================================
    // UI
    // ==========================================================
    function initCard(card) {
        const digits = Math.max(6, Math.min(8, parseInt(card.dataset.digits, 10) || 6));
        const period = Math.max(15, Math.min(120, parseInt(card.dataset.period, 10) || 30));

        const form      = card.querySelector('.totp-card__form');
        const input     = card.querySelector('.totp-field__input');
        const toggleVis = card.querySelector('[data-toggle="visibility"]');
        const pasteBtn  = card.querySelector('[data-toggle="paste"]');
        const resultBox = card.querySelector('.totp-card__result');
        const digitsEl  = card.querySelector('.totp-code__digits');
        const copyBtn   = card.querySelector('[data-toggle="copy"]');
        const progFill  = card.querySelector('.totp-progress__fill');
        const progTime  = card.querySelector('.totp-progress__time');
        const errorBox  = card.querySelector('.totp-card__error');

        let currentSecret = null;
        let ticker = null;
        let debounceTimer = null;

        function showError(m) { errorBox.textContent = m; errorBox.hidden = false; }
        function clearError() { errorBox.hidden = true; errorBox.textContent = ''; }
        function formatCode(c) {
            if (c.length === 6) return c.slice(0,3) + '   ' + c.slice(3);
            if (c.length === 8) return c.slice(0,4) + '   ' + c.slice(4);
            return c;
        }

        async function generate(s) {
            try {
                const code = await totp(s, period, digits);
                digitsEl.textContent = formatCode(code);
                digitsEl.dataset.raw = code;
                digitsEl.classList.remove('is-pulse');
                void digitsEl.offsetWidth;
                digitsEl.classList.add('is-pulse');
            } catch (err) {
                stopTick(); showError(err.message); resultBox.hidden = true;
            }
        }

        function updateProgress() {
            const now = Date.now()/1000;
            const rem = period - (now % period);
            progFill.style.width = (rem/period*100) + '%';
            progTime.textContent = Math.ceil(rem) + 's';
            progFill.classList.toggle('is-warning', rem <= 5);
        }
        function startTick() {
            stopTick(); updateProgress();
            let last = Math.floor(Date.now()/1000/period);
            ticker = setInterval(() => {
                updateProgress();
                const nowC = Math.floor(Date.now()/1000/period);
                if (nowC !== last) { last = nowC; if (currentSecret) generate(currentSecret); }
            }, 500);
        }
        function stopTick() { if (ticker) { clearInterval(ticker); ticker = null; } }

        async function useSecret(s) {
            clearError();
            if (!s) {
                currentSecret = null;
                resultBox.hidden = true;
                stopTick();
                return;
            }
            try { base32Decode(s); }
            catch (err) {
                currentSecret = null;
                resultBox.hidden = true;
                stopTick();
                if (s.replace(/\s+/g,'').length >= 6) showError(err.message);
                return;
            }
            currentSecret = s;
            resultBox.hidden = false;
            await generate(s);
            startTick();
        }

        input.addEventListener('input', () => {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => useSecret(input.value.trim()), 150);
        });

        form.addEventListener('submit', (e) => {
            e.preventDefault();
            clearTimeout(debounceTimer);
            useSecret(input.value.trim());
        });

        toggleVis.addEventListener('click', () => {
            input.type = input.type === 'password' ? 'text' : 'password';
            toggleVis.classList.toggle('is-on', input.type === 'text');
        });

        // Paste button (tiện trên mobile)
        pasteBtn.addEventListener('click', async () => {
            try {
                if (navigator.clipboard && navigator.clipboard.readText && window.isSecureContext) {
                    const text = await navigator.clipboard.readText();
                    input.value = text.trim();
                    input.dispatchEvent(new Event('input'));
                    return;
                }
            } catch (_) {}
            // Fallback: focus input để user có thể paste thủ công
            input.focus();
        });

        copyBtn.addEventListener('click', async () => {
            const raw = digitsEl.dataset.raw; if (!raw) return;
            let ok = false;
            try {
                if (navigator.clipboard && navigator.clipboard.writeText && window.isSecureContext) {
                    await navigator.clipboard.writeText(raw);
                    ok = true;
                }
            } catch (_) {}
            if (!ok) {
                const ta = document.createElement('textarea');
                ta.value = raw;
                ta.setAttribute('readonly', '');
                ta.style.position = 'fixed';
                ta.style.opacity = '0';
                document.body.appendChild(ta);
                ta.select();
                ta.setSelectionRange(0, raw.length);
                try { document.execCommand('copy'); } catch (_) {}
                document.body.removeChild(ta);
            }
            copyBtn.classList.add('is-copied');
            setTimeout(() => copyBtn.classList.remove('is-copied'), 1300);
        });

        window.addEventListener('beforeunload', stopTick);
    }

    function boot() {
        document.querySelectorAll('.totp-card').forEach(initCard);
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot);
    } else {
        boot();
    }
})();
