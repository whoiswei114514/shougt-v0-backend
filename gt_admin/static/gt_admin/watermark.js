// Generated from the main site's adminWatermark.ts by scripts/build-admin-watermark.mjs.
(()=>{
/** Text and screenshot provenance for management views. Never change form values. */
function installAdminWatermark(marker, actor, root = document.body) {
    if (!/^[0-9a-f]{24}$/i.test(marker))
        return () => { };
    const bits = [...marker].flatMap(hex => parseInt(hex, 16).toString(2).padStart(4, '0').split(''));
    const packet = '\u2063' + bits.map(bit => bit === '1' ? '\u200c' : '\u200b').join('') + '\u2063';
    const encoded = /\u2063[\u200b\u200c]{96}\u2063/g;
    const excluded = 'script,style,noscript,textarea,input,select,option,canvas,svg,[contenteditable]:not([contenteditable="false"]),[data-shou-watermark-layer],[data-shou-text-mark]';
    const marks = new Map();
    const layers = ['visible', 'covert', 'frequency'].map(name => {
        const canvas = document.createElement('canvas');
        canvas.dataset.shouWatermarkLayer = name;
        canvas.setAttribute('aria-hidden', 'true');
        canvas.style.cssText = 'position:fixed;inset:0;width:100vw;height:100vh;pointer-events:none;z-index:2147483000;user-select:none';
        root.append(canvas);
        return canvas;
    });
    let stopped = false, pending = 0, resizeTimer;
    function stamp() {
        pending = 0;
        if (stopped)
            return;
        for (const [text, span] of marks) {
            if (!text.isConnected || !text.data.trim() || text.parentNode !== span.parentNode || text.nextSibling !== span) {
                span.remove();
                marks.delete(text);
            }
        }
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
        const found = [];
        let node;
        while ((node = walker.nextNode())) {
            const text = node, parent = text.parentElement;
            if (text.data.trim() && parent?.namespaceURI === 'http://www.w3.org/1999/xhtml' && !parent.closest(excluded))
                found.push(text);
        }
        for (const text of found) {
            if (marks.has(text))
                continue;
            const mark = document.createElement('span');
            mark.dataset.shouTextMark = '';
            mark.setAttribute('aria-hidden', 'true');
            mark.style.cssText = 'display:inline;font-size:0;line-height:0;pointer-events:none';
            mark.textContent = packet;
            text.after(mark);
            marks.set(text, mark);
        }
    }
    const observer = new MutationObserver(records => {
        if (records.some(record => record.type === 'attributes'))
            paint();
        if (!pending)
            pending = requestAnimationFrame(stamp);
    });
    observer.observe(root, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ['arco-theme', 'data-theme'] });
    function paint() {
        const dark = document.body.getAttribute('arco-theme') === 'dark' || getComputedStyle(root).colorScheme === 'dark';
        const ink = dark ? '218,230,224' : '45,75,95';
        for (const canvas of layers) {
            canvas.width = innerWidth;
            canvas.height = innerHeight;
        }
        const visible = layers[0].getContext('2d');
        visible.fillStyle = `rgba(${ink},.10)`;
        visible.font = '13px "Microsoft YaHei",sans-serif';
        for (let y = 65; y < innerHeight + 100; y += 185)
            for (let x = -60; x < innerWidth; x += 320) {
                visible.save();
                visible.translate(x, y);
                visible.rotate(-Math.PI / 12);
                visible.fillText(actor, 0, 0);
                visible.fillText(marker.slice(0, 12), 0, 21);
                visible.restore();
            }
        const hidden = layers[1].getContext('2d');
        for (let oy = 0; oy < innerHeight; oy += 160)
            for (let ox = 0; ox < innerWidth; ox += 192) {
                for (let bit = 0; bit < bits.length; bit++) {
                    hidden.fillStyle = `rgba(${ink},${bits[bit] === '1' ? '.035' : '.012'})`;
                    hidden.fillRect(ox + 12 + bit % 16 * 10, oy + 16 + Math.floor(bit / 16) * 16, 3, 3);
                }
            }
        const tile = document.createElement('canvas');
        tile.width = tile.height = 128;
        const tc = tile.getContext('2d'), data = tc.createImageData(128, 128);
        for (let y = 0; y < 128; y++)
            for (let x = 0; x < 128; x++) {
                let signal = 0;
                for (let i = 0; i < bits.length; i++)
                    signal += (bits[i] === '1' ? 1 : -1) * Math.cos(2 * Math.PI * ((3 + i % 12) * x + (3 + Math.floor(i / 12)) * y) / 128);
                const offset = (y * 128 + x) * 4;
                data.data[offset] = data.data[offset + 1] = data.data[offset + 2] = Math.round(128 + 3 * signal);
                data.data[offset + 3] = 9;
            }
        tc.putImageData(data, 0, 0);
        const frequency = layers[2].getContext('2d');
        frequency.fillStyle = frequency.createPattern(tile, 'repeat');
        frequency.fillRect(0, 0, innerWidth, innerHeight);
    }
    function copy(event) {
        if (event.target instanceof Element && event.target.closest('input,textarea,[contenteditable]:not([contenteditable="false"])'))
            return;
        const selection = getSelection();
        const plain = selection?.toString().replace(encoded, '');
        if (!plain || !event.clipboardData)
            return;
        const chunks = Array.from(plain).reduce((result, char, i) => {
            if (i % 64 === 0)
                result.push('');
            result[result.length - 1] += char;
            return result;
        }, []);
        event.clipboardData.setData('text/plain', chunks.map(chunk => chunk + packet).join(''));
        const wrapper = document.createElement('div');
        for (let i = 0; selection && i < selection.rangeCount; i++)
            wrapper.append(selection.getRangeAt(i).cloneContents());
        wrapper.append(packet);
        event.clipboardData.setData('text/html', wrapper.innerHTML);
        event.preventDefault();
    }
    const resized = () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(paint, 140); };
    root.addEventListener('copy', copy, true);
    window.addEventListener('resize', resized);
    stamp();
    paint();
    return () => {
        stopped = true;
        observer.disconnect();
        cancelAnimationFrame(pending);
        clearTimeout(resizeTimer);
        root.removeEventListener('copy', copy, true);
        window.removeEventListener('resize', resized);
        for (const span of marks.values())
            span.remove();
        for (const canvas of layers)
            canvas.remove();
        marks.clear();
    };
}

const host=document.getElementById('shou-watermark');if(host)installAdminWatermark(host.dataset.marker || '',host.dataset.actor || '');
})();
