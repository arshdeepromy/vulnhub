/* Detail probe: every element wider than the viewport, with its ancestry. */
const fs = require('fs');
const { chromium } = require('playwright');
const url = process.argv[2] || 'http://localhost:8093/';
const width = parseInt(process.argv[3] || '390', 10);

(async () => {
  const b = await chromium.launch();
  const c = await b.newContext({ viewport: { width, height: 900 } });
  const p = await c.newPage();
  const pass = fs.readFileSync('/home/romy/vulnhub/.admin_pass', 'utf8').trim();
  await p.goto('http://localhost:8093/wp-login.php', { waitUntil: 'domcontentloaded' });
  await p.fill('#user_login', (process.env.VH_ADMIN_USER || 'admin'));
  await p.fill('#user_pass', pass);
  await Promise.all([p.waitForNavigation({ waitUntil: 'domcontentloaded' }).catch(() => {}), p.click('#wp-submit')]);
  await p.goto(url, { waitUntil: 'networkidle' });

  const out = await p.evaluate((vw) => {
    const rows = [];
    const path = (el) => {
      const parts = [];
      let n = el;
      for (let i = 0; n && n !== document.body && i < 4; i++) {
        const cls = (n.className && n.className.toString ? n.className.toString().trim().split(/\s+/)[0] : '');
        parts.unshift(n.tagName.toLowerCase() + (cls ? '.' + cls : ''));
        n = n.parentElement;
      }
      return parts.join(' > ');
    };
    document.querySelectorAll('body *').forEach((el) => {
      const r = el.getBoundingClientRect();
      if (!r.width || !r.height) return;
      const right = r.left + r.width + window.scrollX;
      if (right <= vw + 2) return;
      const cs = getComputedStyle(el);
      if (cs.position === 'fixed') return;
      let anc = el.parentElement, scroller = null;
      while (anc && anc !== document.body) {
        const s = getComputedStyle(anc);
        if (s.overflowX === 'auto' || s.overflowX === 'scroll') { scroller = path(anc); break; }
        anc = anc.parentElement;
      }
      rows.push({ path: path(el), right: Math.round(right), w: Math.round(r.width), scroller });
    });
    return rows;
  }, width);

  const seen = new Set();
  out.forEach((r) => {
    const k = r.path + r.right;
    if (seen.has(k)) return;
    seen.add(k);
    console.log(`${String(r.right).padStart(5)}px w=${String(r.w).padStart(5)}  ${r.scroller ? '[in ' + r.scroller + '] ' : ''}${r.path}`);
  });
  console.log(`\n${out.length} elements past ${width}px`);
  await b.close();
})();
