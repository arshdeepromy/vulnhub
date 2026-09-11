/*
 * Static-eye design audit: walks every VulnHub screen and reports the visual
 * defects a human would notice but an HTTP check never will -- controls with
 * no readable label, text the same colour as what it sits on, text clipped by
 * its own box, and tap targets too small to hit.
 *
 *   node dev/designaudit.js [--only=substring] [--theme=dark]
 */
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const BASE = 'http://localhost:8093';
const ROOT = '/srv/vulnhub';

const WIDTHS = [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'phone', width: 390, height: 844 },
];

const PAGES = [
  ['dashboard', '/'],
  ['vulnerabilities', '/vulnerabilities/'],
  ['vulns-critical', '/vulnerabilities/?severity=critical'],
  ['vulns-search', '/vulnerabilities/?search=OpenSSL'],
  ['vulns-overdue', '/vulnerabilities/?overdue=1'],
  ['assets', '/assets/'],
  ['assets-needs-user', '/assets/?needs_user=1'],
  ['tickets', '/tickets/'],
  ['exceptions', '/exceptions/'],
  ['admin-overview', '/portal-admin/'],
  ['admin-integrations', '/portal-admin/?section=integrations'],
  ['admin-imports', '/portal-admin/?section=imports'],
  ['admin-rules', '/portal-admin/?section=rules'],
  ['admin-teams', '/portal-admin/?section=teams'],
  ['admin-activity', '/portal-admin/?section=activity'],
  ['admin-audit', '/portal-admin/?section=audit'],
  ['admin-settings', '/portal-admin/?section=settings'],
  ['admin-appearance', '/portal-admin/?section=appearance'],
  ['el-overview', '/vulnhub-overview/'],
  ['el-estate', '/vulnhub-estate/'],
];

const only = (process.argv.find((a) => a.startsWith('--only=')) || '').slice(7);
const theme = (process.argv.find((a) => a.startsWith('--theme=')) || '').slice(8);

const AUDIT = () => {
  const out = [];
  const seen = new Set();
  const add = (kind, el, detail) => {
    const sel = el.tagName.toLowerCase() +
      (el.id ? '#' + el.id : '') +
      (el.className && el.className.toString ? '.' + el.className.toString().trim().split(/\s+/).join('.') : '');
    const key = kind + '|' + sel + '|' + detail;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ kind, sel: sel.slice(0, 120), detail: String(detail).slice(0, 160) });
  };

  const parse = (c) => {
    const m = c.match(/rgba?\(([^)]+)\)/);
    if (!m) return null;
    const p = m[1].split(',').map((x) => parseFloat(x));
    return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 };
  };
  const over = (fg, bg) => {
    const a = fg.a;
    return { r: fg.r * a + bg.r * (1 - a), g: fg.g * a + bg.g * (1 - a), b: fg.b * a + bg.b * (1 - a), a: 1 };
  };
  const lum = (c) => {
    const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); };
    return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b);
  };
  const ratio = (a, b) => { const l1 = lum(a), l2 = lum(b); const hi = Math.max(l1, l2), lo = Math.min(l1, l2); return (hi + 0.05) / (lo + 0.05); };
  const bgOf = (el) => {
    let base = { r: 255, g: 255, b: 255, a: 1 };
    const stack = [];
    let n = el;
    while (n && n.nodeType === 1) {
      const c = parse(getComputedStyle(n).backgroundColor);
      if (c && c.a > 0) { stack.push(c); if (c.a === 1) break; }
      n = n.parentElement;
    }
    for (let i = stack.length - 1; i >= 0; i--) base = over(stack[i], base);
    return base;
  };

  /*
   * A closed <details> still gives its children a layout box in Chromium (the
   * slot is content-visibility: hidden, not display: none), and a visually
   * hidden label is a 1px clip on purpose. Both looked like defects on the
   * first pass -- every account menu and chart export menu in the app -- so
   * they are excluded rather than reported forty times over.
   */
  const inClosedDetails = (el) => {
    for (let n = el.parentElement; n; n = n.parentElement) {
      if (n.tagName === 'DETAILS' && !n.open && !el.closest('summary')) return true;
    }
    return false;
  };
  const hiddenForSighted = (el) =>
    el.closest('.screen-reader-text, .vh-skip') !== null ||
    (el.clientWidth <= 1 && el.clientHeight <= 1);

  const vis = (el) => {
    const s = getComputedStyle(el);
    if (s.display === 'none' || s.visibility === 'hidden' || parseFloat(s.opacity) === 0) return false;
    if (inClosedDetails(el) || hiddenForSighted(el)) return false;
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  };

  document.querySelectorAll('body *').forEach((el) => {
    if (el.closest('#wpadminbar')) return;
    if (!vis(el)) return;
    const s = getComputedStyle(el);
    const r = el.getBoundingClientRect();
    const tag = el.tagName.toLowerCase();
    const interactive = tag === 'button' || tag === 'a' || tag === 'summary' ||
      el.getAttribute('role') === 'button' || (tag === 'input' && /button|submit/.test(el.type || ''));

    /* 1. control with nothing readable inside it. */
    if (interactive) {
      const label = (el.innerText || '').trim() || el.getAttribute('aria-label') || el.getAttribute('title') ||
        (el.tagName === 'INPUT' ? el.value : '');
      const glyph = el.querySelector('svg, img, .dashicons, i[class]');
      if (!label && !glyph && !el.querySelector('.screen-reader-text')) {
        add('empty-control', el, `${Math.round(r.width)}x${Math.round(r.height)} no text, no icon`);
      }
    }

    /* 2. text the same colour as the surface under it. */
    const ownText = [...el.childNodes].some((n) => n.nodeType === 3 && n.textContent.trim().length > 1);
    if (ownText) {
      const fg0 = parse(s.color);
      if (fg0) {
        const bg = bgOf(el);
        const fg = over(fg0, bg);
        const cr = ratio(fg, bg);
        const size = parseFloat(s.fontSize);
        const bold = parseInt(s.fontWeight, 10) >= 700;
        const large = size >= 24 || (size >= 18.66 && bold);
        const need = large ? 3 : 4.5;
        if (cr < 1.35) add('invisible-text', el, `contrast ${cr.toFixed(2)}:1 -- text is the same colour as its background`);
        else if (cr < need) add('low-contrast', el, `contrast ${cr.toFixed(2)}:1, needs ${need}:1 at ${size}px`);
      }
    }

    /* 3. text clipped by its own box. */
    if (s.overflow === 'hidden' || s.overflowX === 'hidden' || s.textOverflow === 'ellipsis') {
      if (el.scrollWidth > el.clientWidth + 2 && el.clientWidth > 0 && (el.innerText || '').trim() && el.children.length === 0) {
        add('clipped-text', el, `content ${el.scrollWidth}px in a ${el.clientWidth}px box`);
      }
    }

    /*
     * 4. tap target too small to hit reliably. WCAG 2.5.8 exempts a link that
     *    sits inline in a run of text, which is most of the links in a table
     *    cell or a list row, so only controls that are laid out as their own
     *    box are measured.
     */
    if (interactive && s.display !== 'inline') {
      if ((r.width < 24 || r.height < 24) && r.width > 0 && s.position !== 'absolute') {
        add('small-target', el, `${Math.round(r.width)}x${Math.round(r.height)} (min 24x24)`);
      }
    }

    /* 5. child sticking out of a parent that is not a scroller. */
    const p = el.parentElement;
    if (p && p !== document.body) {
      const ps = getComputedStyle(p);
      const pr = p.getBoundingClientRect();
      if (ps.overflowX === 'visible' && ps.overflow === 'visible' && ps.position !== 'relative' &&
          s.position === 'static' && pr.width > 0 && r.right > pr.right + 3) {
        add('escapes-parent', el, `right edge ${Math.round(r.right - pr.right)}px past its parent`);
      }
    }
  });

  return out;
};

(async () => {
  const browser = await chromium.launch();
  const all = [];
  for (const vp of WIDTHS) {
    const ctx = await browser.newContext({ viewport: { width: vp.width, height: vp.height } });
    const page = await ctx.newPage();
    const pass = fs.readFileSync(path.join(ROOT, '.admin_pass'), 'utf8').trim();
    await page.goto(`${BASE}/wp-login.php`, { waitUntil: 'domcontentloaded' });
    await page.fill('#user_login', 'romy');
    await page.fill('#user_pass', pass);
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'domcontentloaded' }).catch(() => {}),
      page.click('#wp-submit'),
    ]);

    for (const [name, url] of PAGES) {
      if (only && !name.includes(only)) continue;
      try {
        await page.goto(BASE + url, { waitUntil: 'networkidle', timeout: 60000 });
      } catch (e) { console.log(`${name} [${vp.name}] NAV FAIL`); continue; }
      if (theme) {
        await page.evaluate((t) => document.documentElement.setAttribute('data-theme', t), theme);
        await page.waitForTimeout(150);
      }
      const found = await page.evaluate(AUDIT);
      all.push({ page: name, viewport: vp.name, found });
      console.log(`${(name + ' [' + vp.name + (theme ? '/' + theme : '') + ']').padEnd(36)} ${found.length ? found.length + ' issue(s)' : 'clean'}`);
      found.forEach((f) => console.log(`    ${f.kind.padEnd(15)} ${f.sel}\n        ${f.detail}`));
    }
    await ctx.close();
  }
  await browser.close();
  fs.writeFileSync(path.join(ROOT, 'dev/shots', `design-audit${theme ? '-' + theme : ''}.json`), JSON.stringify(all, null, 2));
  const n = all.reduce((a, b) => a + b.found.length, 0);
  console.log(`\n${all.length} screens, ${n} issue instance(s).`);
})();
