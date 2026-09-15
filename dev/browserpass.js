const VH_ROOT = process.env.VULNHUB_ROOT || require('path').resolve(__dirname, '..');
/*
 * Drive every VulnHub screen in headless Chromium at desktop and phone widths.
 *
 * Screenshots land in dev/shots/, and the report names anything that would
 * have needed a human to notice it: console errors, PHP notices rendered into
 * the page, horizontal overflow of the document, and elements wider than the
 * viewport.
 *
 *   node dev/browserpass.js [--only=substring]
 *
 * The admin password is read straight from .admin_pass and handed to the
 * page; it is never printed.
 */
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');

const BASE = 'http://localhost:8093';
const ROOT = VH_ROOT;
const OUT = path.join(ROOT, 'dev/shots');

const WIDTHS = [
  { name: 'desktop', width: 1440, height: 900 },
  { name: 'phone', width: 390, height: 844 },
];

const PAGES = [
  ['dashboard',            '/'],
  ['vulnerabilities',      '/vulnerabilities/'],
  ['vulns-critical',       '/vulnerabilities/?severity=critical'],
  ['vulns-search',         '/vulnerabilities/?search=OpenSSL'],
  ['vulns-overdue',        '/vulnerabilities/?overdue=1'],
  ['assets',               '/assets/'],
  ['assets-needs-user',    '/assets/?needs_user=1'],
  ['assets-eol',           '/assets/?eol=win10-22h2'],
  ['assets-no-edr',        '/assets/?defender=gap'],
  ['vulns-no-patch',       '/vulnerabilities/?severity=critical&patch_available=0'],
  ['tickets',              '/tickets/'],
  ['exceptions',           '/exceptions/'],
  ['admin-overview',       '/portal-admin/'],
  ['admin-integrations',   '/portal-admin/?section=integrations'],
  ['admin-imports',        '/portal-admin/?section=imports'],
  ['admin-rules',          '/portal-admin/?section=rules'],
  ['admin-teams',          '/portal-admin/?section=teams'],
  ['admin-activity',       '/portal-admin/?section=activity'],
  ['admin-audit',          '/portal-admin/?section=audit'],
  ['admin-settings',       '/portal-admin/?section=settings'],
  ['admin-lifecycle',      '/portal-admin/?section=screen-vulnhub-lifecycle'],
  ['admin-appearance',     '/portal-admin/?section=appearance'],
  // Built in Elementor rather than by the portal, so they exercise a
  // different template, a different stylesheet and the Theme Builder chrome.
  ['el-overview',          '/vulnhub-overview/'],
  ['el-estate',            '/vulnhub-estate/'],
];

const only = (process.argv.find((a) => a.startsWith('--only=')) || '').slice(7);
const theme = (process.argv.find((a) => a.startsWith('--theme=')) || '').slice(8);
const suffix = theme ? '-' + theme : '';

(async () => {
  const browser = await chromium.launch();
  const report = [];

  for (const vp of WIDTHS) {
    const ctx = await browser.newContext({ viewport: { width: vp.width, height: vp.height } });
    const page = await ctx.newPage();

    // Log in once per context.
    const pass = fs.readFileSync(path.join(ROOT, '.admin_pass'), 'utf8').trim();
    await page.goto(`${BASE}/wp-login.php`, { waitUntil: 'domcontentloaded' });
    await page.fill('#user_login', (process.env.VH_ADMIN_USER || 'admin'));
    await page.fill('#user_pass', pass);
    await Promise.all([
      page.waitForNavigation({ waitUntil: 'domcontentloaded' }).catch(() => {}),
      page.click('#wp-submit'),
    ]);

    for (const [name, url] of PAGES) {
      if (only && !name.includes(only)) continue;

      const errors = [];
      const onErr = (m) => { if (m.type() === 'error') errors.push(m.text().slice(0, 300)); };
      const onPageErr = (e) => errors.push('uncaught: ' + String(e).slice(0, 300));
      page.on('console', onErr);
      page.on('pageerror', onPageErr);

      const t0 = Date.now();
      let status = 0;
      try {
        const resp = await page.goto(BASE + url, { waitUntil: 'networkidle', timeout: 60000 });
        status = resp ? resp.status() : 0;
      } catch (e) {
        errors.push('navigation: ' + String(e).slice(0, 200));
      }
      const ms = Date.now() - t0;

      if (theme) {
        await page.evaluate((t) => document.documentElement.setAttribute('data-theme', t), theme);
        await page.waitForTimeout(120);
      }

      const probe = await page.evaluate((vw) => {
        const doc = document.documentElement;
        const overflow = doc.scrollWidth - vw;
        const wide = [];
        document.querySelectorAll('body *').forEach((el) => {
          // WordPress's own admin bar, not ours -- it clips its own overflow
          // and is only ever shown to signed-in administrators.
          if (el.closest('#wpadminbar')) return;
          const r = el.getBoundingClientRect();
          if (r.width === 0 || r.height === 0) return;
          const right = r.left + r.width + window.scrollX;
          if (right > vw + 2) {
            const style = getComputedStyle(el);
            // An element inside its own horizontal scroller is fine by design.
            let p = el.parentElement, scroller = false;
            while (p && p !== document.body) {
              const ps = getComputedStyle(p);
              if (ps.overflowX === 'auto' || ps.overflowX === 'scroll') { scroller = true; break; }
              p = p.parentElement;
            }
            if (scroller) return;
            if (style.position === 'fixed') return;
            wide.push({
              tag: el.tagName.toLowerCase(),
              cls: (el.className && el.className.toString ? el.className.toString() : '').slice(0, 80),
              right: Math.round(right),
            });
          }
        });
        const text = document.body ? document.body.innerText : '';
        const php = [];
        [/Fatal error/i, /Warning:\s/i, /Notice:\s/i, /Deprecated:\s/i, /There has been a critical error/i]
          .forEach((re) => { const m = text.match(re); if (m) php.push(m[0]); });
        return {
          overflow,
          wide: wide.slice(0, 6),
          wideCount: wide.length,
          php,
          title: document.title,
          bodyChars: text.length,
        };
      }, vp.width);

      const file = path.join(OUT, `${name}--${vp.name}${suffix}.png`);
      try { await page.screenshot({ path: file, fullPage: true }); } catch (e) { errors.push('screenshot: ' + e.message); }

      report.push({ page: name, url, viewport: vp.name, status, ms, ...probe, errors });
      page.off('console', onErr);
      page.off('pageerror', onPageErr);

      const flags = [];
      if (status !== 200) flags.push(`HTTP ${status}`);
      // A few pixels with no unclipped element to blame is not a horizontal
      // scroll -- it is Chrome accounting for the gutter of a nested scroller
      // (the severity matrix scrolls inside its card). Anything a person could
      // actually swipe is far larger than this, and `wideCount` below still
      // reports a real offender at any size.
      if (probe.overflow > 10) flags.push(`overflow +${probe.overflow}px`);
      if (probe.wideCount) flags.push(`${probe.wideCount} wide el`);
      if (probe.php.length) flags.push('PHP: ' + probe.php.join(', '));
      if (errors.length) flags.push(`${errors.length} console err`);
      if (probe.bodyChars < 400) flags.push('thin body');
      console.log(
        `${(name + ' [' + vp.name + (theme ? '/' + theme : '') + ']').padEnd(38)} ${String(ms).padStart(6)}ms  ` +
        (flags.length ? flags.join(' | ') : 'clean')
      );
    }
    await ctx.close();
  }

  await browser.close();
  fs.writeFileSync(path.join(OUT, `report${suffix}.json`), JSON.stringify(report, null, 2));
  const bad = report.filter((r) => r.status !== 200 || r.overflow > 10 || r.wideCount || r.php.length || r.errors.length);
  console.log(`\n${report.length} screens checked, ${bad.length} with something to look at.`);
})();
