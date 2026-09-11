/*
 * The export control, end to end.
 *
 * Three bugs live here and all three were invisible to a status-code check:
 *
 *  1. A filter the form has no control for (product, arrived at from the
 *     exposure-by-product widget) was dropped by Apply, so narrowing libcurl
 *     to servers threw the libcurl half away.
 *  2. The findings export did not read that filter back, so the CSV from a
 *     filtered list was the whole estate.
 *  3. Assets are versioned by mtime. Cloudflare fronts the portal with
 *     max-age=14400, so a static plugin version meant CSS edits were
 *     invisible for four hours -- fresh markup, four-hour-old stylesheet.
 *     That is what makes the popover a popover rather than raw fieldsets.
 */
const fs = require('fs');
const { chromium } = require('playwright');
const BASE = 'http://localhost:8093';
let pass = 0, fail = 0;
const ok = (n, d) => { pass++; console.log(`ok    ${n}${d ? '  — ' + d : ''}`); };
const bad = (n, d) => { fail++; console.log(`FAIL  ${n}${d ? '  — ' + d : ''}`); };

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  const errs = [];
  page.on('pageerror', e => errs.push(String(e).slice(0, 140)));
  page.on('console', m => { if (m.type() === 'error') errs.push(m.text().slice(0, 140)); });

  const pw = fs.readFileSync('/srv/vulnhub/.admin_pass', 'utf8').trim();
  await page.goto(`${BASE}/sign-in/`, { waitUntil: 'domcontentloaded' });
  await page.fill('input[name="log"], #user_login, input[name="username"]', (process.env.VH_ADMIN_USER || 'admin'));
  await page.fill('input[type="password"]', pw);
  await page.click('button[type="submit"], input[type="submit"]', { noWaitAfter: true });
  await page.waitForURL(u => !String(u).includes('sign-in'), { timeout: 60000 });
  await page.waitForLoadState('networkidle').catch(()=>{});

  /* ---- 1. cache-busting version on the CSS ---- */
  const hrefs = await page.evaluate(() => [...document.querySelectorAll('link[rel=stylesheet]')].map(l => l.href).filter(h => /app-redesign|app\.css/.test(h)));
  const versioned = hrefs.filter(h => /ver=[\d.]+\.\d{9,}/.test(h));
  (versioned.length === hrefs.length && hrefs.length >= 2)
    ? ok('portal CSS is versioned by mtime', versioned.map(h => h.split('?')[1]).join(' '))
    : bad('portal CSS is versioned by mtime', hrefs.join(' | '));

  /* ---- 2. the product filter survives Apply ---- */
  await page.goto(`${BASE}/vulnerabilities/?product=libcurl`, { waitUntil: 'networkidle' });
  const before = await page.evaluate(() => document.querySelector('.vh-page-head .vh-sub, .vh-sub').innerText.replace(/\s+/g,' ').trim());
  const banner = await page.evaluate(() => !!document.body.innerText.match(/attributed to\s+libcurl/i));
  banner ? ok('libcurl banner shown on arrival', before) : bad('libcurl banner shown on arrival');

  const hidden = await page.evaluate(() => [...document.querySelectorAll('form.vh-filters input[type=hidden]')].map(i => i.name));
  hidden.includes('product') ? ok('filter form carries product as a hidden field', hidden.join(',')) : bad('filter form carries product', hidden.join(','));

  await page.selectOption('form.vh-filters select[name="asset_type"]', 'server');
  await Promise.all([ page.waitForNavigation({ waitUntil: 'networkidle' }), page.click('form.vh-filters button:has-text("Apply")') ]);
  const url = page.url();
  const stillLibcurl = await page.evaluate(() => !!document.body.innerText.match(/attributed to\s+libcurl/i));
  (url.includes('product=libcurl') && url.includes('asset_type=server') && stillLibcurl)
    ? ok('libcurl survives filtering to servers', url.split('?')[1])
    : bad('libcurl survives filtering to servers', url);

  const after = await page.evaluate(() => document.querySelector('.vh-page-head .vh-sub, .vh-sub').innerText.replace(/\s+/g,' ').trim());
  console.log(`      before: ${before}\n      after : ${after}`);

  /* ---- 3. the export from that filtered list holds only those rows ---- */
  const res = await page.evaluate(async () => {
    const f = document.querySelector('form.vh-export__panel');
    if (!f) return { err: 'no export form' };
    const q = new URLSearchParams();
    for (const el of f.elements) {
      if (!el.name) continue;
      if ((el.type === 'checkbox' || el.type === 'radio') && !el.checked) continue;
      if (el.type === 'submit' || el.type === 'button') continue;
      q.append(el.name, el.value);
    }
    const r = await fetch(f.getAttribute('action') + '?' + q.toString(), { credentials: 'same-origin' });
    const t = await r.text();
    const lines = t.trim().split('\n');
    const shown = document.body.innerText.replace(/,/g,'').match(/([0-9]+)\s+findings? match/);
    return { carried: [...f.querySelectorAll('input[type=hidden]')].map(i => i.name).join(','),
             rows: lines.length - 1, listed: shown ? parseInt(shown[1],10) : -1, head: lines[0].slice(0,70) };
  });
  if (res.err) bad('export from the filtered list', res.err);
  else {
    res.carried.includes('product_slug') ? ok('export carries product_slug', res.carried) : bad('export carries product_slug', res.carried);
    (res.rows === res.listed) ? ok('export row count matches the filtered list', `${res.rows} rows`)
                              : bad('export row count matches the filtered list', `csv ${res.rows}, list ${res.listed}`);
  }

  /* ---- 4. the popover animates, and dismisses ---- */
  await page.click('.vh-export > summary');
  const anim = await page.evaluate(() => {
    const p = document.querySelector('.vh-export[open] > .vh-export__panel');
    if (!p) return null;
    const cs = getComputedStyle(p);
    return { name: cs.animationName, dur: cs.animationDuration, origin: cs.transformOrigin, pos: cs.position, running: p.getAnimations().length };
  });
  (anim && anim.name === 'vhExportIn' && anim.pos === 'absolute')
    ? ok('panel floats and animates in', `${anim.name} ${anim.dur} origin ${anim.origin}`)
    : bad('panel floats and animates in', JSON.stringify(anim));

  await page.waitForTimeout(300);
  const overlaps = await page.evaluate(() => {
    // the panel must overlay, not push the page down
    const d = document.querySelector('.vh-export[open]');
    const p = d.querySelector('.vh-export__panel');
    const next = d.closest('.vh-page-head').nextElementSibling;
    return { panelBottom: Math.round(p.getBoundingClientRect().bottom), nextTop: Math.round(next.getBoundingClientRect().top) };
  });
  (overlaps.panelBottom > overlaps.nextTop) ? ok('panel overlays the page, does not push it', JSON.stringify(overlaps))
                                            : bad('panel overlays the page', JSON.stringify(overlaps));

  await page.keyboard.press('Escape');
  await page.waitForTimeout(300);
  const closedByEsc = await page.evaluate(() => !document.querySelector('.vh-export[open]'));
  closedByEsc ? ok('Escape closes the panel') : bad('Escape closes the panel');

  await page.click('.vh-export > summary');
  await page.waitForTimeout(250);
  await page.click('h1');
  await page.waitForTimeout(300);
  const closedByOutside = await page.evaluate(() => !document.querySelector('.vh-export[open]'));
  closedByOutside ? ok('clicking away closes the panel') : bad('clicking away closes the panel');

  await page.click('.vh-export > summary');
  await page.waitForTimeout(250);
  await page.click('.vh-export > summary');
  await page.waitForTimeout(350);
  const closedByToggle = await page.evaluate(() => !document.querySelector('.vh-export[open], .vh-export.is-closing'));
  closedByToggle ? ok('clicking the button again closes it (and clears is-closing)') : bad('clicking the button again closes it');

  /* ---- 5. still reachable and downloadable after all that ---- */
  await page.click('.vh-export > summary');
  await page.waitForTimeout(250);
  // Arm the listener, then click. Awaiting a download before triggering one
  // just burns the timeout and leaves the real event racing a second wait.
  const pending = page.waitForEvent('download', { timeout: 20000 }).then(d => d.suggestedFilename()).catch(() => null);
  await page.click('.vh-export__panel button[type=submit]').catch(() => {});
  const got = await pending;
  got ? ok('Download CSV still downloads', got) : bad('Download CSV still downloads');

  errs.length ? bad('console clean', errs.slice(0, 3).join(' | ')) : ok('console clean');
  console.log(`\n${pass}/${pass + fail} passed`);
  await browser.close();
  process.exit(fail ? 1 : 0);
})();
